"""Advisor service orchestration.

Ties together deterministic feature extraction, sanitization, caching, the
provider call, optional escalation, and the deterministic policy engine into a
single :meth:`AdvisorService.advise` call that returns a typed
:class:`PolicyDecision`.

The service never mutates the Sigma rule, never generates XML, never deploys,
and never hides provider failures — under fail-open it records the failure and
returns a decision that preserves the deterministic default level.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from wazuh_sigma.advisor.cache import AdvisorCache, compute_cache_key
from wazuh_sigma.advisor.errors import (
    AdvisorError,
    AdvisorRateLimitError,
    AdvisorRequestLimitError,
    AdvisorSanitizationError,
)
from wazuh_sigma.advisor.features import extract_features
from wazuh_sigma.advisor.models import (
    AdvisorModelOutput,
    AdvisorStatus,
    PolicyDecision,
    ProviderRequestMetadata,
    SanitizedAdvisorRequest,
    SigmaFeatureSet,
)
from wazuh_sigma.advisor.policy import (
    POLICY_VERSION,
    PolicyConfig,
)
from wazuh_sigma.advisor.policy import escalation_reasons as compute_escalation_reasons
from wazuh_sigma.advisor.policy import (
    evaluate_policy,
)
from wazuh_sigma.advisor.prompts import (
    OUTPUT_SCHEMA_VERSION,
    PROMPT_VERSION,
    prompt_cache_signature,
)
from wazuh_sigma.advisor.providers.base import AdvisorProvider
from wazuh_sigma.advisor.sanitizer import sanitize_request
from wazuh_sigma.advisor.telemetry import AdvisorTelemetry
from wazuh_sigma.sigma import SigmaRule

logger = logging.getLogger("SigmaAdvisor.service")


@dataclass(frozen=True)
class AdvisorServiceConfig:
    """Runtime settings for a single advisor service instance.

    ``primary_model`` is required — there is no speculative default model ID.
    """

    primary_model: str
    provider_name: str = "openai"
    escalation_model: str | None = None
    timeout_seconds: float = 30.0
    max_output_tokens: int = 400
    fail_open: bool = True
    strict_sanitization: bool = False
    escalation_enabled: bool = True
    escalation_confidence_below: float = 0.70
    max_requests: int | None = None
    changed_only: bool = True
    policy: PolicyConfig = field(default_factory=PolicyConfig)


@dataclass
class _RecommendationOutcome:
    """Provider results for one rule, before the policy engine runs."""

    primary: AdvisorModelOutput
    escalation: AdvisorModelOutput | None
    escalation_reasons: list[str]
    request_id: str | None
    escalation_request_id: str | None


class AdvisorService:
    """Stateful orchestrator for one conversion run (owns telemetry + cache)."""

    def __init__(
        self,
        provider: AdvisorProvider,
        cache: AdvisorCache,
        config: AdvisorServiceConfig,
        telemetry: AdvisorTelemetry | None = None,
    ) -> None:
        self._provider = provider
        self._cache = cache
        self._config = config
        self.telemetry = telemetry or AdvisorTelemetry()

    def advise(self, sigma_rule: SigmaRule) -> PolicyDecision:
        """Return the authoritative policy decision for one normalized Sigma rule."""
        features = extract_features(sigma_rule)
        try:
            request = sanitize_request(features, strict=self._config.strict_sanitization)
        except AdvisorSanitizationError as error:
            return self._handle_failure(features, error)

        cache_key = compute_cache_key(
            request,
            prompt_versions=prompt_cache_signature(),
            policy_version=POLICY_VERSION,
            provider=self._config.provider_name,
            primary_model=self._config.primary_model,
            escalation_model=self._config.escalation_model,
        )

        if self._config.changed_only:
            cached = self._cache.get(cache_key)
            if cached is not None:
                self.telemetry.record_cache_hit()
                return self._decide(
                    features,
                    request,
                    primary=cached.primary_response,
                    escalation=cached.escalation_response,
                    status="cache_hit",
                    cache_hit=True,
                    escalated=cached.escalation_response is not None,
                    escalation_reasons=[],
                    request_id=None,
                    escalation_request_id=None,
                )
            self.telemetry.record_cache_miss()

        try:
            outcome = self._request_recommendations(features, request)
        except AdvisorError as error:
            return self._handle_failure(features, error)

        decision = self._decide(
            features,
            request,
            primary=outcome.primary,
            escalation=outcome.escalation,
            status="success",
            cache_hit=False,
            escalated=outcome.escalation is not None,
            escalation_reasons=outcome.escalation_reasons,
            request_id=outcome.request_id,
            escalation_request_id=outcome.escalation_request_id,
        )
        self._store_cache(cache_key, request, outcome.primary, outcome.escalation)
        return decision

    def _request_recommendations(
        self,
        features: SigmaFeatureSet,
        request: SanitizedAdvisorRequest,
    ) -> _RecommendationOutcome:
        self._enforce_request_limit()
        primary_result = self._provider.analyze(request, self._metadata(self._config.primary_model))
        self.telemetry.record_primary_call()

        # Deterministic escalation reasons are computed and reported even when
        # escalation is disabled, so a report can show "would have escalated".
        reasons = compute_escalation_reasons(
            features,
            primary_result.output,
            confidence_below=self._config.escalation_confidence_below,
            maximum_level_delta=self._config.policy.maximum_level_delta,
        )

        escalation_output: AdvisorModelOutput | None = None
        escalation_request_id: str | None = None
        if self._should_escalate(reasons):
            self._enforce_request_limit()
            escalation_result = self._provider.analyze(
                request,
                self._metadata(self._config.escalation_model or self._config.primary_model),
            )
            self.telemetry.record_escalation_call()
            escalation_output = escalation_result.output
            escalation_request_id = escalation_result.request_id

        return _RecommendationOutcome(
            primary=primary_result.output,
            escalation=escalation_output,
            escalation_reasons=reasons,
            request_id=primary_result.request_id,
            escalation_request_id=escalation_request_id,
        )

    def _should_escalate(self, reasons: list[str]) -> bool:
        return (
            bool(reasons)
            and self._config.escalation_enabled
            and self._config.escalation_model is not None
        )

    def _enforce_request_limit(self) -> None:
        limit = self._config.max_requests
        if limit is not None and self.telemetry.request_count >= limit:
            self.telemetry.record_limit_reached("max_requests")
            raise AdvisorRequestLimitError(f"advisor request limit reached ({limit})")

    def _metadata(self, model: str) -> ProviderRequestMetadata:
        return ProviderRequestMetadata(
            provider=self._config.provider_name,
            model=model,
            prompt_version=PROMPT_VERSION,
            output_schema_version=OUTPUT_SCHEMA_VERSION,
            timeout_seconds=self._config.timeout_seconds,
            max_output_tokens=self._config.max_output_tokens,
        )

    def _decide(
        self,
        features: SigmaFeatureSet,
        request: SanitizedAdvisorRequest,
        *,
        primary: AdvisorModelOutput | None,
        escalation: AdvisorModelOutput | None,
        status: AdvisorStatus,
        cache_hit: bool,
        escalated: bool,
        escalation_reasons: list[str],
        request_id: str | None,
        escalation_request_id: str | None,
    ) -> PolicyDecision:
        return evaluate_policy(
            features,
            primary,
            escalation,
            config=self._config.policy,
            advisor_status=status,
            cache_hit=cache_hit,
            redaction_applied=request.redaction_applied,
            escalated=escalated,
            escalation_reasons=escalation_reasons,
            request_id=request_id,
            escalation_request_id=escalation_request_id,
        )

    def _store_cache(
        self,
        cache_key: str,
        request: SanitizedAdvisorRequest,
        primary: AdvisorModelOutput,
        escalation: AdvisorModelOutput | None,
    ) -> None:
        entry = self._cache.build_entry(
            cache_key=cache_key,
            provider=self._config.provider_name,
            primary_model=self._config.primary_model,
            escalation_model=self._config.escalation_model,
            request=request,
            prompt_versions=prompt_cache_signature(),
            policy_version=POLICY_VERSION,
            primary_response=primary,
            escalation_response=escalation,
        )
        try:
            self._cache.put(entry)
        except AdvisorError as error:
            if not self._config.fail_open:
                raise
            logger.warning("Advisor cache write failed (continuing fail-open): %s", error)

    def _handle_failure(
        self,
        features: SigmaFeatureSet,
        error: AdvisorError,
    ) -> PolicyDecision:
        category = type(error).__name__
        self.telemetry.record_error(category)
        if isinstance(error, AdvisorRateLimitError):
            self.telemetry.record_rate_limit()
        if isinstance(error, AdvisorRequestLimitError):
            self.telemetry.record_limit_reached("max_requests")

        if not self._config.fail_open:
            logger.error("Advisor failed (fail-closed): %s", error)
            raise error

        status = self._failure_status(error)
        logger.warning("Advisor failed (fail-open, %s): %s", status, error)
        return evaluate_policy(
            features,
            None,
            None,
            config=self._config.policy,
            advisor_status=status,
            cache_hit=False,
            redaction_applied=False,
            escalated=False,
        )

    @staticmethod
    def _failure_status(error: AdvisorError) -> AdvisorStatus:
        if isinstance(error, AdvisorRateLimitError):
            return "rate_limited"
        if isinstance(error, AdvisorRequestLimitError):
            return "request_limit_reached"
        return "failed_open"
