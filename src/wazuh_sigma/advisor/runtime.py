"""Wiring between :class:`~wazuh_sigma.config.AdvisorConfig` and the advisor service.

This module is imported lazily by the converter/pipeline only when the advisor
is enabled, so the deterministic core never pays for the optional ``openai`` /
``pydantic`` dependencies. Dependency direction is one-way: the advisor package
reads :class:`AdvisorConfig`; ``config.py`` never imports the advisor package.
"""

from __future__ import annotations

from typing import Any

from wazuh_sigma.advisor.cache import AdvisorCache
from wazuh_sigma.advisor.errors import AdvisorConfigurationError
from wazuh_sigma.advisor.features import FEATURE_SCHEMA_VERSION
from wazuh_sigma.advisor.models import PolicyDecision
from wazuh_sigma.advisor.policy import POLICY_VERSION, PolicyConfig
from wazuh_sigma.advisor.prompts import prompt_cache_signature
from wazuh_sigma.advisor.providers.base import AdvisorProvider
from wazuh_sigma.advisor.providers.openai import OpenAIAdvisorProvider
from wazuh_sigma.advisor.sanitizer import SANITIZER_VERSION
from wazuh_sigma.advisor.service import AdvisorService, AdvisorServiceConfig
from wazuh_sigma.advisor.telemetry import AdvisorTelemetry
from wazuh_sigma.config import AdvisorConfig
from wazuh_sigma.converter.service import AdvisorHook, AdvisorOutcome
from wazuh_sigma.sigma import SigmaRule


def build_advisor_service(
    config: AdvisorConfig,
    *,
    provider: AdvisorProvider | None = None,
    telemetry: AdvisorTelemetry | None = None,
) -> AdvisorService | None:
    """Construct an :class:`AdvisorService` from validated config.

    Returns ``None`` when the advisor is disabled. When no ``provider`` is
    injected (tests inject fakes), the real OpenAI provider is built from the
    environment API key — which raises :class:`AdvisorConfigurationError` if the
    key is missing.
    """
    if not config.enabled:
        return None

    if not config.primary_model:
        # Defensive: AdvisorConfig already enforces this when enabled.
        raise AdvisorConfigurationError(
            "advisor.primary_model is required when the advisor is enabled"
        )

    if provider is None:
        provider = OpenAIAdvisorProvider.from_env(max_retries=config.max_retries)

    policy = PolicyConfig(
        mode=config.mode,  # type: ignore[arg-type]
        minimum_confidence=config.minimum_confidence,
        maximum_level_delta=config.maximum_level_delta,
    )
    service_config = AdvisorServiceConfig(
        provider_name=config.provider,
        primary_model=config.primary_model,
        escalation_model=config.escalation_model,
        timeout_seconds=float(config.timeout_seconds),
        max_output_tokens=config.max_output_tokens,
        fail_open=config.fail_open,
        strict_sanitization=config.strict_sanitization,
        escalation_enabled=config.escalation_enabled,
        escalation_confidence_below=config.escalation_confidence_below,
        max_requests=config.max_requests,
        changed_only=config.changed_only,
        policy=policy,
    )
    cache = AdvisorCache(config.cache_directory, enabled=config.cache_enabled)
    return AdvisorService(provider, cache, service_config, telemetry=telemetry)


def make_advisor_hook(service: AdvisorService, config: AdvisorConfig) -> AdvisorHook:
    """Return the per-rule hook the converter calls when the advisor is enabled.

    The level override is applied only when the deterministic policy accepted a
    recommendation; in report-only mode nothing is ever accepted, so the backend
    receives ``None`` and generated XML is unchanged.
    """

    def hook(sigma_rule: SigmaRule) -> AdvisorOutcome:
        decision = service.advise(sigma_rule)
        level_override = decision.effective_level if decision.accepted else None
        return AdvisorOutcome(
            level_override=level_override,
            report=build_rule_advisor_report(decision, config),
        )

    return hook


def build_run_advisor_summary(service: AdvisorService, config: AdvisorConfig) -> dict[str, Any]:
    """Return the run-level ``advisor`` block for the conversion report."""
    return {
        "enabled": True,
        "provider": config.provider,
        "mode": config.mode,
        "primary_model": config.primary_model,
        "escalation_model": config.escalation_model if config.escalation_enabled else None,
        "cache_enabled": config.cache_enabled,
        "changed_only": config.changed_only,
        "fail_open": config.fail_open,
        "telemetry": service.telemetry.snapshot(),
    }


def build_rule_advisor_report(decision: PolicyDecision, config: AdvisorConfig) -> dict[str, Any]:
    """Serialize a policy decision into the per-rule ``advisor`` report block.

    Never includes prompts, raw responses, secrets, or unsanitized content —
    only versions, levels, and the controlled-vocabulary outputs.
    """
    chosen = decision.escalation_recommendation or decision.primary_recommendation
    report: dict[str, Any] = {
        "status": decision.advisor_status,
        "provider": config.provider,
        "mode": config.mode,
        "primary_model": config.primary_model,
        "escalation_model": config.escalation_model if config.escalation_enabled else None,
        "escalated": decision.escalated,
        "cache_hit": decision.cache_hit,
        "redaction_applied": decision.redaction_applied,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "sanitizer_version": SANITIZER_VERSION,
        "policy_version": POLICY_VERSION,
        "prompt_version": prompt_cache_signature()["prompt_version"],
        "output_schema_version": prompt_cache_signature()["output_schema_version"],
        "default_level": decision.default_level,
        "policy_baseline_level": decision.policy_baseline_level,
        "effective_level": decision.effective_level,
        "accepted": decision.accepted,
        "eligible_for_application": decision.eligible_for_application,
        "requires_human_review": decision.requires_human_review,
        "rejection_reasons": list(decision.rejection_reasons),
        "escalation_reasons": list(decision.escalation_reasons),
        "confidence": decision.confidence_used,
        "recommended_level": chosen.recommended_level if chosen else None,
        "noise_risk": chosen.noise_risk if chosen else None,
        "priority": chosen.priority if chosen else None,
        "quality_flags": list(chosen.quality_flags) if chosen else [],
        "reason_codes": list(chosen.reason_codes) if chosen else [],
        "analyst_summary": chosen.analyst_summary if chosen else None,
        "request_id": decision.request_id,
        "escalation_request_id": decision.escalation_request_id,
    }
    return report
