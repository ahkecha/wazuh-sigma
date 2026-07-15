"""Strict Pydantic models for the optional Sigma rule advisor.

Every value that crosses the advisor boundary — deterministic features, the
sanitized request sent to a provider, the provider's structured response, and
the deterministic policy decision — is a validated, immutable Pydantic model.
Unknown fields are rejected everywhere so a provider cannot smuggle new
semantics past strict validation.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: Bumped whenever the model output contract changes shape or semantics.
OUTPUT_SCHEMA_VERSION = "advisor-output-v1"
#: Bumped whenever the reason-code vocabulary changes.
REASON_CODE_VOCAB_VERSION = "reason-codes-v1"
#: Bumped whenever the quality-flag vocabulary changes.
QUALITY_FLAG_VOCAB_VERSION = "quality-flags-v1"

NoiseRisk = Literal["low", "medium", "high"]
Priority = Literal[
    "deploy",
    "deploy_with_lower_level",
    "needs_tuning",
    "needs_telemetry",
    "reject",
    "human_review",
]

#: Controlled vocabulary for reason codes. The provider must select from this
#: set only; anything else fails schema validation before it can influence
#: policy or reporting.
REASON_CODES: frozenset[str] = frozenset(
    {
        "common_administrative_behavior",
        "documented_false_positives",
        "narrow_high_specificity_indicator",
        "broad_wildcard_selection",
        "single_weak_indicator",
        "multi_indicator_correlation",
        "known_attack_technique_match",
        "telemetry_dependency_unmet",
        "missing_attack_mapping",
        "experimental_rule_status",
        "credential_access_target",
        "persistence_target",
        "privilege_escalation_target",
        "defense_evasion_target",
        "high_noise_expected",
        "low_noise_expected",
        "insufficient_context",
        "conflicting_signals",
    }
)

#: Controlled vocabulary for detection-quality flags.
QUALITY_FLAGS: frozenset[str] = frozenset(
    {
        "missing_filter",
        "overly_broad_regex",
        "overly_broad_wildcard",
        "single_indicator_only",
        "false_positives_not_reviewed",
        "high_false_positive_count",
        "ambiguous_log_source",
        "missing_attack_tags",
        "complex_condition_logic",
        "duplicate_selection_logic",
        "weak_administrative_binary_match",
        "telemetry_gap",
    }
)

#: Advisor status values recorded in reports; "disabled"/"cache_hit" are not
#: failures and must not be treated as such by policy or reporting code.
AdvisorStatus = Literal[
    "disabled",
    "success",
    "cache_hit",
    "failed_open",
    "failed_closed",
    "rate_limited",
    "request_limit_reached",
    "cost_limit_reached",
]

MAX_LIST_LENGTH = 8
MAX_SUMMARY_LENGTH = 400
MAX_TAG_LENGTH = 200


def _bounded_unique(
    values: list[str], *, field_name: str, vocabulary: frozenset[str] | None = None
) -> list[str]:
    """Deduplicate while preserving order, enforce vocabulary and length bounds."""
    if len(values) > MAX_LIST_LENGTH:
        raise ValueError(f"{field_name} must contain at most {MAX_LIST_LENGTH} entries")
    if vocabulary is not None:
        unknown = sorted({value for value in values if value not in vocabulary})
        if unknown:
            raise ValueError(
                f"{field_name} contains values outside the controlled vocabulary: {unknown}"
            )
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return list(seen)


class StrictModel(BaseModel):
    """Base model shared by all advisor contracts: immutable, no unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ProviderFeatureSet(StrictModel):
    """The provider-safe semantic feature subset.

    Contains no raw free text (no ``title``/``description``) — only compact
    semantic features plus versions and a content hash. This is what actually
    travels to a provider and participates in the cache key, so the type's
    "no raw content" guarantee holds by construction. ``rule_content_hash``
    preserves per-rule cache uniqueness even though the raw text is absent.
    """

    feature_schema_version: str
    rule_content_hash: str

    sigma_level: str
    sigma_status: str

    logsource_product: str | None = None
    logsource_category: str | None = None
    logsource_service: str | None = None

    attack_tactics: list[str] = Field(default_factory=list, max_length=32)
    attack_techniques: list[str] = Field(default_factory=list, max_length=32)

    field_names: list[str] = Field(default_factory=list, max_length=256)
    modifier_types: list[str] = Field(default_factory=list, max_length=32)

    selection_count: int = Field(ge=0)
    filter_count: int = Field(ge=0)
    condition_depth: int = Field(ge=0)
    boolean_operator_count: int = Field(ge=0)

    has_negation: bool = False
    uses_one_of_selection: bool = False
    uses_all_of_selection: bool = False
    uses_wildcard_selection: bool = False

    has_broad_regex: bool = False
    has_broad_wildcard: bool = False
    has_admin_binary_reference: bool = False
    has_suspicious_command_primitive: bool = False

    documented_false_positives: bool = False
    false_positive_count: int = Field(default=0, ge=0)

    likely_requires_telemetry: bool = False
    telemetry_implied_by_logsource: bool = False
    is_single_indicator: bool = False

    current_deterministic_level: int = Field(ge=0, le=15)
    policy_baseline_level: int = Field(ge=0, le=15)


class SigmaFeatureSet(ProviderFeatureSet):
    """Full deterministic feature set including raw ``title``/``description``.

    Produced by :mod:`wazuh_sigma.advisor.features` for local use (sanitization,
    policy). The raw free-text fields never leave this object: the sanitizer
    derives a :class:`ProviderFeatureSet` (via :meth:`to_provider_features`) and
    only redacted title/description strings are sent to a provider.
    """

    title: str = ""
    description: str = ""

    def to_provider_features(self) -> ProviderFeatureSet:
        """Return the provider-safe subset, dropping raw free text."""
        return ProviderFeatureSet(**self.model_dump(exclude={"title", "description"}))


class SanitizedAdvisorRequest(StrictModel):
    """Sanitized, provider-bound request payload.

    Produced by :mod:`wazuh_sigma.advisor.sanitizer`. Carries only the
    provider-safe feature subset and redacted title/description strings — no raw
    secrets, hostnames, customer identifiers, or unredacted free text.
    """

    sanitizer_version: str
    features: ProviderFeatureSet
    sanitized_title: str
    sanitized_description: str = ""
    redaction_applied: bool = False
    redaction_categories: list[str] = Field(default_factory=list, max_length=32)


class ProviderRequestMetadata(StrictModel):
    """Metadata describing a single outbound provider request (no payload contents)."""

    provider: str
    model: str
    prompt_version: str
    output_schema_version: str
    timeout_seconds: float = Field(gt=0)
    max_output_tokens: int = Field(gt=0)


class EscalationRequestMetadata(StrictModel):
    """Metadata describing an escalation request, when triggered."""

    triggered: bool
    trigger_reasons: list[str] = Field(default_factory=list, max_length=16)
    model: str | None = None


class AdvisorModelOutput(StrictModel):
    """Strict structured-output contract enforced on every provider response."""

    recommended_level: int = Field(ge=0, le=15)
    confidence: float = Field(ge=0.0, le=1.0)
    noise_risk: NoiseRisk
    quality_flags: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    analyst_summary: str = Field(max_length=MAX_SUMMARY_LENGTH)
    requires_human_review: bool
    priority: Priority

    @field_validator("quality_flags")
    @classmethod
    def _validate_quality_flags(cls, value: list[str]) -> list[str]:
        return _bounded_unique(value, field_name="quality_flags", vocabulary=QUALITY_FLAGS)

    @field_validator("reason_codes")
    @classmethod
    def _validate_reason_codes(cls, value: list[str]) -> list[str]:
        return _bounded_unique(value, field_name="reason_codes", vocabulary=REASON_CODES)


class ProviderResult(StrictModel):
    """Provider-agnostic result envelope wrapping a validated model output.

    Carries the provider's safe response identifier (never a secret) and the
    model that produced the output, so both can be threaded into telemetry and
    the conversion report.
    """

    output: AdvisorModelOutput
    request_id: str | None = None
    model: str


class PolicyDecision(StrictModel):
    """Final, authoritative output of the deterministic policy engine."""

    default_level: int = Field(ge=0, le=15)
    policy_baseline_level: int = Field(ge=0, le=15)
    primary_recommendation: AdvisorModelOutput | None = None
    escalation_recommendation: AdvisorModelOutput | None = None
    effective_level: int = Field(ge=0, le=15)
    accepted: bool
    eligible_for_application: bool = False
    rejection_reasons: list[str] = Field(default_factory=list, max_length=16)
    requires_human_review: bool
    advisor_status: AdvisorStatus
    confidence_used: float | None = Field(default=None, ge=0.0, le=1.0)
    cache_hit: bool = False
    redaction_applied: bool = False
    escalated: bool = False
    escalation_reasons: list[str] = Field(default_factory=list, max_length=16)
    request_id: str | None = None
    escalation_request_id: str | None = None


class CacheEntry(StrictModel):
    """Content-addressed cache entry. Never stores secrets or raw rule content."""

    cache_key: str
    provider: str
    primary_model: str
    escalation_model: str | None = None
    feature_schema_version: str
    sanitizer_version: str
    prompt_version: str
    output_schema_version: str
    policy_version: str
    primary_response: AdvisorModelOutput
    escalation_response: AdvisorModelOutput | None = None
