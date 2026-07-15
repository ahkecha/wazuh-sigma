"""Deterministic policy engine — the final authority over model recommendations.

The model never decides anything on its own. This module takes the (optional)
provider recommendation plus the deterministic feature set and produces a
:class:`PolicyDecision`. In the default ``report-only`` mode the effective level
always equals the deterministic default, so generated XML is unchanged no matter
what the model recommends.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from wazuh_sigma.advisor.models import (
    AdvisorModelOutput,
    AdvisorStatus,
    PolicyDecision,
    SigmaFeatureSet,
)

#: Bumped when policy logic changes. Part of the advisor cache key so cached
#: recommendations are re-evaluated when the rules that gate them change.
POLICY_VERSION = "policy-v1"

PolicyMode = Literal["report-only", "review", "apply"]

CRITICAL_LEVEL_THRESHOLD = 13
_EXPERIMENTAL_STATUSES = frozenset({"experimental", "test", "deprecated", "unsupported"})

#: ATT&CK tactics that warrant a second (escalation) opinion regardless of the
#: primary model's confidence, because a wrong call is high-impact.
HIGH_IMPACT_TACTICS = frozenset(
    {"credential_access", "persistence", "privilege_escalation", "defense_evasion"}
)


def escalation_reasons(
    features: SigmaFeatureSet,
    primary: AdvisorModelOutput,
    *,
    confidence_below: float,
    maximum_level_delta: int,
) -> list[str]:
    """Return the deterministic reasons a primary recommendation should escalate.

    Escalation is warranted when the primary result is uncertain, high-impact, or
    materially disagrees with the deterministic baseline. An empty list means no
    escalation is needed. This is pure and deterministic so the same rule always
    escalates for the same reasons.
    """
    reasons: list[str] = []
    if primary.confidence < confidence_below:
        reasons.append("low_confidence")
    if primary.requires_human_review:
        reasons.append("model_requested_human_review")
    if abs(primary.recommended_level - features.policy_baseline_level) > maximum_level_delta:
        reasons.append("large_level_delta")
    if primary.recommended_level >= CRITICAL_LEVEL_THRESHOLD:
        reasons.append("high_impact_severity")
    if HIGH_IMPACT_TACTICS.intersection(features.attack_tactics):
        reasons.append("high_impact_tactic")
    return list(dict.fromkeys(reasons))


@dataclass(frozen=True)
class PolicyConfig:
    """Tunable, validated policy thresholds.

    Defaults are deliberately conservative: report-only, high confidence
    required, small level delta, critical levels gated behind an even higher
    confidence bar.
    """

    mode: PolicyMode = "report-only"
    minimum_confidence: float = 0.80
    maximum_level_delta: int = 2
    critical_minimum_confidence: float = 0.90
    false_positive_level_ceiling: int = 12
    conflict_delta: int = 3

    def __post_init__(self) -> None:
        if self.mode not in ("report-only", "review", "apply"):
            raise ValueError("policy mode must be report-only, review, or apply")
        if not 0.0 <= self.minimum_confidence <= 1.0:
            raise ValueError("minimum_confidence must be within 0.0-1.0")
        if not 0.0 <= self.critical_minimum_confidence <= 1.0:
            raise ValueError("critical_minimum_confidence must be within 0.0-1.0")
        if self.maximum_level_delta < 0:
            raise ValueError("maximum_level_delta must be non-negative")
        if not 0 <= self.false_positive_level_ceiling <= 15:
            raise ValueError("false_positive_level_ceiling must be within 0-15")
        if self.conflict_delta < 0:
            raise ValueError("conflict_delta must be non-negative")


def evaluate_policy(
    features: SigmaFeatureSet,
    primary: AdvisorModelOutput | None,
    escalation: AdvisorModelOutput | None = None,
    *,
    config: PolicyConfig,
    advisor_status: AdvisorStatus,
    cache_hit: bool = False,
    redaction_applied: bool = False,
    escalated: bool = False,
    escalation_reasons: list[str] | None = None,
    request_id: str | None = None,
    escalation_request_id: str | None = None,
) -> PolicyDecision:
    """Return the authoritative decision for one rule.

    ``primary`` may be ``None`` when the advisor is disabled or the provider
    failed under fail-open: in that case the deterministic default is preserved
    and nothing is accepted.

    Mode semantics:

    * ``report-only`` and ``review`` never change the effective level. ``review``
      additionally marks policy-passing recommendations as
      ``eligible_for_application`` and flags them for human review.
    * ``apply`` is the *only* mode that changes the effective level, and only
      for recommendations that pass every policy check.
    """
    default_level = features.current_deterministic_level
    baseline_level = features.policy_baseline_level
    escalation_reasons = list(escalation_reasons or [])

    chosen = escalation or primary
    if chosen is None:
        return PolicyDecision(
            default_level=default_level,
            policy_baseline_level=baseline_level,
            primary_recommendation=None,
            escalation_recommendation=None,
            effective_level=default_level,
            accepted=False,
            eligible_for_application=False,
            rejection_reasons=[],
            requires_human_review=False,
            advisor_status=advisor_status,
            confidence_used=None,
            cache_hit=cache_hit,
            redaction_applied=redaction_applied,
            escalated=escalated,
            escalation_reasons=escalation_reasons,
            request_id=request_id,
            escalation_request_id=escalation_request_id,
        )

    rejection_reasons: list[str] = []
    requires_human_review = chosen.requires_human_review

    if chosen.requires_human_review:
        rejection_reasons.append("model_requested_human_review")

    if chosen.confidence < config.minimum_confidence:
        rejection_reasons.append("confidence_below_threshold")

    delta = abs(chosen.recommended_level - default_level)
    if delta > config.maximum_level_delta:
        rejection_reasons.append("level_delta_exceeds_maximum")

    if chosen.recommended_level >= CRITICAL_LEVEL_THRESHOLD:
        if chosen.confidence < config.critical_minimum_confidence:
            rejection_reasons.append("critical_requires_higher_confidence")
        if features.sigma_status.lower() in _EXPERIMENTAL_STATUSES:
            rejection_reasons.append("experimental_cannot_be_critical")

    if (
        features.documented_false_positives
        and chosen.recommended_level > config.false_positive_level_ceiling
    ):
        rejection_reasons.append("false_positive_ceiling_exceeded")
        requires_human_review = True

    if primary is not None and escalation is not None:
        if abs(primary.recommended_level - escalation.recommended_level) > config.conflict_delta:
            rejection_reasons.append("primary_escalation_conflict")
            requires_human_review = True

    # De-duplicate while preserving order.
    rejection_reasons = list(dict.fromkeys(rejection_reasons))

    would_accept = not rejection_reasons
    # Only apply mode changes XML. review surfaces a passing recommendation as a
    # human-review candidate without mutating the effective level.
    accepted = would_accept and config.mode == "apply"
    eligible_for_application = would_accept
    if config.mode == "review" and would_accept:
        requires_human_review = True
    effective_level = chosen.recommended_level if accepted else default_level

    return PolicyDecision(
        default_level=default_level,
        policy_baseline_level=baseline_level,
        primary_recommendation=primary,
        escalation_recommendation=escalation,
        effective_level=effective_level,
        accepted=accepted,
        eligible_for_application=eligible_for_application,
        rejection_reasons=rejection_reasons,
        requires_human_review=requires_human_review,
        advisor_status=advisor_status,
        confidence_used=chosen.confidence,
        cache_hit=cache_hit,
        redaction_applied=redaction_applied,
        escalated=escalated,
        escalation_reasons=escalation_reasons,
        request_id=request_id,
        escalation_request_id=escalation_request_id,
    )
