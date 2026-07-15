"""Deterministic policy-engine boundary tests."""

from __future__ import annotations

from tests.advisor_helpers import make_output, make_rule
from wazuh_sigma.advisor.features import extract_features
from wazuh_sigma.advisor.policy import PolicyConfig, escalation_reasons, evaluate_policy


def _features(**over):
    return extract_features(make_rule(**over))


def test_escalation_reasons_low_confidence():
    features = _features(level="high")
    primary = make_output(recommended_level=12, confidence=0.4)
    reasons = escalation_reasons(features, primary, confidence_below=0.7, maximum_level_delta=2)
    assert "low_confidence" in reasons


def test_escalation_reasons_high_impact_tactic():
    features = _features(tags=["attack.credential_access", "attack.t1003"])
    primary = make_output(recommended_level=12, confidence=0.95)
    reasons = escalation_reasons(features, primary, confidence_below=0.7, maximum_level_delta=2)
    assert "high_impact_tactic" in reasons


def test_escalation_reasons_large_delta_and_critical():
    features = _features(level="low")  # baseline 5
    primary = make_output(recommended_level=14, confidence=0.99)  # delta 9, critical
    reasons = escalation_reasons(features, primary, confidence_below=0.7, maximum_level_delta=2)
    assert "large_level_delta" in reasons
    assert "high_impact_severity" in reasons


def test_escalation_reasons_empty_when_confident_and_aligned():
    features = _features(level="high", tags=["attack.execution"])  # baseline 12
    primary = make_output(recommended_level=12, confidence=0.95)
    reasons = escalation_reasons(features, primary, confidence_below=0.7, maximum_level_delta=2)
    assert reasons == []


def test_decision_carries_request_id_and_eligibility():
    features = _features(level="high")
    output = make_output(recommended_level=11, confidence=0.95)
    decision = evaluate_policy(
        features,
        output,
        config=PolicyConfig(mode="apply"),
        advisor_status="success",
        request_id="resp_xyz",
        escalation_reasons=["low_confidence"],
    )
    assert decision.request_id == "resp_xyz"
    assert decision.escalation_reasons == ["low_confidence"]
    assert decision.eligible_for_application is True


def test_report_only_never_changes_level_even_when_acceptable():
    features = _features(level="high")  # default 12
    output = make_output(recommended_level=11, confidence=0.95)
    decision = evaluate_policy(
        features,
        output,
        config=PolicyConfig(mode="report-only"),
        advisor_status="success",
    )
    assert decision.effective_level == 12
    assert decision.accepted is False
    assert decision.rejection_reasons == []


def test_apply_mode_applies_acceptable_recommendation():
    features = _features(level="high")  # default 12
    output = make_output(recommended_level=11, confidence=0.95)
    decision = evaluate_policy(
        features,
        output,
        config=PolicyConfig(mode="apply"),
        advisor_status="success",
    )
    assert decision.accepted is True
    assert decision.eligible_for_application is True
    assert decision.effective_level == 11


def test_review_mode_is_non_mutating_but_flags_for_review():
    features = _features(level="high")  # default 12
    output = make_output(recommended_level=11, confidence=0.95)
    decision = evaluate_policy(
        features,
        output,
        config=PolicyConfig(mode="review"),
        advisor_status="success",
    )
    # review surfaces a passing recommendation for approval but never changes XML.
    assert decision.accepted is False
    assert decision.eligible_for_application is True
    assert decision.requires_human_review is True
    assert decision.effective_level == 12


def test_low_confidence_rejected():
    features = _features(level="high")
    output = make_output(recommended_level=11, confidence=0.50)
    decision = evaluate_policy(
        features,
        output,
        config=PolicyConfig(mode="review", minimum_confidence=0.80),
        advisor_status="success",
    )
    assert decision.accepted is False
    assert "confidence_below_threshold" in decision.rejection_reasons


def test_level_delta_exceeds_maximum_rejected():
    features = _features(level="high")  # default 12
    output = make_output(recommended_level=5, confidence=0.99)  # delta 7
    decision = evaluate_policy(
        features,
        output,
        config=PolicyConfig(mode="review", maximum_level_delta=2),
        advisor_status="success",
    )
    assert decision.accepted is False
    assert "level_delta_exceeds_maximum" in decision.rejection_reasons


def test_human_review_recommendation_never_applied():
    features = _features(level="high")
    output = make_output(recommended_level=11, confidence=0.99, requires_human_review=True)
    decision = evaluate_policy(
        features,
        output,
        config=PolicyConfig(mode="apply"),
        advisor_status="success",
    )
    assert decision.accepted is False
    assert decision.requires_human_review is True
    assert "model_requested_human_review" in decision.rejection_reasons


def test_critical_requires_higher_confidence():
    features = _features(level="critical")  # default 15
    output = make_output(recommended_level=14, confidence=0.85)  # delta 1 but critical
    decision = evaluate_policy(
        features,
        output,
        config=PolicyConfig(mode="review", maximum_level_delta=2, critical_minimum_confidence=0.90),
        advisor_status="success",
    )
    assert "critical_requires_higher_confidence" in decision.rejection_reasons


def test_experimental_rule_cannot_be_promoted_to_critical():
    features = _features(level="critical", status="experimental")  # default 15
    output = make_output(recommended_level=14, confidence=0.99)
    decision = evaluate_policy(
        features,
        output,
        config=PolicyConfig(mode="review"),
        advisor_status="success",
    )
    assert "experimental_cannot_be_critical" in decision.rejection_reasons


def test_false_positive_ceiling_forces_review():
    features = _features(level="high")  # documented FPs, default 12
    output = make_output(recommended_level=13, confidence=0.99)
    decision = evaluate_policy(
        features,
        output,
        config=PolicyConfig(mode="review", maximum_level_delta=3, false_positive_level_ceiling=12),
        advisor_status="success",
    )
    assert "false_positive_ceiling_exceeded" in decision.rejection_reasons
    assert decision.requires_human_review is True


def test_primary_escalation_conflict_forces_review():
    features = _features(level="high")
    primary = make_output(recommended_level=11, confidence=0.95)
    escalation = make_output(recommended_level=4, confidence=0.95)  # differ by 7
    decision = evaluate_policy(
        features,
        primary,
        escalation,
        config=PolicyConfig(mode="review", conflict_delta=3),
        advisor_status="success",
    )
    assert "primary_escalation_conflict" in decision.rejection_reasons
    assert decision.requires_human_review is True


def test_no_recommendation_preserves_default():
    features = _features(level="high")
    decision = evaluate_policy(
        features,
        None,
        config=PolicyConfig(mode="review"),
        advisor_status="failed_open",
    )
    assert decision.effective_level == 12
    assert decision.accepted is False
    assert decision.confidence_used is None
    assert decision.advisor_status == "failed_open"


def test_escalation_recommendation_is_used_over_primary():
    # No documented false positives here so the critical FP ceiling does not apply.
    features = _features(level="high", falsepositives=["Unknown"])
    primary = make_output(recommended_level=11, confidence=0.60)
    escalation = make_output(recommended_level=13, confidence=0.95)
    decision = evaluate_policy(
        features,
        primary,
        escalation,
        config=PolicyConfig(mode="apply", maximum_level_delta=2),
        advisor_status="success",
    )
    # escalation (13) is the chosen recommendation; delta from 12 is 1 (ok) and
    # 13 is critical with confidence 0.95 >= 0.90, so it is accepted in apply mode.
    assert decision.confidence_used == 0.95
    assert decision.effective_level == 13
    assert decision.accepted is True
