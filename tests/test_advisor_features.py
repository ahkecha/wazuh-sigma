"""Deterministic feature-extraction tests."""

from __future__ import annotations

from tests.advisor_helpers import make_rule
from wazuh_sigma.advisor.features import (
    FEATURE_SCHEMA_VERSION,
    extract_features,
    hash_rule_content,
)


def test_extraction_is_deterministic():
    rule = make_rule()
    first = extract_features(rule)
    second = extract_features(make_rule())
    assert first == second
    assert first.feature_schema_version == FEATURE_SCHEMA_VERSION


def test_basic_metadata_features():
    features = extract_features(make_rule())
    assert features.title.startswith("Suspicious cmd.exe")
    assert features.sigma_level == "high"
    assert features.sigma_status == "stable"
    assert features.logsource_product == "windows"
    assert features.logsource_category == "process_creation"


def test_attack_tactics_and_techniques_split():
    features = extract_features(make_rule())
    assert "execution" in features.attack_tactics
    assert "t1059.003" in features.attack_techniques


def test_field_names_and_modifiers_collected():
    features = extract_features(make_rule())
    assert "Image" in features.field_names
    assert "endswith" in features.modifier_types


def test_baseline_level_maps_from_sigma_level():
    # high -> 12 per WazuhRuleGenerator.LEVEL_MAPPING
    features = extract_features(make_rule(level="high"))
    assert features.current_deterministic_level == 12
    assert features.policy_baseline_level == 12
    low = extract_features(make_rule(level="low"))
    assert low.current_deterministic_level == 5


def test_documented_false_positives_detected():
    features = extract_features(make_rule())
    assert features.documented_false_positives is True
    assert features.false_positive_count == 1

    unknown = extract_features(make_rule(falsepositives=["Unknown"]))
    assert unknown.documented_false_positives is False
    assert unknown.false_positive_count == 1


def test_selection_and_filter_counts():
    rule = make_rule(
        detection={
            "selection": {"Image|endswith": "\\cmd.exe"},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        }
    )
    features = extract_features(rule)
    assert features.selection_count == 1
    assert features.filter_count == 1
    assert features.has_negation is True


def test_one_of_and_wildcard_selection_flags():
    rule = make_rule(
        detection={
            "selection_a": {"Image|endswith": "\\cmd.exe"},
            "selection_b": {"Image|endswith": "\\powershell.exe"},
            "condition": "1 of selection_*",
        }
    )
    features = extract_features(rule)
    assert features.uses_one_of_selection is True
    assert features.uses_wildcard_selection is True


def test_broad_regex_detected():
    rule = make_rule(
        detection={
            "selection": {"CommandLine|re": ".*"},
            "condition": "selection",
        }
    )
    features = extract_features(rule)
    assert features.has_broad_regex is True


def test_broad_wildcard_detected():
    rule = make_rule(
        detection={
            "selection": {"CommandLine": "*"},
            "condition": "selection",
        }
    )
    features = extract_features(rule)
    assert features.has_broad_wildcard is True


def test_admin_binary_and_suspicious_primitive_detected():
    rule = make_rule(
        detection={
            "selection": {"CommandLine": "cmd.exe /c whoami"},
            "condition": "selection",
        }
    )
    features = extract_features(rule)
    assert features.has_admin_binary_reference is True
    assert features.has_suspicious_command_primitive is True


def test_telemetry_dependency_detected():
    rule = make_rule(
        detection={
            "selection": {"Image|endswith": "\\cmd.exe"},
            "condition": "selection",
        }
    )
    features = extract_features(rule)
    assert features.likely_requires_telemetry is True


def test_single_indicator_flag():
    rule = make_rule(
        detection={
            "selection": {"Image|endswith": "\\cmd.exe"},
            "condition": "selection",
        }
    )
    features = extract_features(rule)
    assert features.is_single_indicator is True


def test_hash_rule_content_is_stable():
    raw = {"title": "t", "detection": {"selection": {"a": "b"}, "condition": "selection"}}
    assert hash_rule_content(raw) == hash_rule_content(dict(raw))


def test_missing_optional_metadata_is_safe():
    rule = make_rule(tags=[], falsepositives=None, description="")
    features = extract_features(rule)
    assert features.attack_tactics == []
    assert features.attack_techniques == []
    assert features.documented_false_positives is False
    assert features.description == ""
