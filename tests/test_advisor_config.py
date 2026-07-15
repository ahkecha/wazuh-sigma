"""Advisor configuration validation tests."""

from __future__ import annotations

import pytest

from wazuh_sigma.config import AdvisorConfig, PipelineConfig, PipelineConfigError


def _advisor(payload):
    return PipelineConfig.from_mapping({"advisor": payload}).advisor


def test_advisor_disabled_by_default():
    config = PipelineConfig.from_mapping({})
    assert config.advisor.enabled is False
    assert config.advisor.mode == "report-only"


def test_valid_advisor_config_parsed():
    advisor = _advisor(
        {
            "enabled": True,
            "mode": "review",
            "primary_model": "my-primary-model",
            "escalation_model": "my-escalation-model",
            "minimum_confidence": 0.9,
            "maximum_level_delta": 1,
            "escalation": {"enabled": True, "confidence_below": 0.6, "max_requests": 50},
        }
    )
    assert advisor.enabled is True
    assert advisor.mode == "review"
    assert advisor.primary_model == "my-primary-model"
    assert advisor.minimum_confidence == 0.9
    assert advisor.escalation_confidence_below == 0.6
    assert advisor.max_requests == 50


def test_primary_model_required_when_enabled():
    with pytest.raises(PipelineConfigError):
        _advisor({"enabled": True})  # no primary_model


def test_primary_model_optional_when_disabled():
    advisor = _advisor({"enabled": False})
    assert advisor.primary_model is None


def test_no_speculative_default_model():
    # A default (disabled) config must not ship any hard-coded model ID.
    assert AdvisorConfig().primary_model is None
    assert AdvisorConfig().escalation_model is None


def test_unknown_advisor_key_rejected():
    with pytest.raises(PipelineConfigError):
        _advisor({"bogus": True})


def test_unknown_escalation_key_rejected():
    with pytest.raises(PipelineConfigError):
        _advisor({"escalation": {"nope": 1}})


def test_invalid_mode_rejected():
    with pytest.raises(PipelineConfigError):
        _advisor({"mode": "autopilot"})


def test_non_openai_provider_rejected():
    with pytest.raises(PipelineConfigError):
        _advisor({"provider": "anthropic"})


def test_confidence_out_of_range_rejected():
    with pytest.raises(PipelineConfigError):
        _advisor({"minimum_confidence": 1.5})


def test_negative_level_delta_rejected():
    with pytest.raises(PipelineConfigError):
        _advisor({"maximum_level_delta": -1})


def test_non_positive_timeout_rejected():
    with pytest.raises(PipelineConfigError):
        _advisor({"timeout_seconds": 0})


def test_non_positive_max_requests_rejected():
    with pytest.raises(PipelineConfigError):
        _advisor({"escalation": {"max_requests": 0}})


def test_empty_primary_model_rejected():
    with pytest.raises(PipelineConfigError):
        _advisor({"primary_model": "  "})


def test_escalation_model_may_be_null():
    advisor = _advisor({"escalation_model": None})
    assert advisor.escalation_model is None


def test_apply_mode_requires_explicit_value():
    # apply is a valid but non-default mode; it must be set explicitly.
    assert AdvisorConfig().mode != "apply"
    advisor = _advisor({"mode": "apply"})
    assert advisor.mode == "apply"
