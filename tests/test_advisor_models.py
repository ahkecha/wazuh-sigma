"""Strict-schema tests for advisor Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tests.advisor_helpers import make_output
from wazuh_sigma.advisor.models import (
    MAX_LIST_LENGTH,
    MAX_SUMMARY_LENGTH,
    AdvisorModelOutput,
)


def test_valid_output_round_trips():
    output = make_output()
    assert output.recommended_level == 11
    assert output.priority == "deploy"


@pytest.mark.parametrize("level", [-1, 16, 100])
def test_level_out_of_range_rejected(level):
    with pytest.raises(ValidationError):
        make_output(recommended_level=level)


@pytest.mark.parametrize("confidence", [-0.01, 1.01, 2.0])
def test_confidence_out_of_range_rejected(confidence):
    with pytest.raises(ValidationError):
        make_output(confidence=confidence)


def test_unknown_fields_rejected():
    with pytest.raises(ValidationError):
        AdvisorModelOutput(
            recommended_level=5,
            confidence=0.5,
            noise_risk="low",
            analyst_summary="ok",
            requires_human_review=False,
            priority="deploy",
            sneaky_extra_field="malicious",
        )


def test_reason_codes_outside_vocabulary_rejected():
    with pytest.raises(ValidationError):
        make_output(reason_codes=["totally_made_up_code"])


def test_quality_flags_outside_vocabulary_rejected():
    with pytest.raises(ValidationError):
        make_output(quality_flags=["not_a_real_flag"])


def test_duplicate_reason_codes_are_normalized():
    output = make_output(
        reason_codes=["known_attack_technique_match", "known_attack_technique_match"],
    )
    assert output.reason_codes == ["known_attack_technique_match"]


def test_list_length_bounded():
    too_many = ["missing_filter"] * (MAX_LIST_LENGTH + 2)
    with pytest.raises(ValidationError):
        make_output(quality_flags=too_many)


def test_summary_length_bounded():
    with pytest.raises(ValidationError):
        make_output(analyst_summary="x" * (MAX_SUMMARY_LENGTH + 1))


def test_invalid_priority_rejected():
    with pytest.raises(ValidationError):
        make_output(priority="ship_it")


def test_invalid_noise_risk_rejected():
    with pytest.raises(ValidationError):
        make_output(noise_risk="catastrophic")


def test_model_is_frozen():
    output = make_output()
    with pytest.raises(ValidationError):
        output.recommended_level = 3
