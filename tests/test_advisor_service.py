"""Advisor service orchestration tests: cache, escalation, fail-open/closed, limits."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.advisor_helpers import FakeProvider, make_output, make_rule
from wazuh_sigma.advisor.cache import AdvisorCache
from wazuh_sigma.advisor.errors import (
    AdvisorRequestLimitError,
    AdvisorTimeoutError,
    AdvisorUnavailableError,
)
from wazuh_sigma.advisor.policy import PolicyConfig
from wazuh_sigma.advisor.service import AdvisorService, AdvisorServiceConfig


def _service(provider, tmp_path: Path, **cfg_over) -> AdvisorService:
    base = {
        "primary_model": "test-model",
        "policy": PolicyConfig(mode="report-only"),
        "escalation_enabled": False,
    }
    base.update(cfg_over)
    cache = AdvisorCache(tmp_path / "cache", enabled=base.pop("cache_enabled", True))
    return AdvisorService(provider, cache, AdvisorServiceConfig(**base))


def test_success_returns_decision(tmp_path):
    provider = FakeProvider(make_output(recommended_level=11, confidence=0.95))
    service = _service(provider, tmp_path)
    decision = service.advise(make_rule())
    assert decision.advisor_status == "success"
    assert decision.primary_recommendation is not None
    assert provider.call_count == 1


def test_second_call_hits_cache(tmp_path):
    provider = FakeProvider(make_output(), make_output())
    service = _service(provider, tmp_path)
    service.advise(make_rule())
    decision = service.advise(make_rule())
    assert decision.advisor_status == "cache_hit"
    assert decision.cache_hit is True
    assert provider.call_count == 1  # second call served from cache


def test_changed_only_false_bypasses_cache_read(tmp_path):
    provider = FakeProvider(make_output(), make_output())
    service = _service(provider, tmp_path, changed_only=False)
    service.advise(make_rule())
    service.advise(make_rule())
    assert provider.call_count == 2


def test_escalation_triggered_on_low_confidence(tmp_path):
    provider = FakeProvider(
        make_output(recommended_level=11, confidence=0.50),  # primary, low confidence
        make_output(recommended_level=11, confidence=0.95),  # escalation
    )
    service = _service(
        provider,
        tmp_path,
        escalation_enabled=True,
        escalation_confidence_below=0.70,
        escalation_model="gpt-5.4-mini",
    )
    decision = service.advise(make_rule())
    assert decision.escalated is True
    assert provider.call_count == 2


def test_no_escalation_when_confidence_high(tmp_path):
    provider = FakeProvider(make_output(confidence=0.95))
    service = _service(
        provider,
        tmp_path,
        escalation_enabled=True,
        escalation_confidence_below=0.70,
        escalation_model="gpt-5.4-mini",
    )
    decision = service.advise(make_rule())
    assert decision.escalated is False
    assert provider.call_count == 1


def test_fail_open_preserves_default_on_provider_failure(tmp_path):
    provider = FakeProvider(AdvisorUnavailableError("provider down"))
    service = _service(provider, tmp_path, fail_open=True)
    decision = service.advise(make_rule(level="high"))
    assert decision.advisor_status == "failed_open"
    assert decision.effective_level == 12  # deterministic default preserved
    assert decision.primary_recommendation is None
    assert service.telemetry.errors_by_category.get("AdvisorUnavailableError") == 1


def test_fail_closed_raises_on_provider_failure(tmp_path):
    provider = FakeProvider(AdvisorTimeoutError("timed out"))
    service = _service(provider, tmp_path, fail_open=False)
    with pytest.raises(AdvisorTimeoutError):
        service.advise(make_rule())


def test_request_limit_enforced_fail_open(tmp_path):
    provider = FakeProvider(make_output(), make_output())
    service = _service(provider, tmp_path, max_requests=1, fail_open=True, cache_enabled=False)
    service.advise(make_rule(title="rule one"))
    # Second distinct rule would exceed the request budget.
    decision = service.advise(make_rule(title="rule two"))
    assert decision.advisor_status == "request_limit_reached"
    assert "max_requests" in service.telemetry.limits_reached


def test_request_limit_fail_closed_raises(tmp_path):
    provider = FakeProvider(make_output(), make_output())
    service = _service(provider, tmp_path, max_requests=1, fail_open=False, cache_enabled=False)
    service.advise(make_rule(title="rule one"))
    with pytest.raises(AdvisorRequestLimitError):
        service.advise(make_rule(title="rule two"))


def test_telemetry_snapshot_has_no_secrets(tmp_path):
    provider = FakeProvider(make_output())
    service = _service(provider, tmp_path)
    service.advise(make_rule())
    snapshot = service.telemetry.snapshot()
    assert set(snapshot) >= {"request_count", "cache_hits", "primary_calls"}
    assert "api_key" not in snapshot


def test_build_advisor_service_returns_none_when_disabled():
    from wazuh_sigma.advisor.runtime import build_advisor_service
    from wazuh_sigma.config import AdvisorConfig

    assert build_advisor_service(AdvisorConfig(enabled=False)) is None


def test_build_advisor_service_uses_injected_provider(tmp_path):
    from wazuh_sigma.advisor.runtime import build_advisor_service, make_advisor_hook
    from wazuh_sigma.config import AdvisorConfig

    config = AdvisorConfig(
        enabled=True,
        mode="report-only",
        primary_model="test-model",
        cache_directory=tmp_path / "cache",
    )
    provider = FakeProvider(make_output(recommended_level=9, confidence=0.9))
    service = build_advisor_service(config, provider=provider)
    assert service is not None
    hook = make_advisor_hook(service, config)
    outcome = hook(make_rule())
    # report-only never applies an override
    assert outcome.level_override is None
    assert outcome.report["mode"] == "report-only"
    assert provider.call_count == 1


def test_policy_config_rejects_invalid_values():
    from wazuh_sigma.advisor.policy import PolicyConfig

    for bad in (
        {"mode": "nonsense"},
        {"minimum_confidence": 1.5},
        {"maximum_level_delta": -1},
        {"critical_minimum_confidence": -0.1},
        {"false_positive_level_ceiling": 99},
        {"conflict_delta": -2},
    ):
        with pytest.raises(ValueError):
            PolicyConfig(**bad)
