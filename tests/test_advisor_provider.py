"""OpenAI provider tests using a fake SDK client and real openai exceptions.

No network access. The fake client's ``responses.parse`` returns queued
response objects or raises queued exceptions, exercising the provider's error
mapping and retry classification.
"""

from __future__ import annotations

import httpx
import openai
import pytest

from tests.advisor_helpers import make_output, make_rule
from wazuh_sigma.advisor.errors import (
    AdvisorAuthenticationError,
    AdvisorMalformedOutputError,
    AdvisorRateLimitError,
    AdvisorRefusalError,
    AdvisorSchemaValidationError,
    AdvisorTimeoutError,
    AdvisorUnavailableError,
)
from wazuh_sigma.advisor.features import extract_features
from wazuh_sigma.advisor.models import ProviderRequestMetadata
from wazuh_sigma.advisor.providers.openai import OpenAIAdvisorProvider
from wazuh_sigma.advisor.sanitizer import sanitize_request


def _request():
    return sanitize_request(extract_features(make_rule()))


def _metadata(model: str = "gpt-5.4-nano") -> ProviderRequestMetadata:
    return ProviderRequestMetadata(
        provider="openai",
        model=model,
        prompt_version="severity-v1",
        output_schema_version="advisor-output-v1",
        timeout_seconds=30.0,
        max_output_tokens=400,
    )


class _Content:
    def __init__(self, *, parsed=None, refusal=None):
        self.parsed = parsed
        self.type = "refusal" if refusal is not None else "output_text"
        self.refusal = refusal


class _Message:
    def __init__(self, content):
        self.content = content


class _FakeResponse:
    def __init__(
        self,
        *,
        output_parsed=None,
        output=None,
        status="completed",
        incomplete_reason=None,
        id="resp_fake_123",
    ):
        self.output_parsed = output_parsed
        self.output = output or []
        self.status = status
        self.id = id
        self.incomplete_details = (
            type("Details", (), {"reason": incomplete_reason})() if incomplete_reason else None
        )


class _FakeResponses:
    def __init__(self, results):
        self._results = list(results)
        self.calls = 0

    def parse(self, **_kwargs):
        self.calls += 1
        result = self._results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class _FakeClient:
    def __init__(self, results):
        self.responses = _FakeResponses(results)


def _http_response(status: int) -> httpx.Response:
    return httpx.Response(
        status_code=status, request=httpx.Request("POST", "https://api.openai.test/v1")
    )


def _rate_limit() -> openai.RateLimitError:
    return openai.RateLimitError("slow down", response=_http_response(429), body=None)


def _server_error() -> openai.InternalServerError:
    return openai.InternalServerError("boom", response=_http_response(500), body=None)


def _auth_error() -> openai.AuthenticationError:
    return openai.AuthenticationError("bad key", response=_http_response(401), body=None)


def _timeout() -> openai.APITimeoutError:
    return openai.APITimeoutError(request=httpx.Request("POST", "https://api.openai.test/v1"))


def _provider(results, **kwargs) -> OpenAIAdvisorProvider:
    return OpenAIAdvisorProvider(
        _FakeClient(results),
        sleeper=lambda _seconds: None,
        **kwargs,
    )


def test_successful_structured_output():
    provider = _provider([_FakeResponse(output_parsed=make_output())])
    result = provider.analyze(_request(), _metadata())
    assert result.output.recommended_level == make_output().recommended_level


def test_incomplete_response_is_malformed():
    provider = _provider(
        [_FakeResponse(status="incomplete", incomplete_reason="max_output_tokens")]
    )
    with pytest.raises(AdvisorMalformedOutputError):
        provider.analyze(_request(), _metadata())


def test_missing_output_is_malformed():
    provider = _provider([_FakeResponse(output_parsed=None, output=[])])
    with pytest.raises(AdvisorMalformedOutputError):
        provider.analyze(_request(), _metadata())


def test_refusal_is_mapped():
    refusal_msg = _Message([_Content(refusal="I cannot help with that")])
    provider = _provider([_FakeResponse(output=[refusal_msg])])
    with pytest.raises(AdvisorRefusalError):
        provider.analyze(_request(), _metadata())


def test_schema_mismatch_is_rejected():
    # output_parsed is a dict that violates the strict schema (level out of range).
    bad = {
        "recommended_level": 99,
        "confidence": 0.5,
        "noise_risk": "low",
        "quality_flags": [],
        "reason_codes": [],
        "analyst_summary": "x",
        "requires_human_review": False,
        "priority": "deploy",
    }
    provider = _provider([_FakeResponse(output_parsed=bad)])
    with pytest.raises(AdvisorSchemaValidationError):
        provider.analyze(_request(), _metadata())


def test_authentication_error_is_not_retried():
    provider = _provider([_auth_error(), _FakeResponse(output_parsed=make_output())], max_retries=3)
    with pytest.raises(AdvisorAuthenticationError):
        provider.analyze(_request(), _metadata())
    assert provider._client.responses.calls == 1


def test_timeout_is_mapped_and_retried():
    provider = _provider([_timeout(), _FakeResponse(output_parsed=make_output())], max_retries=2)
    result = provider.analyze(_request(), _metadata())
    assert result.output.recommended_level == make_output().recommended_level
    assert provider._client.responses.calls == 2


def test_rate_limit_retries_then_succeeds():
    provider = _provider(
        [_rate_limit(), _rate_limit(), _FakeResponse(output_parsed=make_output())],
        max_retries=3,
    )
    result = provider.analyze(_request(), _metadata())
    assert result.output.recommended_level == make_output().recommended_level
    assert provider._client.responses.calls == 3


def test_rate_limit_exhausts_retries():
    provider = _provider([_rate_limit(), _rate_limit()], max_retries=1)
    with pytest.raises(AdvisorRateLimitError):
        provider.analyze(_request(), _metadata())
    assert provider._client.responses.calls == 2


def test_server_error_retries_then_raises_unavailable():
    provider = _provider([_server_error(), _server_error()], max_retries=1)
    with pytest.raises(AdvisorUnavailableError):
        provider.analyze(_request(), _metadata())
    assert provider._client.responses.calls == 2


def test_from_env_without_key_raises(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from wazuh_sigma.advisor.errors import AdvisorConfigurationError

    with pytest.raises(AdvisorConfigurationError):
        OpenAIAdvisorProvider.from_env()


def test_result_carries_request_id_and_model():
    provider = _provider([_FakeResponse(output_parsed=make_output(), id="resp_abc")])
    result = provider.analyze(_request(), _metadata(model="some-model"))
    assert result.request_id == "resp_abc"
    assert result.model == "some-model"


def test_call_does_not_send_temperature():
    provider = _provider([_FakeResponse(output_parsed=make_output())])
    provider.analyze(_request(), _metadata())
    # _FakeResponses.parse would need temperature only if we sent it; assert the
    # provider never passes it so temperature-restricted models are not rejected.
    captured: dict = {}

    class _CapturingResponses(_FakeResponses):
        def parse(self, **kwargs):
            captured.update(kwargs)
            return super().parse(**kwargs)

    client = _FakeClient([_FakeResponse(output_parsed=make_output())])
    client.responses = _CapturingResponses([_FakeResponse(output_parsed=make_output())])
    OpenAIAdvisorProvider(client, sleeper=lambda _s: None).analyze(_request(), _metadata())
    assert "temperature" not in captured


def test_from_env_disables_sdk_retries(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    captured: dict = {}

    class _FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    import openai as openai_module

    monkeypatch.setattr(openai_module, "OpenAI", _FakeOpenAI)
    OpenAIAdvisorProvider.from_env()
    assert captured.get("max_retries") == 0


def test_installed_sdk_supports_required_responses_api():
    # Guards the pinned SDK lower bound without making a network request.
    client = openai.OpenAI(api_key="test")
    assert callable(client.responses.parse)
