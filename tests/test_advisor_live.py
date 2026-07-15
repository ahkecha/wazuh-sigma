"""Optional live OpenAI advisor test.

NOT part of the default suite: this file is intentionally excluded from
``pyproject.toml`` ``testpaths`` so ``pytest`` never collects it automatically.
Run it explicitly, with a key and the marker, when you want a bounded live
smoke against the real API::

    OPENAI_API_KEY=sk-... pytest tests/test_advisor_live.py -m openai_integration

It issues a single request with a tight output-token cap and asserts only that a
schema-valid recommendation comes back. It never prints secrets.
"""

from __future__ import annotations

import os

import pytest

from tests.advisor_helpers import make_rule
from wazuh_sigma.advisor.features import extract_features
from wazuh_sigma.advisor.models import AdvisorModelOutput, ProviderRequestMetadata
from wazuh_sigma.advisor.providers.openai import OpenAIAdvisorProvider
from wazuh_sigma.advisor.sanitizer import sanitize_request

pytestmark = pytest.mark.openai_integration

_HAS_KEY = bool(os.getenv("OPENAI_API_KEY"))


@pytest.mark.skipif(not _HAS_KEY, reason="OPENAI_API_KEY not set; live advisor test skipped")
def test_live_single_recommendation_is_schema_valid():
    provider = OpenAIAdvisorProvider.from_env(max_retries=1)
    request = sanitize_request(extract_features(make_rule()))
    metadata = ProviderRequestMetadata(
        provider="openai",
        model=os.getenv("ADVISOR_TEST_MODEL", "gpt-5.4-nano"),
        prompt_version="severity-v1",
        output_schema_version="advisor-output-v1",
        timeout_seconds=30.0,
        max_output_tokens=300,
    )
    result = provider.analyze(request, metadata)
    assert isinstance(result, AdvisorModelOutput)
    assert 0 <= result.recommended_level <= 15
    assert 0.0 <= result.confidence <= 1.0
