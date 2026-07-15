"""Content-addressed cache tests: keying, invalidation, corruption, disable."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.advisor_helpers import make_output, make_rule
from wazuh_sigma.advisor.cache import AdvisorCache, compute_cache_key
from wazuh_sigma.advisor.errors import AdvisorCacheError
from wazuh_sigma.advisor.features import extract_features
from wazuh_sigma.advisor.policy import POLICY_VERSION
from wazuh_sigma.advisor.prompts import prompt_cache_signature
from wazuh_sigma.advisor.sanitizer import sanitize_request


def _request():
    return sanitize_request(extract_features(make_rule()))


def _key(request, **over):
    params = {
        "prompt_versions": prompt_cache_signature(),
        "policy_version": POLICY_VERSION,
        "provider": "openai",
        "primary_model": "gpt-5.4-nano",
        "escalation_model": "gpt-5.4-mini",
    }
    params.update(over)
    return compute_cache_key(request, **params)


def test_cache_key_is_deterministic():
    request = _request()
    assert _key(request) == _key(_request())


def test_cache_key_changes_with_prompt_version():
    request = _request()
    baseline = _key(request)
    bumped = _key(
        request, prompt_versions={**prompt_cache_signature(), "prompt_version": "severity-v999"}
    )
    assert baseline != bumped


def test_cache_key_changes_with_model():
    request = _request()
    assert _key(request) != _key(request, primary_model="gpt-9.9-ultra")


def test_round_trip_put_get(tmp_path: Path):
    cache = AdvisorCache(tmp_path / "cache")
    request = _request()
    key = _key(request)
    entry = cache.build_entry(
        cache_key=key,
        provider="openai",
        primary_model="gpt-5.4-nano",
        escalation_model="gpt-5.4-mini",
        request=request,
        prompt_versions=prompt_cache_signature(),
        policy_version=POLICY_VERSION,
        primary_response=make_output(),
        escalation_response=None,
    )
    cache.put(entry)
    loaded = cache.get(key)
    assert loaded is not None
    assert loaded.primary_response.recommended_level == make_output().recommended_level


def test_missing_entry_is_miss(tmp_path: Path):
    cache = AdvisorCache(tmp_path / "cache")
    assert cache.get("deadbeef") is None


def test_corrupted_entry_is_treated_as_miss(tmp_path: Path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(parents=True)
    (cache_dir / "corrupt.json").write_text("{not valid json", encoding="utf-8")
    cache = AdvisorCache(cache_dir)
    assert cache.get("corrupt") is None


def test_mismatched_key_is_ignored(tmp_path: Path):
    cache = AdvisorCache(tmp_path / "cache")
    request = _request()
    entry = cache.build_entry(
        cache_key="realkey",
        provider="openai",
        primary_model="gpt-5.4-nano",
        escalation_model=None,
        request=request,
        prompt_versions=prompt_cache_signature(),
        policy_version=POLICY_VERSION,
        primary_response=make_output(),
        escalation_response=None,
    )
    cache.put(entry)
    # Reading under a different key file name would mismatch; simulate by copying.
    src = (tmp_path / "cache" / "realkey.json").read_text(encoding="utf-8")
    (tmp_path / "cache" / "otherkey.json").write_text(src, encoding="utf-8")
    assert cache.get("otherkey") is None


def test_disabled_cache_never_reads_or_writes(tmp_path: Path):
    cache = AdvisorCache(tmp_path / "cache", enabled=False)
    request = _request()
    entry = cache.build_entry(
        cache_key="k",
        provider="openai",
        primary_model="m",
        escalation_model=None,
        request=request,
        prompt_versions=prompt_cache_signature(),
        policy_version=POLICY_VERSION,
        primary_response=make_output(),
        escalation_response=None,
    )
    cache.put(entry)
    assert not (tmp_path / "cache").exists()
    assert cache.get("k") is None


def test_put_failure_raises_cache_error(tmp_path: Path):
    # Point the cache at a path where the directory can't be created (a file).
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file", encoding="utf-8")
    cache = AdvisorCache(blocker / "cache")
    request = _request()
    entry = cache.build_entry(
        cache_key="k",
        provider="openai",
        primary_model="m",
        escalation_model=None,
        request=request,
        prompt_versions=prompt_cache_signature(),
        policy_version=POLICY_VERSION,
        primary_response=make_output(),
        escalation_response=None,
    )
    with pytest.raises(AdvisorCacheError):
        cache.put(entry)
