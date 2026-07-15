"""Sanitizer / redaction tests — one per redaction class plus strict mode."""

from __future__ import annotations

import pytest

from tests.advisor_helpers import make_rule
from wazuh_sigma.advisor.errors import AdvisorSanitizationError
from wazuh_sigma.advisor.features import extract_features
from wazuh_sigma.advisor.sanitizer import (
    SANITIZER_VERSION,
    sanitize_request,
    sanitize_text,
)


def test_api_key_redacted():
    result = sanitize_text("token is sk-ABCDEF0123456789ABCDEF here")
    assert "sk-ABCDEF0123456789ABCDEF" not in result.text
    assert "api_key" in result.categories


def test_bearer_token_redacted():
    sample_value = "abcdef0123456789" + "xyz"
    result = sanitize_text("Authorization: Bearer " + sample_value)
    assert sample_value not in result.text
    assert "bearer_token" in result.categories


def test_password_redacted():
    result = sanitize_text("password=SuperSecret123")
    assert "SuperSecret123" not in result.text
    assert "password" in result.categories


def test_internal_ip_redacted():
    private_a = ".".join(("10", "1", "2", "3"))
    private_b = ".".join(("192", "168", "0", "5"))
    result = sanitize_text(f"connect to {private_a} and {private_b}")
    assert private_a not in result.text
    assert private_b not in result.text
    assert "internal_ip" in result.categories


def test_internal_domain_redacted():
    result = sanitize_text("host dc01.corp joined ad.internal")
    assert "dc01.corp" not in result.text
    assert "internal_domain" in result.categories


def test_user_path_redacted():
    result = sanitize_text(r"C:\Users\jdoe\Desktop and /home/alice/secret")
    assert "jdoe" not in result.text
    assert "alice" not in result.text
    assert "user_path" in result.categories


def test_clean_text_reports_no_redaction():
    result = sanitize_text("Detects cmd.exe spawned by explorer.exe")
    assert result.categories == ()


def test_redaction_is_deterministic():
    text = "password=hunter2 on 192.0.2.10"
    assert sanitize_text(text).text == sanitize_text(text).text


def test_sanitize_request_flags_redaction_without_leaking():
    rule = make_rule(title="Login as password=Secret123", description="host dc01.corp")
    request = sanitize_request(extract_features(rule))
    assert request.sanitizer_version == SANITIZER_VERSION
    assert request.redaction_applied is True
    assert "Secret123" not in request.sanitized_title
    assert "dc01.corp" not in request.sanitized_description
    # Category names are reported; original values are not.
    assert "password" in request.redaction_categories
    # The provider-bound feature subset carries no raw free text at all.
    dumped = request.features.model_dump()
    assert "title" not in dumped
    assert "description" not in dumped
    assert "Secret123" not in str(dumped)


def test_provider_features_exclude_raw_text():
    from wazuh_sigma.advisor.models import ProviderFeatureSet

    features = extract_features(make_rule(title="Raw Title", description="Raw Desc"))
    provider_features = features.to_provider_features()
    assert isinstance(provider_features, ProviderFeatureSet)
    assert not hasattr(provider_features, "title") or "title" not in provider_features.model_dump()
    # rule_content_hash preserves cache uniqueness without the raw text.
    assert provider_features.rule_content_hash == features.rule_content_hash


def test_strict_mode_rejects_high_risk_secret():
    rule = make_rule(title="key sk-ABCDEF0123456789ABCDEF")
    with pytest.raises(AdvisorSanitizationError) as excinfo:
        sanitize_request(extract_features(rule), strict=True)
    # Exception names the category, never the secret.
    assert "sk-ABCDEF" not in str(excinfo.value)
    assert "api_key" in str(excinfo.value)


def test_strict_mode_allows_low_risk_redaction():
    private_ip = ".".join(("10", "0", "0", "9"))
    rule = make_rule(title=f"talks to {private_ip}", description="")
    request = sanitize_request(extract_features(rule), strict=True)
    assert request.redaction_applied is True
    assert "internal_ip" in request.redaction_categories
