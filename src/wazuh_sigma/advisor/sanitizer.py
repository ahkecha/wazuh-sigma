"""Deterministic sanitization and redaction of advisor requests.

Runs before any external API request. Redaction is deterministic (same input
-> same placeholders), versioned, and never exposes the original values it
removed. In strict mode, detection of high-risk secrets (API keys, bearer
tokens, passwords) raises :class:`AdvisorSanitizationError` instead of sending
a redacted request.

Only the free-text fields — the rule title and description — are scrubbed for
secrets. The structured feature set carries field *names*, counts, and coarse
booleans, not raw detection values, so it does not transit secrets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from wazuh_sigma.advisor.errors import AdvisorSanitizationError
from wazuh_sigma.advisor.models import SanitizedAdvisorRequest, SigmaFeatureSet

#: Bumped whenever redaction rules change. Part of the advisor cache key.
SANITIZER_VERSION = "sanitizer-v1"

#: Redaction categories that are considered high-risk secrets. In strict mode,
#: their presence rejects the request rather than redacting it.
HIGH_RISK_CATEGORIES: frozenset[str] = frozenset(
    {
        "api_key",
        "bearer_token",
        "password",
    }
)


@dataclass(frozen=True)
class _RedactionRule:
    category: str
    placeholder: str
    pattern: re.Pattern[str]


# Order matters: higher-risk / more-specific patterns run first so that, e.g.,
# an authorization header is not partially consumed by the generic IP rule.
_REDACTION_RULES: tuple[_RedactionRule, ...] = (
    _RedactionRule(
        "api_key",
        "<redacted:api_key>",
        re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9]{16,}\b"),
    ),
    _RedactionRule(
        "bearer_token",
        "<redacted:bearer_token>",
        re.compile(r"(?i)\b(?:bearer|authorization)\s*[:=]?\s*[A-Za-z0-9._~+/-]{12,}=*"),
    ),
    _RedactionRule(
        "password",
        "<redacted:password>",
        re.compile(r"(?i)\b(?:password|passwd|pwd|secret)\s*[:=]\s*\S+"),
    ),
    _RedactionRule(
        "internal_ip",
        "<redacted:internal_ip>",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
        ),
    ),
    _RedactionRule(
        "internal_domain",
        "<redacted:internal_domain>",
        re.compile(r"\b[A-Za-z0-9-]+\.(?:corp|internal|local|lan|intra|intranet)\b", re.IGNORECASE),
    ),
    _RedactionRule(
        "user_path",
        "<redacted:user_path>",
        re.compile(r"(?i)(?:[A-Za-z]:\\Users\\|/home/|/Users/)[^\\/\s]+"),
    ),
)


@dataclass(frozen=True)
class SanitizationResult:
    """Outcome of sanitizing a single string: cleaned text plus categories hit."""

    text: str
    categories: tuple[str, ...]


def sanitize_text(value: str) -> SanitizationResult:
    """Redact secrets from a free-text value deterministically.

    Returns the cleaned text and the ordered, de-duplicated set of redaction
    categories that fired. Never returns the original matched substrings.
    """
    categories: dict[str, None] = {}
    cleaned = value
    for rule in _REDACTION_RULES:
        if rule.pattern.search(cleaned):
            categories.setdefault(rule.category, None)
            cleaned = rule.pattern.sub(rule.placeholder, cleaned)
    return SanitizationResult(text=cleaned, categories=tuple(categories))


def sanitize_request(features: SigmaFeatureSet, *, strict: bool = False) -> SanitizedAdvisorRequest:
    """Produce a sanitized, provider-bound request from a feature set.

    In ``strict`` mode, detection of any high-risk secret category raises
    :class:`AdvisorSanitizationError` (with only the category names, never the
    values). Otherwise the values are redacted and the request proceeds.
    """
    title_result = sanitize_text(features.title)
    description_result = sanitize_text(features.description)

    all_categories: dict[str, None] = {}
    for category in (*title_result.categories, *description_result.categories):
        all_categories.setdefault(category, None)

    high_risk_hits = sorted(HIGH_RISK_CATEGORIES.intersection(all_categories))
    if strict and high_risk_hits:
        raise AdvisorSanitizationError(
            "strict sanitization rejected a request containing high-risk secrets: "
            f"{', '.join(high_risk_hits)}"
        )

    redaction_applied = bool(all_categories)
    return SanitizedAdvisorRequest(
        sanitizer_version=SANITIZER_VERSION,
        # Only the provider-safe subset travels onward; raw title/description
        # never leave the local SigmaFeatureSet.
        features=features.to_provider_features(),
        sanitized_title=title_result.text,
        sanitized_description=description_result.text,
        redaction_applied=redaction_applied,
        redaction_categories=list(all_categories),
    )
