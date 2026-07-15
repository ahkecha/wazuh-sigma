"""Explicit typed exceptions for incremental conversion."""

from __future__ import annotations


class ConversionCacheError(Exception):
    """Base exception for conversion cache failures."""


class ManifestError(Exception):
    """Base exception for manifest-related failures."""


class ManifestCorruptionError(ManifestError):
    """Manifest file is corrupted or invalid."""


class DuplicateRuleIdentityError(ManifestError):
    """Multiple rules share the same stable identity (Sigma UUID or fallback hash)."""


class DuplicateRuleIDError(ManifestError):
    """Multiple rules were allocated the same Wazuh rule ID."""


class RuleIDRangeExhaustedError(ManifestError):
    """No more rule IDs available in the configured range."""


class ConversionFingerprintError(Exception):
    """Fingerprint computation failed."""
