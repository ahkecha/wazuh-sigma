"""Incremental conversion cache for Sigma-to-Wazuh rules.

This package provides content-addressed caching of converted rule XML fragments
and persistent rule ID allocation. It is an optimization layer that sits
between rule discovery and backend conversion, allowing unchanged rules to
reuse cached XML without reparsing or reconversion.

Key classes:

- :class:`RuleManifest` — persistent identity and ID allocation tracking
- :class:`ConversionCache` — content-addressed fragment storage
- :class:`IncrementalConverterService` — orchestration
"""

from wazuh_sigma.incremental.cache import ConversionCache
from wazuh_sigma.incremental.errors import (
    ConversionCacheError,
    ConversionFingerprintError,
    DuplicateRuleIDError,
    DuplicateRuleIdentityError,
    ManifestCorruptionError,
    ManifestError,
    RuleIDRangeExhaustedError,
)
from wazuh_sigma.incremental.models import (
    CacheEntry,
    ManifestEntry,
    RuleManifest,
)
from wazuh_sigma.incremental.service import IncrementalConverterService

__all__ = [
    "CacheEntry",
    "ConversionCache",
    "ConversionCacheError",
    "ConversionFingerprintError",
    "DuplicateRuleIDError",
    "DuplicateRuleIdentityError",
    "IncrementalConverterService",
    "ManifestCorruptionError",
    "ManifestEntry",
    "ManifestError",
    "RuleIDRangeExhaustedError",
    "RuleManifest",
]
