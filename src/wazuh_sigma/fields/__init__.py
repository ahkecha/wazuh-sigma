"""Field mapping and resolution for Windows EVTX and generic log sources.

This package provides typed, context-aware field mapping from Sigma detection
fields to Wazuh decoded event fields. All mappings are documented with sources
and verification evidence.
"""

from wazuh_sigma.fields.errors import (
    FieldMappingError,
    UnsupportedWindowsFieldError,
    InvalidMappingConfigError,
)
from wazuh_sigma.fields.models import (
    FieldMapping,
    FieldNamespace,
    VerificationSource,
    ConfidenceLevel,
)
from wazuh_sigma.fields.registry import FieldMappingRegistry
from wazuh_sigma.fields.validation import FieldValidator

__all__ = [
    "FieldMappingError",
    "UnsupportedWindowsFieldError",
    "InvalidMappingConfigError",
    "FieldMapping",
    "FieldNamespace",
    "VerificationSource",
    "ConfidenceLevel",
    "FieldMappingRegistry",
    "FieldValidator",
]
