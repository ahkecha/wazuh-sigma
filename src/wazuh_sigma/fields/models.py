"""Typed models for field mapping definitions and resolution results."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal, Optional


class FieldNamespace(str, Enum):
    """Namespace of a Wazuh decoded field."""

    SYSTEM = "system"
    EVENTDATA = "eventdata"
    STATIC = "static"
    GENERIC = "generic"


class VerificationSource(str, Enum):
    """Source of verification for a field mapping."""

    WAZUH_DOCUMENTATION = "wazuh_documentation"
    WINDOWS_DOCUMENTATION = "windows_documentation"
    DECODED_FIXTURE = "decoded_fixture"
    REPOSITORY_LEGACY = "repository_legacy"


class ConfidenceLevel(str, Enum):
    """Confidence level of a field mapping."""

    VERIFIED = "verified"
    HIGH = "high"
    PROVISIONAL = "provisional"


@dataclass(frozen=True)
class FieldResolutionResult:
    """Result of resolving a Sigma field to a Wazuh field.

    This typed result enables safe handling of different resolution modes:
    - "resolved": field_name is valid and verified, safe to emit
    - "unsupported": field_name is None, must not emit (Windows field in strict/warn mode)
    - "legacy_fallback": field_name is lowercased fallback (legacy mode only)
    - "warning": field_name should not be emitted; use warning_message for logging

    Attributes:
        field_name: Resolved Wazuh field name, or None if field must not be emitted
        status: Resolution status indicating safety level
        warning_message: Optional warning message for logging or diagnostics
        verification: Source of verification if field_name is resolved
    """

    field_name: Optional[str]
    status: Literal["resolved", "unsupported", "legacy_fallback", "warning"]
    warning_message: Optional[str] = None
    verification: Optional[VerificationSource] = None

    def should_emit(self) -> bool:
        """Check if this field should be emitted in the rule.

        Returns False for unsupported and warning statuses.
        """
        return self.status == "resolved" or self.status == "legacy_fallback"

    def get_field_name_or_raise(self) -> str:
        """Get field name or raise ValueError if None.

        Used in legacy_fallback and resolved statuses.
        """
        if self.field_name is None:
            raise ValueError(f"Field resolution status {self.status!r} has no field_name: {self.warning_message}")
        return self.field_name


@dataclass(frozen=True)
class FieldMapping:
    """Definition of a Sigma field to Wazuh field mapping.

    All mappings require:
    - sigma_field: The Sigma field name (exact case)
    - wazuh_field: The Wazuh decoded field name (exact case)
    - namespace: Where the field lives (system, eventdata, static, generic)
    - products: Log source products this mapping applies to
    - services: Log source services (may be empty for product-level mappings)
    - categories: Log source categories (may be empty)
    - documentation_reference: URL or file path to verification source
    - verification_source: Type of source used for verification
    - confidence: How confident we are in this mapping

    Optional:
    - notes: Implementation notes or gotchas
    """

    sigma_field: str
    wazuh_field: str
    namespace: FieldNamespace
    products: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    documentation_reference: str = ""
    verification_source: VerificationSource = VerificationSource.REPOSITORY_LEGACY
    confidence: ConfidenceLevel = ConfidenceLevel.PROVISIONAL
    notes: str | None = None

    def __post_init__(self) -> None:
        # Validate namespace consistency for Windows fields
        if self.wazuh_field.startswith("win."):
            namespace = self._extract_namespace(self.wazuh_field)
            if namespace != self.namespace:
                raise ValueError(
                    f"Namespace mismatch for {self.sigma_field}: "
                    f"field prefix indicates {namespace} but namespace={self.namespace}"
                )

    @staticmethod
    def _extract_namespace(wazuh_field: str) -> FieldNamespace:
        """Extract namespace from a wazuh field like 'win.system.eventID'."""
        parts = wazuh_field.split(".")
        if len(parts) < 2:
            return FieldNamespace.GENERIC
        if parts[0] != "win":
            return FieldNamespace.GENERIC
        if parts[1] == "system":
            return FieldNamespace.SYSTEM
        if parts[1] == "eventdata":
            return FieldNamespace.EVENTDATA
        return FieldNamespace.GENERIC

    def applies_to(
        self,
        *,
        product: str | None = None,
        service: str | None = None,
        category: str | None = None,
    ) -> bool:
        """Check if this mapping applies to the given logsource context."""
        if self.products and product:
            if product.lower() not in (p.lower() for p in self.products):
                return False
        if self.services and service:
            if service.lower() not in (s.lower() for s in self.services):
                return False
        if self.categories and category:
            if category.lower() not in (c.lower() for c in self.categories):
                return False
        return True
