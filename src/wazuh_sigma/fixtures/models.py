"""Typed models for fixture metadata and verification results."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal, Optional


class FixtureSourceType(str, Enum):
    """Type of fixture source."""

    CAPTURED_WAZUH_ALERT = "captured_wazuh_alert"
    CAPTURED_NATIVE_EVTX = "captured_native_evtx"
    CAPTURED_SYSMON = "captured_sysmon"
    OFFICIAL_MICROSOFT_DOCS = "official_microsoft_docs"
    OFFICIAL_SYSMON_DOCS = "official_sysmon_docs"

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Check if value is a valid source type."""
        return value.startswith("captured_") or value.startswith("official_")


@dataclass(frozen=True)
class FixtureMetadata:
    """Metadata for a fixture document.

    Attributes:
        fixture_schema_version: Version of fixture schema (e.g., wazuh-windows-fixture-v1)
        wazuh_version: Wazuh version this fixture was captured from
        windows_version: Windows version this fixture was captured from
        provider: Event provider name (e.g., Microsoft-Windows-Security-Auditing)
        channel: Event channel (e.g., Security)
        event_id: Windows event ID
        source_type: Type of fixture (captured_wazuh_alert, official_microsoft_docs, etc.)
        capture_method: Method used to capture fixture (e.g., archives.json, native_export)
        captured_at: ISO8601 timestamp when fixture was captured
        sanitized: Whether fixture content has been sanitized
        sanitization_notes: Notes about sanitization applied
        source_sha256: SHA256 of original unsanitized source
        evidence_reference: Path to evidence document validating this fixture
    """

    fixture_schema_version: str
    wazuh_version: str
    windows_version: str
    provider: str
    channel: str
    event_id: int
    source_type: str
    capture_method: str
    captured_at: str
    sanitized: bool
    sanitization_notes: str
    source_sha256: str
    evidence_reference: str

    def validate(self) -> None:
        """Validate metadata invariants.

        Raises:
            InvalidFixtureSchemaError: If schema version is not recognized
            InvalidFixtureSourceTypeError: If source_type is invalid
        """
        if self.fixture_schema_version != "wazuh-windows-fixture-v1":
            from .errors import InvalidFixtureSchemaError

            raise InvalidFixtureSchemaError(
                "<fixture>", self.fixture_schema_version
            )

        if not FixtureSourceType.is_valid(self.source_type):
            from .errors import InvalidFixtureSourceTypeError

            raise InvalidFixtureSourceTypeError("<fixture>", self.source_type)


@dataclass(frozen=True)
class FieldPath:
    """Path to a field within a fixture document.

    Example: FieldPath(path="win.system.eventID", namespace="system")

    Attributes:
        path: Dot-separated field path (e.g., win.system.eventID)
        namespace: Namespace segment (system, eventdata, etc.)
    """

    path: str
    namespace: Literal["system", "eventdata", "static", "generic"]

    @classmethod
    def from_wazuh_field(cls, wazuh_field: str) -> FieldPath:
        """Create FieldPath from a Wazuh field name.

        Args:
            wazuh_field: Field name like 'win.system.eventID'

        Returns:
            FieldPath with extracted namespace

        Raises:
            ValueError: If field format is invalid
        """
        parts = wazuh_field.split(".")
        if len(parts) < 2:
            raise ValueError(f"Invalid Wazuh field format: {wazuh_field}")

        namespace_str = parts[1]
        if namespace_str not in ("system", "eventdata", "static", "generic"):
            namespace_str = "generic"

        return cls(path=wazuh_field, namespace=namespace_str)  # type: ignore


@dataclass(frozen=True)
class FixtureCatalogueEntry:
    """Entry in the fixture catalogue.

    Attributes:
        fixture_path: Absolute path to fixture file
        metadata: Parsed fixture metadata
        all_fields: Set of all field paths in this fixture (case-sensitive)
    """

    fixture_path: str
    metadata: FixtureMetadata
    all_fields: frozenset[str]

    def has_field(self, field_name: str) -> bool:
        """Check if fixture contains field with exact case match.

        Args:
            field_name: Field name (e.g., win.system.eventID)

        Returns:
            True if field exists with exact case match
        """
        return field_name in self.all_fields

    def get_exact_field(self, field_name: str) -> Optional[str]:
        """Get field name from fixture with exact case.

        Args:
            field_name: Proposed field name to look up

        Returns:
            Exact field name from fixture, or None if not found
        """
        if field_name in self.all_fields:
            return field_name
        return None


@dataclass(frozen=True)
class VerificationResult:
    """Structured result of fixture verification.

    Attributes:
        status: Verification status
        fixture: Path to fixture used for verification (or None)
        field: Field name that was verified
        provider: Provider from fixture (or None)
        channel: Channel from fixture (or None)
        event_id: Event ID from fixture (or None)
        error: Error message if verification failed (or None)
        suggestion: Diagnostic suggestion for near-matches (or None)
    """

    status: Literal["verified", "unverified", "case_mismatch", "context_mismatch"]
    fixture: Optional[str]
    field: str
    provider: Optional[str]
    channel: Optional[str]
    event_id: Optional[int]
    error: Optional[str] = None
    suggestion: Optional[str] = None

    def is_verified(self) -> bool:
        """Check if verification succeeded."""
        return self.status == "verified"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation of result
        """
        return {
            "status": self.status,
            "fixture": self.fixture,
            "field": self.field,
            "provider": self.provider,
            "channel": self.channel,
            "event_id": self.event_id,
            "error": self.error,
            "suggestion": self.suggestion,
        }
