"""Custom exceptions for fixture verification."""

from __future__ import annotations

from typing import Optional


class FixtureValidationError(Exception):
    """Base exception for fixture validation failures."""

    pass


class CaseMismatchError(FixtureValidationError):
    """Raised when field name case does not match exactly."""

    def __init__(
        self,
        field_name: str,
        expected_name: str,
        fixture_path: str,
    ) -> None:
        """Initialize CaseMismatchError.

        Args:
            field_name: The field name that was provided (wrong case)
            expected_name: The correct field name from fixture (exact case)
            fixture_path: Path to the fixture file
        """
        self.field_name = field_name
        self.expected_name = expected_name
        self.fixture_path = fixture_path
        message = (
            f"Case mismatch in {fixture_path}: "
            f"field '{field_name}' does not match exact case '{expected_name}'"
        )
        super().__init__(message)


class ContextMismatchError(FixtureValidationError):
    """Raised when field context (provider, channel, event_id) does not match."""

    def __init__(
        self,
        field_name: str,
        fixture_path: str,
        fixture_provider: Optional[str],
        expected_provider: Optional[str],
        fixture_channel: Optional[str],
        expected_channel: Optional[str],
        fixture_event_id: Optional[int],
        expected_event_id: Optional[int],
    ) -> None:
        """Initialize ContextMismatchError."""
        self.field_name = field_name
        self.fixture_path = fixture_path
        self.fixture_provider = fixture_provider
        self.expected_provider = expected_provider
        self.fixture_channel = fixture_channel
        self.expected_channel = expected_channel
        self.fixture_event_id = fixture_event_id
        self.expected_event_id = expected_event_id

        parts = []
        if fixture_provider != expected_provider:
            parts.append(
                f"provider {fixture_provider!r} != {expected_provider!r}"
            )
        if fixture_channel != expected_channel:
            parts.append(f"channel {fixture_channel!r} != {expected_channel!r}")
        if fixture_event_id != expected_event_id:
            parts.append(f"event_id {fixture_event_id} != {expected_event_id}")

        message = (
            f"Context mismatch for field '{field_name}' in {fixture_path}: "
            f"{', '.join(parts)}"
        )
        super().__init__(message)


class MissingEvidenceError(FixtureValidationError):
    """Raised when fixture evidence document is missing or invalid."""

    def __init__(
        self,
        fixture_path: str,
        evidence_reference: str,
    ) -> None:
        """Initialize MissingEvidenceError."""
        self.fixture_path = fixture_path
        self.evidence_reference = evidence_reference
        message = (
            f"Missing or invalid evidence for fixture {fixture_path}: "
            f"{evidence_reference} not found"
        )
        super().__init__(message)


class InvalidFixtureSchemaError(FixtureValidationError):
    """Raised when fixture schema version is not recognized."""

    def __init__(self, fixture_path: str, schema_version: str) -> None:
        """Initialize InvalidFixtureSchemaError."""
        self.fixture_path = fixture_path
        self.schema_version = schema_version
        message = (
            f"Unknown fixture schema version {schema_version!r} in {fixture_path}. "
            f"Only 'wazuh-windows-fixture-v1' is supported."
        )
        super().__init__(message)


class InvalidFixtureSourceTypeError(FixtureValidationError):
    """Raised when fixture source_type is not in allowed set."""

    def __init__(self, fixture_path: str, source_type: str) -> None:
        """Initialize InvalidFixtureSourceTypeError."""
        self.fixture_path = fixture_path
        self.source_type = source_type
        message = (
            f"Invalid fixture source_type {source_type!r} in {fixture_path}. "
            f"Must be one of: captured_*, official_*"
        )
        super().__init__(message)


class MissingFixtureMetadataError(FixtureValidationError):
    """Raised when fixture metadata is missing."""

    def __init__(self, fixture_path: str, missing_field: str) -> None:
        """Initialize MissingFixtureMetadataError."""
        self.fixture_path = fixture_path
        self.missing_field = missing_field
        message = f"Missing metadata field '{missing_field}' in fixture {fixture_path}"
        super().__init__(message)


class FixtureLookupError(FixtureValidationError):
    """Raised when fixture lookup fails or is ambiguous."""

    def __init__(self, message: str) -> None:
        """Initialize FixtureLookupError."""
        super().__init__(message)
