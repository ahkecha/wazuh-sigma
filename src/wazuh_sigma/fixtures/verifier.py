"""Verify field mappings against fixtures with exact case matching."""

from __future__ import annotations

import difflib
import logging
from typing import Optional

from .catalogue import FixtureCatalogue
from .errors import FixtureLookupError
from .models import VerificationResult

logger = logging.getLogger(__name__)


def verify_exact_path(
    field_name: str,
    catalogue: FixtureCatalogue,
    provider: str,
    channel: str,
    event_id: int,
) -> VerificationResult:
    """Verify field exists in fixture with exact case and context.

    This is the primary verification function. It:
    1. Looks up the fixture by provider, channel, event_id
    2. Checks if field exists with EXACT case match (not .lower())
    3. Returns structured VerificationResult with diagnostic info

    A field matching in the WRONG provider fixture is NOT verified.

    Args:
        field_name: Field name to verify (e.g., win.system.eventID)
        catalogue: FixtureCatalogue to search
        provider: Expected provider (e.g., Microsoft-Windows-Security-Auditing)
        channel: Expected channel (e.g., Security)
        event_id: Expected event ID (e.g., 4624)

    Returns:
        VerificationResult with status and diagnostic info.
        Status is:
        - "verified": Field found with exact case in correct fixture
        - "case_mismatch": Field exists but case doesn't match
        - "context_mismatch": Field not in this context's fixture
        - "unverified": Field not found anywhere
    """
    from .catalogue import lookup_fixture

    try:
        fixture = lookup_fixture(catalogue, provider, channel, event_id)
    except FixtureLookupError as e:
        # Fixture not found for this context
        logger.debug(f"Fixture lookup failed: {e}")
        similar_fields = find_similar_fields(field_name, catalogue)
        suggestion = similar_fields[0] if similar_fields else None

        return VerificationResult(
            status="context_mismatch",
            fixture=None,
            field=field_name,
            provider=provider,
            channel=channel,
            event_id=event_id,
            error=str(e),
            suggestion=suggestion,
        )

    # Fixture found. Check for exact match.
    if fixture.has_field(field_name):
        # Exact match found!
        return VerificationResult(
            status="verified",
            fixture=fixture.fixture_path,
            field=field_name,
            provider=fixture.metadata.provider,
            channel=fixture.metadata.channel,
            event_id=fixture.metadata.event_id,
            error=None,
            suggestion=None,
        )

    # Field not found. Check for case mismatch.
    case_insensitive_match = find_case_insensitive_match(
        field_name, fixture.all_fields
    )

    if case_insensitive_match:
        # Field exists but with wrong case
        return VerificationResult(
            status="case_mismatch",
            fixture=fixture.fixture_path,
            field=field_name,
            provider=fixture.metadata.provider,
            channel=fixture.metadata.channel,
            event_id=fixture.metadata.event_id,
            error=(
                f"Field '{field_name}' not found in fixture. "
                f"Found '{case_insensitive_match}' with different case."
            ),
            suggestion=case_insensitive_match,
        )

    # Field not found at all
    similar_fields = find_similar_fields(field_name, catalogue)
    suggestion = similar_fields[0] if similar_fields else None

    return VerificationResult(
        status="unverified",
        fixture=fixture.fixture_path,
        field=field_name,
        provider=fixture.metadata.provider,
        channel=fixture.metadata.channel,
        event_id=fixture.metadata.event_id,
        error=f"Field '{field_name}' not found in fixture",
        suggestion=suggestion,
    )


def verify_mapping_against_fixtures(
    field_name: str,
    catalogue: FixtureCatalogue,
    provider: Optional[str] = None,
    channel: Optional[str] = None,
    event_id: Optional[int] = None,
) -> VerificationResult:
    """Verify field mapping against any matching fixtures.

    This function is more permissive than verify_exact_path():
    - If provider, channel, event_id are provided, verify against that specific fixture
    - Otherwise, search across all fixtures for the field
    - NEVER emit "verified" for a field that exists in a DIFFERENT context fixture

    Args:
        field_name: Field name to verify (e.g., win.system.eventID)
        catalogue: FixtureCatalogue to search
        provider: Provider name (optional, case-sensitive)
        channel: Channel name (optional, case-sensitive)
        event_id: Event ID (optional)

    Returns:
        VerificationResult with status and diagnostic info
    """
    if provider is not None and channel is not None and event_id is not None:
        # Specific context provided - use exact verification
        return verify_exact_path(
            field_name, catalogue, provider, channel, event_id
        )

    # Search across all matching fixtures
    fixtures = catalogue.find_by_context(
        provider=provider, channel=channel, event_id=event_id
    )

    if not fixtures:
        # No fixtures match the criteria
        similar_fields = find_similar_fields(field_name, catalogue)
        suggestion = similar_fields[0] if similar_fields else None

        return VerificationResult(
            status="unverified",
            fixture=None,
            field=field_name,
            provider=provider,
            channel=channel,
            event_id=event_id,
            error=f"No fixtures found for provider={provider}, "
            f"channel={channel}, event_id={event_id}",
            suggestion=suggestion,
        )

    # Check if field exists in any matching fixture
    for fixture in fixtures:
        if fixture.has_field(field_name):
            return VerificationResult(
                status="verified",
                fixture=fixture.fixture_path,
                field=field_name,
                provider=fixture.metadata.provider,
                channel=fixture.metadata.channel,
                event_id=fixture.metadata.event_id,
                error=None,
                suggestion=None,
            )

    # Check for case mismatches
    for fixture in fixtures:
        match = find_case_insensitive_match(field_name, fixture.all_fields)
        if match:
            return VerificationResult(
                status="case_mismatch",
                fixture=fixture.fixture_path,
                field=field_name,
                provider=fixture.metadata.provider,
                channel=fixture.metadata.channel,
                event_id=fixture.metadata.event_id,
                error=(
                    f"Field '{field_name}' not found. "
                    f"Found '{match}' with different case."
                ),
                suggestion=match,
            )

    # Field not found
    similar_fields = find_similar_fields(field_name, catalogue)
    suggestion = similar_fields[0] if similar_fields else None

    return VerificationResult(
        status="unverified",
        fixture=fixtures[0].fixture_path if fixtures else None,
        field=field_name,
        provider=provider,
        channel=channel,
        event_id=event_id,
        error=f"Field '{field_name}' not found in any matching fixture",
        suggestion=suggestion,
    )


def find_case_insensitive_match(
    field_name: str, available_fields: frozenset[str]
) -> Optional[str]:
    """Find field with same name but different case.

    This is used for diagnostic purposes only. Never returns a valid
    verification unless the case matches EXACTLY.

    Args:
        field_name: Field name to search for
        available_fields: Set of available fields (case-sensitive)

    Returns:
        Matching field with different case, or None if no case-insensitive match
    """
    lower_name = field_name.lower()
    for field in available_fields:
        if field.lower() == lower_name and field != field_name:
            return field
    return None


def find_similar_fields(
    field_name: str,
    catalogue: FixtureCatalogue,
    max_suggestions: int = 3,
) -> list[str]:
    """Find fields similar to input (for diagnostic suggestions).

    Uses difflib to find close matches across all fixtures.
    This is diagnostic only and never passes verification.

    Args:
        field_name: Field name to search for
        catalogue: FixtureCatalogue to search
        max_suggestions: Maximum number of suggestions to return

    Returns:
        List of similar field names (sorted by similarity)
    """
    all_fields = set()
    for entry in catalogue.all_entries():
        all_fields.update(entry.all_fields)

    similar = difflib.get_close_matches(
        field_name, all_fields, n=max_suggestions, cutoff=0.6
    )
    return similar
