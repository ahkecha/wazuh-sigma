"""Build and query fixture catalogue."""

from __future__ import annotations

import logging
from json import JSONDecodeError
from pathlib import Path
from typing import Optional

from .errors import FixtureLookupError, FixtureValidationError
from .loader import load_fixture_catalogue_entry
from .models import FixtureCatalogueEntry

logger = logging.getLogger(__name__)


class FixtureCatalogue:
    """Index of all available fixture files.

    Supports lookup by provider, channel, and event_id.
    All field lookups are case-sensitive.
    """

    def __init__(self) -> None:
        """Initialize empty catalogue."""
        self._entries: list[FixtureCatalogueEntry] = []
        self._by_provider_channel: dict[
            tuple[str, str, int], list[FixtureCatalogueEntry]
        ] = {}

    def add_fixture(self, entry: FixtureCatalogueEntry) -> None:
        """Add fixture entry to catalogue.

        Args:
            entry: FixtureCatalogueEntry to add
        """
        self._entries.append(entry)

        key = (entry.metadata.provider, entry.metadata.channel, entry.metadata.event_id)
        if key not in self._by_provider_channel:
            self._by_provider_channel[key] = []
        self._by_provider_channel[key].append(entry)

    def lookup_exact(
        self,
        provider: str,
        channel: str,
        event_id: int,
    ) -> Optional[FixtureCatalogueEntry]:
        """Look up fixture by provider, channel, and event_id.

        Args:
            provider: Provider name (exact match)
            channel: Channel name (exact match)
            event_id: Event ID (exact match)

        Returns:
            First matching FixtureCatalogueEntry, or None if not found.
            If multiple fixtures match, returns the first one.
        """
        key = (provider, channel, event_id)
        entries = self._by_provider_channel.get(key)
        if entries:
            return entries[0]
        return None

    def find_by_context(
        self,
        provider: Optional[str] = None,
        channel: Optional[str] = None,
        event_id: Optional[int] = None,
    ) -> list[FixtureCatalogueEntry]:
        """Find fixtures matching context criteria.

        All criteria are AND-ed together.

        Args:
            provider: Provider name (optional, case-sensitive)
            channel: Channel name (optional, case-sensitive)
            event_id: Event ID (optional)

        Returns:
            List of matching FixtureCatalogueEntry objects
        """
        results = []

        for entry in self._entries:
            if provider is not None and entry.metadata.provider != provider:
                continue
            if channel is not None and entry.metadata.channel != channel:
                continue
            if event_id is not None and entry.metadata.event_id != event_id:
                continue

            results.append(entry)

        return results

    def find_field(self, field_name: str) -> list[FixtureCatalogueEntry]:
        """Find all fixtures containing a field (case-sensitive).

        Args:
            field_name: Field name to search for (exact case)

        Returns:
            List of FixtureCatalogueEntry objects containing the field
        """
        results = []
        for entry in self._entries:
            if entry.has_field(field_name):
                results.append(entry)
        return results

    def all_entries(self) -> list[FixtureCatalogueEntry]:
        """Get all catalogue entries.

        Returns:
            List of all FixtureCatalogueEntry objects
        """
        return list(self._entries)

    def size(self) -> int:
        """Get number of fixtures in catalogue.

        Returns:
            Number of loaded fixtures
        """
        return len(self._entries)


def build_fixture_catalogue(fixture_dir: str | Path) -> FixtureCatalogue:
    """Build fixture catalogue by scanning directory.

    Recursively scans the directory for JSON files and loads each as a fixture.
    Invalid or malformed fixtures are skipped with logging.

    Args:
        fixture_dir: Directory containing fixture JSON files

    Returns:
        FixtureCatalogue with all successfully loaded fixtures

    Raises:
        FileNotFoundError: If fixture_dir does not exist
    """
    catalogue = FixtureCatalogue()
    base_path = Path(fixture_dir)

    if not base_path.exists():
        raise FileNotFoundError(f"Fixture directory not found: {fixture_dir}")

    json_files = sorted(base_path.glob("**/*.json"))

    for json_file in json_files:
        try:
            entry = load_fixture_catalogue_entry(json_file)
            catalogue.add_fixture(entry)
        except (FixtureValidationError, FileNotFoundError, JSONDecodeError, OSError) as e:
            logger.warning(
                f"Skipping invalid fixture {json_file}: {type(e).__name__}: {e}"
            )

    logger.info(f"Built fixture catalogue with {catalogue.size()} fixtures")

    return catalogue


def lookup_fixture(
    catalogue: FixtureCatalogue,
    provider: str,
    channel: str,
    event_id: int,
) -> FixtureCatalogueEntry:
    """Look up fixture with guaranteed result.

    Args:
        catalogue: FixtureCatalogue to search
        provider: Provider name (exact match)
        channel: Channel name (exact match)
        event_id: Event ID (exact match)

    Returns:
        FixtureCatalogueEntry matching all criteria

    Raises:
        FixtureLookupError: If no fixture matches all criteria
    """
    entry = catalogue.lookup_exact(provider, channel, event_id)
    if entry is None:
        raise FixtureLookupError(
            f"No fixture found for provider={provider!r}, "
            f"channel={channel!r}, event_id={event_id}"
        )
    return entry
