"""Load and validate fixture files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .errors import (
    InvalidFixtureSchemaError,
    InvalidFixtureSourceTypeError,
    MissingFixtureMetadataError,
)
from .models import FixtureCatalogueEntry, FixtureMetadata, FixtureSourceType


def load_fixture(fixture_path: str | Path) -> dict[str, Any]:
    """Load a fixture JSON file with validation.

    Args:
        fixture_path: Path to fixture JSON file

    Returns:
        Parsed fixture dictionary

    Raises:
        FileNotFoundError: If fixture file does not exist
        json.JSONDecodeError: If fixture is not valid JSON
    """
    path = Path(fixture_path)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_fixture_schema(fixture_data: dict[str, Any]) -> FixtureMetadata:
    """Validate fixture data and extract metadata.

    Args:
        fixture_data: Parsed fixture dictionary

    Returns:
        FixtureMetadata object

    Raises:
        MissingFixtureMetadataError: If required metadata field is missing
        InvalidFixtureSchemaError: If schema version is not recognized
        InvalidFixtureSourceTypeError: If source_type is invalid
    """
    metadata_key = "_fixture_metadata"
    if metadata_key not in fixture_data:
        raise MissingFixtureMetadataError("<fixture>", metadata_key)

    metadata_dict = fixture_data[metadata_key]

    required_fields = [
        "fixture_schema_version",
        "wazuh_version",
        "windows_version",
        "provider",
        "channel",
        "event_id",
        "source_type",
        "capture_method",
        "captured_at",
        "sanitized",
        "sanitization_notes",
        "source_sha256",
        "evidence_reference",
    ]

    for field in required_fields:
        if field not in metadata_dict:
            raise MissingFixtureMetadataError("<fixture>", field)

    metadata = FixtureMetadata(
        fixture_schema_version=metadata_dict["fixture_schema_version"],
        wazuh_version=metadata_dict["wazuh_version"],
        windows_version=metadata_dict["windows_version"],
        provider=metadata_dict["provider"],
        channel=metadata_dict["channel"],
        event_id=int(metadata_dict["event_id"]),
        source_type=metadata_dict["source_type"],
        capture_method=metadata_dict["capture_method"],
        captured_at=metadata_dict["captured_at"],
        sanitized=bool(metadata_dict["sanitized"]),
        sanitization_notes=metadata_dict["sanitization_notes"],
        source_sha256=metadata_dict["source_sha256"],
        evidence_reference=metadata_dict["evidence_reference"],
    )

    metadata.validate()

    return metadata


def extract_all_fields(fixture_data: dict[str, Any]) -> frozenset[str]:
    """Extract all field paths from fixture data (exact case).

    Recursively walks the fixture structure and collects all field names
    with their exact case from the fixture file.

    Args:
        fixture_data: Parsed fixture dictionary

    Returns:
        Frozenset of all field paths (case-sensitive) like:
        {
            "win.system.eventID",
            "win.system.channel",
            "win.eventdata.targetUserName",
            ...
        }
    """
    fields = set()

    def walk_structure(
        obj: Any, prefix: Optional[str] = None
    ) -> None:
        """Recursively walk fixture structure and collect field paths."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "_fixture_metadata":
                    continue

                if prefix:
                    path = f"{prefix}.{key}"
                else:
                    path = key

                fields.add(path)

                if isinstance(value, dict):
                    walk_structure(value, path)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                if isinstance(item, dict):
                    walk_structure(item, prefix)

    walk_structure(fixture_data)
    return frozenset(fields)


def load_fixture_catalogue_entry(
    fixture_path: str | Path,
) -> FixtureCatalogueEntry:
    """Load a fixture file and create a catalogue entry.

    Args:
        fixture_path: Path to fixture JSON file

    Returns:
        FixtureCatalogueEntry with metadata and field listing

    Raises:
        FileNotFoundError: If fixture file does not exist
        json.JSONDecodeError: If fixture is not valid JSON
        MissingFixtureMetadataError: If required metadata is missing
        InvalidFixtureSchemaError: If schema version is not recognized
        InvalidFixtureSourceTypeError: If source_type is invalid
    """
    path = Path(fixture_path)
    fixture_data = load_fixture(path)
    metadata = validate_fixture_schema(fixture_data)
    all_fields = extract_all_fields(fixture_data)

    return FixtureCatalogueEntry(
        fixture_path=str(path.absolute()),
        metadata=metadata,
        all_fields=all_fields,
    )
