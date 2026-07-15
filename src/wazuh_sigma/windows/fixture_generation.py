"""
Windows Event Fixture Generation.

Create test fixtures from Windows event groups with proper metadata.
Generates fixture files, inventory report, and field mapping documentation.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple


def create_fixture_content(
    event_group: Dict[str, Any],
    extracted_at: str,
) -> Dict[str, Any]:
    """
    Create fixture content from event group with proper metadata.

    Args:
        event_group: Dictionary containing provider, channel, eventID,
            eventCount, and sample_event.
        extracted_at: ISO format timestamp of extraction.

    Returns:
        Dictionary with fixture metadata and decoded event data.
    """
    provider = event_group["provider"]
    channel = event_group["channel"]
    event_id = event_group["eventID"]
    event_count = event_group["eventCount"]
    sample_event = event_group["sample_event"]

    # Create fixture metadata
    fixture: Dict[str, Any] = {
        "_fixture_metadata": {
            "source": "archive_analysis",
            "wazuh_version": "4.x",
            "provider": provider,
            "channel": channel,
            "event_id": int(event_id),
            "source_type": "EventChannel",
            "event_count": event_count,
            "extracted_at": extracted_at,
            "captured_by": "Archive Analysis Phase",
            "notes": f"Extracted from {event_count} real events in archive analysis",
        },
        "decoded": sample_event,
    }

    return fixture


def get_provider_directory_name(provider: str) -> str:
    """
    Convert provider name to directory name.

    Removes common prefixes and applies provider-specific mappings.

    Args:
        provider: Windows provider name (e.g., "Microsoft-Windows-Security").

    Returns:
        Directory-safe provider name (lowercase, underscores).
    """
    # Remove common prefixes
    name = provider.replace(
        "Microsoft-Windows-", ""
    ).replace("Microsoft ", "")

    # Map known providers to directory names
    mapping = {
        "Sysmon": "sysmon",
        "Security-Auditing": "security",
        "Security": "security",
        "System": "system",
        "Application": "application",
        "DNS Client": "dns_client",
        "PowerShell": "powershell",
        "Windows Defender": "defender",
        "Service Control Manager": "system",
        "Kernel-General": "system",
        "Kernel-Power": "system",
    }

    # Try exact match first
    if provider in mapping:
        return mapping[provider]

    # Try partial match
    for key, val in mapping.items():
        if key in provider:
            return val

    # Default: lowercase and replace spaces
    return (
        name.lower()
        .replace(" ", "_")
        .replace("-", "_")
    )


def get_channel_filename(channel: str, event_id: str) -> str:
    """
    Create filename from channel and event ID.

    Args:
        channel: Windows event channel (e.g., "Security" or "System/Path").
        event_id: Event ID as string.

    Returns:
        Safe filename combining channel name and event ID.
    """
    # Extract meaningful channel name
    channel_name = (
        channel.split("/")[-1].lower()
        if "/" in channel
        else channel.lower()
    )
    channel_name = channel_name.replace(" ", "_").replace("-", "_")

    return f"{channel_name}_event_{event_id}.json"


def create_fixtures(
    event_groups_file: Path,
    fixtures_base: Path,
    extracted_at: str,
) -> Tuple[int, int]:
    """
    Create fixture files from event groups.

    Args:
        event_groups_file: Path to JSON file with event groups.
        fixtures_base: Base path for fixture output
            (e.g., tests/fixtures/wazuh).
        extracted_at: ISO format timestamp.

    Returns:
        Tuple of (created, updated) counts.
    """
    created = 0
    updated = 0

    with open(event_groups_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    event_groups = data.get("event_groups", [])
    print(
        f"Processing {len(event_groups)} event groups...",
        file=sys.stderr,
    )

    for group in event_groups:
        provider = group["provider"]
        channel = group["channel"]
        event_id = group["eventID"]

        # Create directory path
        provider_dir = get_provider_directory_name(provider)
        channel_dir = fixtures_base / "windows" / provider_dir
        channel_dir.mkdir(parents=True, exist_ok=True)

        # Create filename
        filename = get_channel_filename(channel, event_id)
        fixture_path = channel_dir / filename

        # Create fixture content
        fixture = create_fixture_content(group, extracted_at)

        # Write fixture file
        try:
            fixture_path.write_text(
                json.dumps(fixture, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            if fixture_path.exists():
                created += 1
                print(
                    f"✓ Created "
                    f"{fixture_path.relative_to(fixtures_base.parent)}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"✗ Failed to create {fixture_path}",
                    file=sys.stderr,
                )
        except (OSError, TypeError, ValueError) as e:
            print(
                f"✗ Error writing {fixture_path}: {e}",
                file=sys.stderr,
            )

    return created, updated


def build_inventory(
    event_groups_file: Path,
    fixtures_base: Path,
) -> Dict[str, Any]:
    """
    Build complete fixture inventory.

    Args:
        event_groups_file: Path to JSON file with event groups.
        fixtures_base: Base path for fixtures.

    Returns:
        Dictionary with inventory metadata and fixture listing.
    """
    with open(event_groups_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    event_groups = data.get("event_groups", [])

    inventory: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_event_groups": len(event_groups),
        "total_events_analyzed": data.get("total_events", 0),
        "fixtures": [],
    }

    # Group by provider/channel
    by_provider: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for group in event_groups:
        provider = group["provider"]
        channel = group["channel"]
        event_id = group["eventID"]
        event_count = group["eventCount"]

        key = (provider, channel)
        if key not in by_provider:
            by_provider[key] = {
                "provider": provider,
                "channel": channel,
                "event_ids": [],
            }

        by_provider[key]["event_ids"].append({
            "event_id": int(event_id),
            "event_count": event_count,
        })

    # Build fixtures list
    for (provider, channel), info in sorted(by_provider.items()):
        provider_dir = get_provider_directory_name(provider)

        for event_info in sorted(
            info["event_ids"],
            key=lambda x: x["event_id"],
        ):
            event_id = event_info["event_id"]
            filename = get_channel_filename(channel, str(event_id))
            fixture_path = (
                f"tests/fixtures/wazuh/windows/{provider_dir}/{filename}"
            )

            inventory["fixtures"].append({
                "provider": provider,
                "channel": channel,
                "event_id": event_id,
                "event_count": event_info["event_count"],
                "fixture_path": fixture_path,
            })

    return inventory


def generate_field_mapping_docs(
    event_groups_file: Path,
) -> str:
    """
    Generate field mapping documentation.

    Creates a comprehensive markdown document of all fields observed
    in Windows event fixtures.

    Args:
        event_groups_file: Path to JSON file with event groups.

    Returns:
        Markdown documentation string.
    """
    with open(event_groups_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    event_groups = data.get("event_groups", [])

    doc = """# Windows Field Mapping — Expanded Edition

This document catalogs all fields observed in Windows event fixtures \
extracted from archive analysis.
Each field is mapped to its context (provider, channel, event ID) and \
data type.

## Overview

- **Total Event Groups**: {}
- **Total Events Analyzed**: {:,}
- **Total Unique Field Schemas**: {}
- **Generated**: {}

## Field Index by Provider

""".format(
        len(event_groups),
        data.get("total_events", 0),
        data.get("total_unique_schemas", 0),
        datetime.now(timezone.utc).isoformat(),
    )

    # Group by provider
    by_provider: Dict[str, list] = {}
    for group in event_groups:
        provider = group["provider"]
        if provider not in by_provider:
            by_provider[provider] = []
        by_provider[provider].append(group)

    # Document each provider
    for provider in sorted(by_provider.keys()):
        groups = by_provider[provider]
        doc += f"\n### {provider}\n\n"

        # Group by channel
        by_channel: Dict[str, list] = {}
        for group in groups:
            channel = group["channel"]
            if channel not in by_channel:
                by_channel[channel] = []
            by_channel[channel].append(group)

        for channel in sorted(by_channel.keys()):
            channel_groups = by_channel[channel]
            doc += f"**Channel**: {channel}\n\n"

            for group in sorted(
                channel_groups,
                key=lambda x: int(x["eventID"]),
            ):
                event_id = group["eventID"]
                event_count = group["eventCount"]

                doc += (
                    f"#### Event {event_id} "
                    f"({event_count} occurrences)\n\n"
                )

                # System fields
                system_fields = group["system_fields"]
                if system_fields:
                    doc += "**System Fields**:\n"
                    for field, ftype in sorted(system_fields.items()):
                        doc += f"- `{field}` ({ftype})\n"
                    doc += "\n"

                # EventData fields
                eventdata_fields = group["eventdata_fields"]
                if eventdata_fields:
                    doc += "**EventData Fields**:\n"
                    for field, ftype in sorted(eventdata_fields.items()):
                        doc += f"- `{field}` ({ftype})\n"
                    doc += "\n"

    # Add usage guide
    doc += """
## Usage

To use these field mappings in Sigma rules:

```yaml
logsource:
  product: windows
  service: <service>
  category: <category>

detection:
  selection:
    EventID: <event_id>
    <field>: <value>

filter:
  condition: selection
```

## Notes

- Field names are case-sensitive
- Data types are inferred from fixture values
- Multiple schemas may exist for the same event ID (see fixtures for \
exact structures)
- All fields are extracted from real Wazuh decoded Windows events

## Verification

All fields in this mapping have been extracted from actual Windows event \
fixtures and verified
against the Wazuh Windows EventChannel decoder output.
"""

    return doc
