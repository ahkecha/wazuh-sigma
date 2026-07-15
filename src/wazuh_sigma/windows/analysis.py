"""
Windows Event Inventory Analyzer.

Parse local JSON files, extract data.win events, group by provider/channel/eventID,
deduplicate by schema, and generate structured inventory.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Set, Tuple


def get_field_type(value: Any) -> str:
    """
    Determine the data type of a value.

    Args:
        value: The value to analyze.

    Returns:
        A string representation of the value's type.
    """
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return "bool"
    elif isinstance(value, int):
        return "int"
    elif isinstance(value, float):
        return "float"
    elif isinstance(value, str):
        return "string"
    elif isinstance(value, list):
        if value:
            # Check if all items are same type
            item_types: Set[str] = {get_field_type(item) for item in value}
            if len(item_types) == 1:
                return f"array[{item_types.pop()}]"
            else:
                return "array[mixed]"
        return "array[empty]"
    elif isinstance(value, dict):
        return "object"
    else:
        return "unknown"


def analyze_field_structure(data: Dict[str, Any]) -> Dict[str, str]:
    """
    Analyze structure of fields in a dictionary.

    Args:
        data: Dictionary to analyze.

    Returns:
        Dictionary mapping field names to their types.
    """
    structure: Dict[str, str] = {}
    for key, value in data.items():
        structure[key] = get_field_type(value)
    return structure


def schema_hash(structure: Dict[str, str]) -> str:
    """
    Create a hash of field structure for deduplication.

    Args:
        structure: Dictionary of field name -> type mappings.

    Returns:
        MD5 hash of the structure.
    """
    sorted_items = sorted(structure.items())
    content = json.dumps(sorted_items, sort_keys=True)
    return hashlib.md5(content.encode()).hexdigest()


def parse_json_files(directory: Path) -> List[Dict[str, Any]]:
    """
    Parse all JSON files in directory and extract events.

    Expects files to contain Elasticsearch response format with hits/hits array.
    Extracts data.win events from _source field.

    Args:
        directory: Path to directory containing JSON files.

    Returns:
        List of Windows event dictionaries.
    """
    events: List[Dict[str, Any]] = []
    json_files = sorted(directory.glob("*.json"))

    print(
        f"Found {len(json_files)} JSON files in {directory}",
        file=sys.stderr,
    )

    for json_file in json_files:
        print(f"Processing {json_file.name}...", file=sys.stderr)
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Extract hits from Elasticsearch response
            if isinstance(data, dict) and "hits" in data:
                hits = data["hits"].get("hits", [])
                for hit in hits:
                    source = hit.get("_source", {})
                    win_data = source.get("data", {}).get("win")
                    if win_data:
                        events.append(win_data)

            extracted_count = 0
            if isinstance(data, dict):
                extracted_count = len(data.get("hits", {}).get("hits", []))
            print(
                f"  Extracted {extracted_count} events from {json_file.name}",
                file=sys.stderr,
            )
        except (OSError, json.JSONDecodeError, TypeError) as e:
            print(
                f"Error processing {json_file}: {e}",
                file=sys.stderr,
            )

    print(f"Total events extracted: {len(events)}", file=sys.stderr)
    return events


def group_and_deduplicate(
    events: List[Dict[str, Any]],
) -> Dict[Tuple[str, str, str], List[Dict[str, Any]]]:
    """
    Group events by (provider, channel, eventID) and track schemas.

    Returns dict mapping (provider, channel, eventID) to list of events
    with their schema information.

    Args:
        events: List of Windows event dictionaries.

    Returns:
        Dictionary mapping (provider, channel, eventID) tuple to list of
        event objects with schema metadata.
    """
    grouped: DefaultDict[
        Tuple[str, str, str], List[Dict[str, Any]]
    ] = defaultdict(list)

    for event in events:
        system = event.get("system", {})
        provider = system.get("providerName", "UNKNOWN")
        channel = system.get("channel", "UNKNOWN")
        event_id = system.get("eventID", "UNKNOWN")

        # Create a schema signature for this event
        eventdata = event.get("eventdata", {})
        eventdata_structure = analyze_field_structure(eventdata)
        system_structure = analyze_field_structure(system)

        key: Tuple[str, str, str] = (provider, channel, event_id)

        event_with_schema: Dict[str, Any] = {
            "event": event,
            "system_structure": system_structure,
            "eventdata_structure": eventdata_structure,
            "schema_hash": (
                schema_hash(system_structure),
                schema_hash(eventdata_structure),
            ),
        }

        grouped[key].append(event_with_schema)

    return grouped


def deduplicate_by_schema(
    events_with_schema: List[Dict[str, Any]],
) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    """
    Deduplicate events by schema within a group.

    Returns dict mapping schema_hash_tuple to list of actual events.

    Args:
        events_with_schema: List of event objects with schema metadata.

    Returns:
        Dictionary mapping schema hash tuple to list of events.
    """
    by_schema: DefaultDict[
        Tuple[str, str], List[Dict[str, Any]]
    ] = defaultdict(list)
    for item in events_with_schema:
        schema_key: Tuple[str, str] = item["schema_hash"]
        by_schema[schema_key].append(item["event"])

    return by_schema


def build_inventory(
    grouped_events: Dict[Tuple[str, str, str], List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """
    Build final inventory with event counts and field analysis.

    Args:
        grouped_events: Dictionary of grouped events from
            group_and_deduplicate().

    Returns:
        List of inventory items, sorted by event count then by provider.
    """
    inventory: List[Dict[str, Any]] = []

    for (provider, channel, event_id), events_with_schema in sorted(
        grouped_events.items()
    ):
        # Deduplicate by schema
        by_schema = deduplicate_by_schema(events_with_schema)

        for schema_key, actual_events in by_schema.items():
            # Get representative event for this schema
            sample_event = actual_events[0]
            system = sample_event.get("system", {})
            eventdata = sample_event.get("eventdata", {})

            system_structure = analyze_field_structure(system)
            eventdata_structure = analyze_field_structure(eventdata)

            inventory_item: Dict[str, Any] = {
                "provider": provider,
                "channel": channel,
                "eventID": event_id,
                "eventCount": len(actual_events),
                "system_fields": system_structure,
                "eventdata_fields": eventdata_structure,
                "sample_event": {
                    "system": system,
                    "eventdata": eventdata,
                },
            }

            inventory.append(inventory_item)

    # Sort by event count (descending) then by provider/channel/eventID
    inventory.sort(
        key=lambda x: (-x["eventCount"], x["provider"], x["channel"],
                       x["eventID"])
    )

    return inventory
