"""Audit Windows field mappings removed during cleanup.

The cleanup report removed 40 mappings. This script reconciles each removal
against:

* the previous evidence classification report;
* exact paths present in fixture JSON files;
* current SigmaHQ Windows corpus field usage;
* the current mapping table.

It intentionally does not restore mappings. It produces evidence for a
maintainer decision.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from wazuh_sigma.fields.windows import WINDOWS_FIELD_MAPPINGS


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def flatten_paths(value: Any, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            paths.add(path)
            paths.update(flatten_paths(child, path))
    elif isinstance(value, list):
        for child in value[:25]:
            paths.update(flatten_paths(child, prefix))
    return paths


def previous_mapping_index(classification: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for bucket, items in classification.get("mappings_by_classification", {}).items():
        for item in items:
            sigma_field = item.get("sigma_field")
            if not sigma_field:
                continue
            index[str(sigma_field)] = {
                "previous_bucket": bucket,
                "previous_wazuh_field": item.get("wazuh_field"),
                "previous_confidence": item.get("confidence"),
                "previous_verification_source": item.get("verification_source"),
                "previous_fixture_evidence": item.get("fixture_evidence", []),
                "previous_found_in_fixture": item.get("found_in_fixture"),
            }
    return index


def scan_fixture_paths(fixtures_dir: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    for path in fixtures_dir.rglob("*.json"):
        try:
            payload = load_json(path)
        except json.JSONDecodeError:
            continue
        for flattened in flatten_paths(payload):
            result[flattened].append(path.as_posix())
    return {key: sorted(set(paths)) for key, paths in result.items()}


def scan_sigma_usage(sigma_dir: Path, fields: list[str]) -> dict[str, list[str]]:
    usage: dict[str, list[str]] = {field: [] for field in fields}
    patterns = {
        field: re.compile(rf"(?m)^\s*{re.escape(field)}(?:\|[^:]+)?\s*:")
        for field in fields
    }
    for path in sigma_dir.rglob("*.yml"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for field, pattern in patterns.items():
            if pattern.search(text):
                usage[field].append(path.as_posix())
    for path in sigma_dir.rglob("*.yaml"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for field, pattern in patterns.items():
            if pattern.search(text):
                usage[field].append(path.as_posix())
    return {field: sorted(set(paths)) for field, paths in usage.items()}


def fixture_paths_for_wazuh_field(fixture_paths: dict[str, list[str]], wazuh_field: str | None) -> list[str]:
    if not wazuh_field:
        return []
    matched: set[str] = set()
    suffix = "." + wazuh_field
    decoded_equivalent = None
    if wazuh_field.startswith("win.eventdata."):
        decoded_equivalent = "decoded.eventdata." + wazuh_field.rsplit(".", 1)[-1]
    elif wazuh_field.startswith("win.system."):
        decoded_equivalent = "decoded.system." + wazuh_field.rsplit(".", 1)[-1]
    decoded_suffix = "." + decoded_equivalent if decoded_equivalent else None
    for path, files in fixture_paths.items():
        if (
            path == wazuh_field
            or path.endswith(suffix)
            or (decoded_equivalent and path == decoded_equivalent)
            or (decoded_suffix and path.endswith(decoded_suffix))
        ):
            matched.update(files)
    return sorted(matched)


def current_mapping_fields() -> set[str]:
    return {mapping.sigma_field for mapping in WINDOWS_FIELD_MAPPINGS}


def classify(record: dict[str, Any]) -> str:
    if record["currently_mapped"]:
        return "restored_or_present"
    if record["fixture_path_count"] and record["sigma_usage_count"]:
        return "needs_review_fixture_and_sigma_usage"
    if record["fixture_path_count"]:
        return "needs_review_fixture_only"
    if record["sigma_usage_count"]:
        return "needs_review_sigma_usage_only"
    return "removal_probably_justified_no_current_evidence"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cleanup", type=Path, default=Path("build/reports/windows-mapping-cleanup.json"))
    parser.add_argument("--previous-evidence", type=Path, default=Path("build/reports/windows_mapping_evidence_classification.json"))
    parser.add_argument("--fixtures-dir", type=Path, default=Path("tests/fixtures"))
    parser.add_argument("--sigma-dir", type=Path, default=Path("sigma/rules/windows"))
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args()

    removed_fields = load_json(args.cleanup).get("fields_removed", [])
    previous = previous_mapping_index(load_json(args.previous_evidence))
    fixture_paths = scan_fixture_paths(args.fixtures_dir)
    sigma_usage = scan_sigma_usage(args.sigma_dir, removed_fields)
    current = current_mapping_fields()

    records = []
    for field in removed_fields:
        previous_info = previous.get(field, {})
        wazuh_field = previous_info.get("previous_wazuh_field")
        exact_fixture_paths = fixture_paths_for_wazuh_field(fixture_paths, str(wazuh_field) if wazuh_field else None)
        record = {
            "sigma_field": field,
            "previous_wazuh_field": wazuh_field,
            "previous_bucket": previous_info.get("previous_bucket"),
            "previous_confidence": previous_info.get("previous_confidence"),
            "previous_verification_source": previous_info.get("previous_verification_source"),
            "previous_found_in_fixture": previous_info.get("previous_found_in_fixture"),
            "previous_fixture_evidence": previous_info.get("previous_fixture_evidence", []),
            "currently_mapped": field in current,
            "fixture_path_count": len(exact_fixture_paths),
            "fixture_paths": exact_fixture_paths[:25],
            "sigma_usage_count": len(sigma_usage.get(field, [])),
            "sigma_usage_files": sigma_usage.get(field, [])[:25],
        }
        record["decision"] = classify(record)
        records.append(record)

    summary_counts: dict[str, int] = defaultdict(int)
    for record in records:
        summary_counts[record["decision"]] += 1

    payload = {
        "summary": {
            "removed_fields": len(removed_fields),
            "decision_counts": dict(sorted(summary_counts.items())),
            "currently_mapped_count": sum(1 for item in records if item["currently_mapped"]),
            "fixture_evidenced_count": sum(1 for item in records if item["fixture_path_count"]),
            "sigma_used_count": sum(1 for item in records if item["sigma_usage_count"]),
        },
        "records": records,
    }
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Removed Windows mapping audit",
        "",
        "This reconciles the 40 mappings removed in `build/reports/windows-mapping-cleanup.json` against previous evidence, fixture paths, and current Sigma usage.",
        "",
        "## Summary",
        "",
        f"- Removed fields audited: {payload['summary']['removed_fields']}",
        f"- Currently mapped again: {payload['summary']['currently_mapped_count']}",
        f"- Exact fixture-path evidence: {payload['summary']['fixture_evidenced_count']}",
        f"- Current Sigma corpus usage: {payload['summary']['sigma_used_count']}",
        "",
        "### Decision counts",
        "",
        *[f"- `{name}`: {count}" for name, count in payload["summary"]["decision_counts"].items()],
        "",
        "## Fields requiring review",
        "",
    ]
    for record in records:
        if record["decision"] == "removal_probably_justified_no_current_evidence":
            continue
        lines.extend(
            [
                f"### `{record['sigma_field']}`",
                "",
                f"- Previous Wazuh field: `{record['previous_wazuh_field']}`",
                f"- Previous bucket/source: `{record['previous_bucket']}` / `{record['previous_verification_source']}`",
                f"- Decision: `{record['decision']}`",
                f"- Exact fixture paths: {record['fixture_path_count']}",
                f"- Sigma usage files: {record['sigma_usage_count']}",
                "",
            ]
        )
        for fixture_path in record["fixture_paths"][:5]:
            lines.append(f"  - fixture: `{fixture_path}`")
        for sigma_path in record["sigma_usage_files"][:5]:
            lines.append(f"  - sigma: `{sigma_path}`")
        lines.append("")
    args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
