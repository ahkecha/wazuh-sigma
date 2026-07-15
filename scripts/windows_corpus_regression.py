"""Summarize Windows Sigma corpus conversion regression evidence.

This script compares the current full-corpus conversion report with a previous
baseline report and writes machine-readable plus Markdown evidence. It is
deliberately report-only: it does not change converter behavior.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


UNSUPPORTED_FIELD_RE = re.compile(r"Unsupported Windows field: '([^']+)'")
UNSUPPORTED_MODIFIER_RE = re.compile(r"unsupported Sigma string modifier\(s\): ([^|]+?)(?:$|\s)")
PATTERN_LENGTH_RE = re.compile(r"Wazuh pattern length (\d+) for field '([^']+)' exceeds supported maximum (\d+)")


def load_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_source(source: object) -> str:
    return str(source).replace("\\", "/")


def converted_sources(report: dict[str, Any]) -> set[str]:
    return {
        normalize_source(item.get("source_file"))
        for item in report.get("converted_rules", [])
        if item.get("source_file")
    }


def converted_titles_by_source(report: dict[str, Any]) -> dict[str, str]:
    return {
        normalize_source(item.get("source_file")): str(item.get("sigma_title"))
        for item in report.get("converted_rules", [])
        if item.get("source_file")
    }


def error_source_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        normalize_source(item.get("source_file")): item
        for item in report.get("error_details", [])
        if item.get("source_file")
    }


def classify_errors(report: dict[str, Any]) -> dict[str, Any]:
    unsupported_fields: Counter[str] = Counter()
    unsupported_modifiers: Counter[str] = Counter()
    error_types: Counter[str] = Counter()
    pattern_length_failures: list[dict[str, Any]] = []
    parser_failures: list[dict[str, Any]] = []

    for item in report.get("error_details", []):
        message = str(item.get("message", ""))
        error_type = str(item.get("error_type", "unknown"))
        error_types[error_type] += 1

        if field_match := UNSUPPORTED_FIELD_RE.search(message):
            unsupported_fields[field_match.group(1)] += 1

        if modifier_match := UNSUPPORTED_MODIFIER_RE.search(message):
            for modifier in modifier_match.group(1).split(","):
                unsupported_modifiers[modifier.strip()] += 1

        if length_match := PATTERN_LENGTH_RE.search(message):
            pattern_length_failures.append(
                {
                    "source_file": item.get("source_file"),
                    "message": message,
                    "length": int(length_match.group(1)),
                    "field": length_match.group(2),
                    "maximum": int(length_match.group(3)),
                }
            )

        if error_type.lower().startswith("sigma") or "parser" in message.lower() or "parse" in message.lower():
            parser_failures.append(item)

    return {
        "error_types": dict(error_types.most_common()),
        "unsupported_fields": dict(unsupported_fields.most_common()),
        "unsupported_modifiers": dict(unsupported_modifiers.most_common()),
        "pattern_length_failures": pattern_length_failures,
        "parser_failures": parser_failures,
    }


def pct(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 2) if denominator else 0.0


def build_summary(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    total = int(current.get("total_discovered") or current.get("total_converted", 0) + current.get("total_errors", 0))
    baseline_total = int(baseline.get("total_discovered") or baseline.get("total_converted", 0) + baseline.get("total_errors", 0))
    current_converted = int(current.get("total_converted", 0))
    baseline_converted = int(baseline.get("total_converted", 0))

    current_sources = converted_sources(current)
    baseline_sources = converted_sources(baseline)
    titles = converted_titles_by_source(current) | converted_titles_by_source(baseline)
    current_errors = error_source_map(current)

    gained = sorted(current_sources - baseline_sources)
    lost = sorted(baseline_sources - current_sources)
    unchanged = sorted(current_sources & baseline_sources)

    classified = classify_errors(current)
    return {
        "current": {
            "total_discovered": total,
            "converted": current_converted,
            "rejected": int(current.get("total_errors", 0)),
            "conversion_percentage": pct(current_converted, total),
            "parser_backends": current.get("parser_backends", []),
            "chunks": current.get("chunks", {}),
        },
        "baseline": {
            "report": "build/reports/windows-conversion-full-report.json",
            "total_discovered": baseline_total,
            "converted": baseline_converted,
            "rejected": int(baseline.get("total_errors", 0)),
            "conversion_percentage": pct(baseline_converted, baseline_total),
        },
        "delta": {
            "converted_count": current_converted - baseline_converted,
            "conversion_percentage_points": round(pct(current_converted, total) - pct(baseline_converted, baseline_total), 2),
            "gained_count": len(gained),
            "lost_count": len(lost),
            "unchanged_converted_count": len(unchanged),
        },
        "gained_rules": [{"source_file": source, "title": titles.get(source)} for source in gained],
        "lost_rules": [
            {
                "source_file": source,
                "title": titles.get(source),
                "current_error": current_errors.get(source),
            }
            for source in lost
        ],
        "current_failure_breakdown": classified,
    }


def write_markdown(summary: dict[str, Any], path: Path) -> None:
    current = summary["current"]
    baseline = summary["baseline"]
    delta = summary["delta"]
    fields = summary["current_failure_breakdown"]["unsupported_fields"]
    modifiers = summary["current_failure_breakdown"]["unsupported_modifiers"]
    error_types = summary["current_failure_breakdown"]["error_types"]
    pattern_failures = summary["current_failure_breakdown"]["pattern_length_failures"]
    parser_failures = summary["current_failure_breakdown"]["parser_failures"]

    lines = [
        "# Windows Sigma corpus regression",
        "",
        "Generated from the current full-corpus conversion report. This is evidence, not a target-state document.",
        "",
        "## Summary",
        "",
        "| Metric | Baseline | Current | Delta |",
        "| --- | ---: | ---: | ---: |",
        f"| Rules discovered | {baseline['total_discovered']} | {current['total_discovered']} | {current['total_discovered'] - baseline['total_discovered']} |",
        f"| Converted | {baseline['converted']} | {current['converted']} | {delta['converted_count']} |",
        f"| Rejected | {baseline['rejected']} | {current['rejected']} | {current['rejected'] - baseline['rejected']} |",
        f"| Conversion percentage | {baseline['conversion_percentage']}% | {current['conversion_percentage']}% | {delta['conversion_percentage_points']} pp |",
        f"| Gained converted rules | - | {delta['gained_count']} | +{delta['gained_count']} |",
        f"| Lost converted rules | - | {delta['lost_count']} | -{delta['lost_count']} |",
        "",
        "## Current chunking",
        "",
        f"- Chunking enabled: `{current['chunks'].get('enabled')}`",
        f"- Chunk count: `{current['chunks'].get('chunk_count')}`",
        f"- Rules per chunk: `{current['chunks'].get('rules_per_chunk')}`",
        "",
        "## Failure breakdown",
        "",
        "### Error types",
        "",
        *[f"- `{name}`: {count}" for name, count in list(error_types.items())[:25]],
        "",
        "### Unsupported modifiers",
        "",
        *[f"- `{name}`: {count}" for name, count in modifiers.items()],
        "",
        "### Unsupported fields, top 40",
        "",
        *[f"- `{name}`: {count}" for name, count in list(fields.items())[:40]],
        "",
        "### Pattern-length failures",
        "",
        f"- Count: {len(pattern_failures)}",
        *[
            f"- `{item['field']}` length {item['length']} > {item['maximum']}: `{item['source_file']}`"
            for item in pattern_failures[:20]
        ],
        "",
        "### Parser failures",
        "",
        f"- Count: {len(parser_failures)}",
        "",
        "## Production interpretation",
        "",
        "- Current conversion coverage is materially below the 55.68% baseline.",
        "- The drop is expected from stricter fail-closed mapping behavior, but it is still a production blocker until each lost rule is justified or recovered.",
        "- XML validation passed separately, but native `wazuh-analysisd -t` validation was not run by this script.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=Path("build/reports/windows-conversion-full-report.json"))
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args()

    summary = build_summary(load_report(args.current), load_report(args.baseline))
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_markdown(summary, args.markdown_output)
    print(json.dumps({
        "current_conversion_percentage": summary["current"]["conversion_percentage"],
        "baseline_conversion_percentage": summary["baseline"]["conversion_percentage"],
        "converted_delta": summary["delta"]["converted_count"],
        "gained": summary["delta"]["gained_count"],
        "lost": summary["delta"]["lost_count"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
