"""Presentation helpers for the Sigma conversion CLI."""

from __future__ import annotations

from typing import Any, Mapping


def format_conversion_summary(report: Mapping[str, Any], output_file: str) -> str:
    """Return the human-readable conversion summary printed by ``sigma-convert``."""
    lines = [
        "",
        "=" * 60,
        "CONVERSION SUMMARY",
        "=" * 60,
        f"Total Rules Converted: {report['total_converted']}",
        f"Total Errors: {report['total_errors']}",
        f"Output File: {output_file}",
        "=" * 60,
    ]

    if report.get("errors"):
        lines.extend(["", "ERRORS:"])
        lines.extend(f"  - {error}" for error in report["errors"])

    return "\n".join(lines)
