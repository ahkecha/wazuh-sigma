"""Report rendering for Wazuh rule validation results."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict
from html import escape
from typing import Any, Iterable


def generate_validation_report(file_reports: Iterable[Any], output_format: str = "text") -> str:
    """Render validation results in text, JSON, or HTML format."""
    reports = list(file_reports)
    if output_format == "json":
        return _generate_json_report(reports)
    if output_format == "html":
        return _generate_html_report(reports)
    return _generate_text_report(reports)


def _generate_text_report(file_reports: list[Any]) -> str:
    """Generate a human-readable text report."""
    report = [
        "=" * 80,
        "WAZUH RULE VALIDATION REPORT",
        "=" * 80,
        "",
    ]

    total_files = len(file_reports)
    total_checks = sum(r.total_checks for r in file_reports)
    total_passed = sum(r.passed_checks for r in file_reports)
    total_failed = sum(r.failed_checks for r in file_reports)
    total_warnings = sum(r.warning_checks for r in file_reports)

    report.extend(
        [
            "SUMMARY",
            "-" * 80,
            f"Total files validated:  {total_files}",
            f"Total checks performed: {total_checks}",
            f"Passed: {total_passed} | Failed: {total_failed} | Warnings: {total_warnings}",
            (
                f"Success rate: {(total_passed / total_checks * 100):.1f}%"
                if total_checks > 0
                else "N/A"
            ),
            "",
            "DETAILED RESULTS",
            "-" * 80,
        ]
    )

    for file_report in file_reports:
        report.append(f"\nFile: {file_report.rule_file}")
        report.append(f"Rule ID: {file_report.rule_id}")
        report.append(
            "Checks: "
            f"{file_report.passed_checks} PASS "
            f"{file_report.failed_checks} FAIL "
            f"{file_report.warning_checks} WARN"
        )
        report.append("")

        by_status = defaultdict(list)
        for result in file_report.results:
            by_status[result.status].append(result)

        if by_status.get("FAIL"):
            report.append("  FAILURES:")
            for result in by_status["FAIL"]:
                report.append(f"    FAIL {result.check_name}: {result.message}")
            report.append("")

        if by_status.get("WARN"):
            report.append("  WARNINGS:")
            for result in by_status["WARN"]:
                report.append(f"    WARN {result.check_name}: {result.message}")
            report.append("")

        if by_status.get("PASS"):
            if len(by_status["PASS"]) <= 5:
                report.append("  PASSES:")
                for result in by_status["PASS"]:
                    report.append(f"    PASS {result.check_name}: {result.message}")
            else:
                report.append(f"  PASSES: {len(by_status['PASS'])} checks passed")
            report.append("")

    report.append("=" * 80)
    return "\n".join(report)


def _generate_json_report(file_reports: list[Any]) -> str:
    """Generate a machine-readable JSON validation report."""
    data = {
        "metadata": {
            "total_files": len(file_reports),
            "total_checks": sum(r.total_checks for r in file_reports),
            "passed": sum(r.passed_checks for r in file_reports),
            "failed": sum(r.failed_checks for r in file_reports),
            "warnings": sum(r.warning_checks for r in file_reports),
        },
        "results": [],
    }

    for file_report in file_reports:
        data["results"].append(
            {
                "file": file_report.rule_file,
                "rule_id": file_report.rule_id,
                "summary": {
                    "total": file_report.total_checks,
                    "passed": file_report.passed_checks,
                    "failed": file_report.failed_checks,
                    "warnings": file_report.warning_checks,
                },
                "results": [asdict(result) for result in file_report.results],
            }
        )

    return json.dumps(data, indent=2)


def _generate_html_report(file_reports: list[Any]) -> str:
    """Generate an HTML validation report."""
    html = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<title>Wazuh Rule Validation Report</title>",
        "<style>",
        """
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #333; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: white; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .file-result { background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #ddd; }
        .pass { color: green; }
        .fail { color: red; font-weight: bold; }
        .warn { color: orange; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        """,
        "</style>",
        "</head>",
        "<body>",
        "<div class='header'>",
        "<h1>Wazuh Rule Validation Report</h1>",
        "</div>",
    ]

    total_checks = sum(r.total_checks for r in file_reports)
    total_passed = sum(r.passed_checks for r in file_reports)
    total_failed = sum(r.failed_checks for r in file_reports)
    total_warnings = sum(r.warning_checks for r in file_reports)

    html.extend(
        [
            "<div class='summary'>",
            "<h2>Summary</h2>",
            f"<p><strong>Total Files:</strong> {len(file_reports)}</p>",
            f"<p><strong>Total Checks:</strong> {total_checks}</p>",
            f"<p class='pass'><strong>Passed:</strong> {total_passed}</p>",
            f"<p class='fail'><strong>Failed:</strong> {total_failed}</p>",
            f"<p class='warn'><strong>Warnings:</strong> {total_warnings}</p>",
            "</div>",
        ]
    )

    for file_report in file_reports:
        html.extend(
            [
                "<div class='file-result'>",
                f"<h3>{escape(str(file_report.rule_file))}</h3>",
                f"<p><strong>Rule ID:</strong> {escape(str(file_report.rule_id))}</p>",
                "<table>",
                "<tr><th>Check</th><th>Status</th><th>Message</th></tr>",
            ]
        )

        for result in file_report.results:
            status_class = escape(str(result.status).lower(), quote=True)
            html.extend(
                [
                    "<tr>",
                    f"<td>{escape(str(result.check_name))}</td>",
                    f"<td class='{status_class}'>{escape(str(result.status))}</td>",
                    f"<td>{escape(str(result.message))}</td>",
                    "</tr>",
                ]
            )

        html.extend(["</table>", "</div>"])

    html.extend(["</body>", "</html>"])
    return "\n".join(html)
