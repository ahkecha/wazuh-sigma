"""Data contracts produced by Wazuh rule validation."""

from __future__ import annotations

from dataclasses import dataclass
from os import PathLike


@dataclass
class ValidationResult:
    """Result of a single Wazuh rule validation check."""

    check_name: str
    status: str
    message: str
    rule_id: str = ""
    severity: str = "INFO"


@dataclass
class RuleValidationReport:
    """Validation summary for one Wazuh rule file."""

    rule_file: str
    rule_id: str
    results: list[ValidationResult]
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warning_checks: int = 0


def build_validation_report(
    rule_file: str,
    rule_id: str,
    results: list[ValidationResult],
) -> RuleValidationReport:
    """Build a validation report with counters matching its results."""
    return RuleValidationReport(
        rule_file=str(rule_file),
        rule_id=rule_id,
        results=results,
        total_checks=len(results),
        passed_checks=sum(1 for result in results if result.status == "PASS"),
        failed_checks=sum(1 for result in results if result.status == "FAIL"),
        warning_checks=sum(1 for result in results if result.status == "WARN"),
    )


def build_no_rule_files_report(rules_path: str | PathLike) -> RuleValidationReport:
    """Build a failed report for an input path with no XML rule files."""
    result = ValidationResult(
        check_name="rule_file_discovery",
        status="FAIL",
        message=f"No XML rule files found in {rules_path}",
        severity="CRITICAL",
    )
    return build_validation_report(str(rules_path), "UNKNOWN", [result])
