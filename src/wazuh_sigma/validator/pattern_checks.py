"""Regex, performance, and sample-log checks for Wazuh rules."""

from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from wazuh_sigma.validator import catalog
from wazuh_sigma.validator.models import ValidationResult


def validate_regex_patterns(rule_elem: ET.Element, rule_id: str) -> list[ValidationResult]:
    """Validate regular expressions declared by a Wazuh rule element."""
    results: list[ValidationResult] = []

    for elem_name in ("match", "regex", "pcre"):
        for elem in rule_elem.findall(f".//{elem_name}"):
            if elem.text:
                results.append(validate_single_regex(elem.text, elem_name, rule_id))

    for elem in rule_elem.findall(".//field"):
        if elem.text and elem.get("type", "").lower() in {"pcre", "pcre2", "regex"}:
            results.append(validate_single_regex(elem.text, "field", rule_id))

    if not results:
        results.append(ValidationResult(
            check_name="regex_patterns",
            status="PASS",
            message="No regex patterns found or all patterns are valid",
            rule_id=rule_id,
        ))

    return results


def validate_single_regex(
    pattern: str,
    element_type: str,
    rule_id: str,
) -> ValidationResult:
    """Validate one Wazuh regex-like pattern."""
    if len(pattern) > catalog.MAX_REGEX_LENGTH:
        return ValidationResult(
            check_name=f"regex_complexity_{element_type}",
            status="WARN",
            message=(
                f"{element_type} pattern exceeds {catalog.MAX_REGEX_LENGTH} "
                f"chars (length: {len(pattern)})"
            ),
            rule_id=rule_id,
            severity="WARNING",
        )

    alternation_count = pattern.count("|")
    if alternation_count > catalog.MAX_ALTERNATION_DEPTH:
        return ValidationResult(
            check_name=f"regex_alternation_{element_type}",
            status="WARN",
            message=(
                f"{element_type} has {alternation_count} alternations "
                f"(threshold: {catalog.MAX_ALTERNATION_DEPTH})"
            ),
            rule_id=rule_id,
            severity="WARNING",
        )

    backrefs = len(re.findall(r"\\[1-9]", pattern))
    if backrefs > catalog.MAX_BACKREFERENCES:
        return ValidationResult(
            check_name=f"regex_backreferences_{element_type}",
            status="WARN",
            message=f"{element_type} has {backrefs} backreferences",
            rule_id=rule_id,
            severity="WARNING",
        )

    try:
        re.compile(pattern)
        return ValidationResult(
            check_name=f"regex_validity_{element_type}",
            status="PASS",
            message=f"{element_type} pattern is valid",
            rule_id=rule_id,
        )
    except re.error as error:
        return ValidationResult(
            check_name=f"regex_validity_{element_type}",
            status="FAIL",
            message=f"{element_type} pattern is invalid: {str(error)}",
            rule_id=rule_id,
            severity="ERROR",
        )


def analyze_performance(rule_elem: ET.Element, rule_id: str) -> list[ValidationResult]:
    """Analyze simple performance implications for regex-heavy Wazuh rules."""
    results: list[ValidationResult] = []
    expensive_patterns = [
        (r"^\^", "start anchor", "moderate"),
        (r"\$^", "end anchor", "moderate"),
        (r".*.*", "greedy nested quantifiers", "high"),
        (r"(.+)+", "nested quantifiers", "high"),
        (r"(?:.*){5,}", "complex repetition", "high"),
    ]

    for elem in rule_elem.findall(".//regex"):
        if elem.text:
            for pattern, name, cost in expensive_patterns:
                if re.search(pattern, elem.text):
                    results.append(ValidationResult(
                        check_name="performance_pattern",
                        status="WARN",
                        message=f"Regex contains {name} pattern (performance cost: {cost})",
                        rule_id=rule_id,
                        severity="WARNING",
                    ))

    match_elem = rule_elem.find(".//match")
    if match_elem is not None and match_elem.text and len(match_elem.text) > 20:
        results.append(ValidationResult(
            check_name="performance_specificity",
            status="PASS",
            message="Rule has good specificity (long match pattern)",
            rule_id=rule_id,
        ))

    if not results:
        results.append(ValidationResult(
            check_name="performance_analysis",
            status="PASS",
            message="No obvious performance issues detected",
            rule_id=rule_id,
        ))

    return results


def test_rule_against_samples(
    rule_elem: ET.Element,
    rule_id: str,
    test_samples: list[str],
) -> list[ValidationResult]:
    """Test a Wazuh rule's simple patterns against sample log lines."""
    results: list[ValidationResult] = []
    patterns: dict[str, str] = {}
    for pattern_type in ("match", "regex", "pcre"):
        elem = rule_elem.find(pattern_type)
        if elem is not None and elem.text:
            patterns[pattern_type] = elem.text

    if not patterns:
        return results

    matches_found = 0
    invalid_sample_patterns: set[tuple[str, str]] = set()
    for sample in test_samples:
        for pattern_type, pattern in patterns.items():
            pattern_key = (pattern_type, pattern)
            if pattern_key in invalid_sample_patterns:
                continue
            try:
                if pattern_type in {"regex", "pcre"}:
                    if re.search(pattern, sample):
                        matches_found += 1
                elif pattern in sample:
                    matches_found += 1
            except re.error as error:
                invalid_sample_patterns.add(pattern_key)
                results.append(ValidationResult(
                    check_name="sample_testing_regex",
                    status="FAIL",
                    message=(
                        f"Cannot test {pattern_type} pattern against samples: "
                        f"{error}"
                    ),
                    rule_id=rule_id,
                    severity="ERROR",
                ))
                break

    if any(result.status == "FAIL" for result in results):
        return results

    if matches_found > 0:
        results.append(ValidationResult(
            check_name="sample_testing",
            status="PASS",
            message=f"Rule matched {matches_found} sample log line(s)",
            rule_id=rule_id,
        ))
    else:
        results.append(ValidationResult(
            check_name="sample_testing",
            status="WARN",
            message="Rule did not match any sample log lines",
            rule_id=rule_id,
            severity="WARNING",
        ))

    return results
