"""XML, rule-id, and required-field checks for Wazuh rules."""

from __future__ import annotations

import logging
from pathlib import Path
from xml.etree import ElementTree as ET

from wazuh_sigma.validator import catalog
from wazuh_sigma.validator.models import ValidationResult


logger = logging.getLogger(__name__)


def validate_xml_wellformedness(rule_file: Path) -> tuple[bool, ET.Element | None]:
    """Return whether a Wazuh rule XML file parses successfully."""
    try:
        tree = ET.parse(rule_file)
        return True, tree.getroot()
    except ET.ParseError as error:
        logger.error("XML Parse Error in %s: %s", rule_file, error)
        return False, None
    except (OSError, UnicodeError) as error:
        logger.error("Error reading %s: %s", rule_file, error)
        return False, None


def validate_rule_id(
    rule_id: str,
    file_path: str,
    seen_rule_ids: dict[str, str],
) -> ValidationResult:
    """Validate Wazuh rule ID format and cross-file uniqueness."""
    if not rule_id or rule_id == "UNKNOWN":
        return ValidationResult(
            check_name="rule_id_format",
            status="FAIL",
            message="Rule ID is missing or empty",
            rule_id=rule_id,
            severity="CRITICAL",
        )

    if not catalog.RULE_ID_PATTERN.match(rule_id):
        return ValidationResult(
            check_name="rule_id_format",
            status="FAIL",
            message=f"Rule ID '{rule_id}' must be 1-7 digits",
            rule_id=rule_id,
            severity="ERROR",
        )

    if rule_id in seen_rule_ids:
        return ValidationResult(
            check_name="rule_id_uniqueness",
            status="FAIL",
            message=(
                f"Rule ID '{rule_id}' is duplicated "
                f"(first seen in {seen_rule_ids[rule_id]}, duplicated in {file_path})"
            ),
            rule_id=rule_id,
            severity="CRITICAL",
        )

    seen_rule_ids[rule_id] = file_path
    return ValidationResult(
        check_name="rule_id_format",
        status="PASS",
        message=f"Rule ID '{rule_id}' is valid and unique in {file_path}",
        rule_id=rule_id,
    )


def validate_required_fields(
    rule_elem: ET.Element,
    rule_id: str,
    level: str | None,
) -> list[ValidationResult]:
    """Validate required Wazuh rule attributes and child fields."""
    results: list[ValidationResult] = []
    for field in catalog.REQUIRED_FIELDS:
        if field == "id":
            results.append(_required_attribute_result(field, rule_id, rule_id and rule_id != "UNKNOWN"))
        elif field == "level":
            results.append(_required_attribute_result(field, rule_id, bool(level)))
        else:
            field_elem = rule_elem.find(field)
            present = field_elem is not None and (field_elem.text is not None or bool(field_elem.attrib))
            results.append(_required_attribute_result(field, rule_id, present))
    return results


def _required_attribute_result(field: str, rule_id: str, present: bool) -> ValidationResult:
    return ValidationResult(
        check_name=f"required_field_{field}",
        status="PASS" if present else "FAIL",
        message=f"Required field '{field}' is {'present' if present else 'missing'}",
        rule_id=rule_id,
        severity="INFO" if present else "CRITICAL",
    )


def validate_numeric_fields(rule_elem: ET.Element, rule_id: str) -> list[ValidationResult]:
    """Validate numeric Wazuh rule attributes and child elements."""
    results: list[ValidationResult] = []
    for field in catalog.NUMERIC_FIELDS:
        value = rule_elem.get(field)
        if not value:
            field_elem = rule_elem.find(field)
            value = field_elem.text if field_elem is not None else None

        if value and not value.isdigit():
            results.append(ValidationResult(
                check_name=f"numeric_field_{field}",
                status="FAIL",
                message=f"Field '{field}' must be numeric, got: {value}",
                rule_id=rule_id,
                severity="ERROR",
            ))
    return results


def validate_level_range(level: str | None, rule_id: str) -> list[ValidationResult]:
    """Validate Wazuh rule severity level range."""
    if not level:
        return []

    try:
        parsed_level = int(level)
    except ValueError:
        return []

    if parsed_level not in catalog.VALID_LEVELS:
        return [ValidationResult(
            check_name="level_range",
            status="FAIL",
            message=f"Level {parsed_level} is out of valid range (0-16)",
            rule_id=rule_id,
            severity="ERROR",
        )]

    return [ValidationResult(
        check_name="level_range",
        status="PASS",
        message=f"Level {parsed_level} is valid",
        rule_id=rule_id,
    )]
