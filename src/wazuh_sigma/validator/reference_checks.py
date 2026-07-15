"""Decoder, group, and metadata reference checks for Wazuh rules."""

from __future__ import annotations

import logging
from pathlib import Path
from xml.etree import ElementTree as ET

from wazuh_sigma.validator import catalog
from wazuh_sigma.validator.models import ValidationResult


logger = logging.getLogger(__name__)
REFERENCE_READ_ERRORS = (ET.ParseError, OSError, UnicodeError, LookupError)


def validate_decoder_reference(
    rule_elem: ET.Element,
    rule_id: str,
    known_decoders: set[str],
) -> ValidationResult | None:
    """Validate a Wazuh rule decoder reference against built-in and discovered names."""
    decoder_elem = rule_elem.find("decoder")
    if decoder_elem is None or not decoder_elem.text:
        return None

    decoder_name = decoder_elem.text
    if decoder_name not in catalog.COMMON_DECODERS and decoder_name not in known_decoders:
        return ValidationResult(
            check_name="decoder_reference",
            status="WARN",
            message=f"Decoder '{decoder_name}' not found in known decoders",
            rule_id=rule_id,
            severity="WARNING",
        )

    return ValidationResult(
        check_name="decoder_reference",
        status="PASS",
        message=f"Decoder '{decoder_name}' exists",
        rule_id=rule_id,
    )


def validate_group_reference(
    rule_elem: ET.Element,
    rule_id: str,
    known_groups: set[str],
) -> ValidationResult | None:
    """Validate Wazuh rule groups against built-in and discovered group names."""
    group_elem = rule_elem.find("group")
    if group_elem is None or not group_elem.text:
        return None

    groups = group_elem.text.split(",")
    for group in groups:
        group = group.strip()
        if group not in catalog.COMMON_RULESETS and group not in known_groups:
            return ValidationResult(
                check_name="group_reference",
                status="WARN",
                message=f"Group '{group}' not found in known groups",
                rule_id=rule_id,
                severity="WARNING",
            )

    return ValidationResult(
        check_name="group_reference",
        status="PASS",
        message=f"Groups '{group_elem.text}' verified",
        rule_id=rule_id,
    )


def extract_reference_metadata(
    rule_file: Path,
    *,
    decoders: set[str],
    group_names: set[str],
) -> None:
    """Collect decoder and group names declared in a Wazuh rule file."""
    try:
        root = ET.parse(rule_file).getroot()
    except REFERENCE_READ_ERRORS as error:
        logger.debug("Could not extract metadata from %s: %s", rule_file, error)
        return

    for rule_elem in root.findall(".//rule"):
        group_elem = rule_elem.find("group")
        if group_elem is not None and group_elem.text:
            for group in group_elem.text.split(","):
                group_names.add(group.strip())

        decoder_elem = rule_elem.find("decoder")
        if decoder_elem is not None and decoder_elem.text:
            decoders.add(decoder_elem.text)
