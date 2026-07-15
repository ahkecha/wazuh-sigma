#!/usr/bin/env python3
"""
Comprehensive Wazuh Rule Validation Script

Validates Wazuh rules for:
1. XML well-formedness and schema compliance
2. Rule ID uniqueness and format
3. Required fields presence
4. Regex pattern validity
5. Decoder/ruleset references
6. Performance implications (pattern complexity)
7. Testing against sample logs
"""

import sys
import logging
from pathlib import Path
from xml.etree import ElementTree as ET

from wazuh_sigma.validator import catalog
from wazuh_sigma.validator.discovery import discover_rule_files
from wazuh_sigma.validator.models import (
    RuleValidationReport,
    ValidationResult,
    build_no_rule_files_report,
    build_validation_report,
)
from wazuh_sigma.validator.pattern_checks import (
    analyze_performance,
    test_rule_against_samples,
    validate_regex_patterns,
    validate_single_regex,
)
from wazuh_sigma.validator.reference_checks import (
    extract_reference_metadata,
    validate_decoder_reference,
    validate_group_reference,
)
from wazuh_sigma.validator.reporting import generate_validation_report
from wazuh_sigma.validator.structure_checks import (
    validate_level_range,
    validate_numeric_fields,
    validate_required_fields,
    validate_rule_id,
    validate_xml_wellformedness,
)

logger = logging.getLogger(__name__)

XML_READ_ERRORS = (ET.ParseError, OSError, UnicodeError, LookupError)


class WazuhRuleValidator:
    """Main validator class for Wazuh rules"""

    REQUIRED_FIELDS = catalog.REQUIRED_FIELDS
    NUMERIC_FIELDS = catalog.NUMERIC_FIELDS
    VALID_LEVELS = catalog.VALID_LEVELS
    RULE_ID_PATTERN = catalog.RULE_ID_PATTERN
    MAX_REGEX_LENGTH = catalog.MAX_REGEX_LENGTH
    MAX_ALTERNATION_DEPTH = catalog.MAX_ALTERNATION_DEPTH
    MAX_BACKREFERENCES = catalog.MAX_BACKREFERENCES
    COMMON_DECODERS = catalog.COMMON_DECODERS
    COMMON_RULESETS = catalog.COMMON_RULESETS

    def __init__(
        self,
        rules_path: str | Path,
        strict_mode: bool = False,
        test_samples: list[str] | None = None,
    ):
        """
        Initialize the validator

        Args:
            rules_path: Path to rules directory or file
            strict_mode: If True, warnings are treated as failures
            test_samples: List of sample log lines to test rules against
        """
        self.rules_path = Path(rules_path)
        self.strict_mode = strict_mode
        self.test_samples = test_samples or []
        self.all_results: list[RuleValidationReport] = []
        self.rule_ids: dict[str, str] = {}
        self.decoders: set[str] = set()
        self.group_names: set[str] = set()

    def validate_all(self) -> list[RuleValidationReport]:
        """Validate all rules in the specified path"""
        logger.info(f"Starting validation of rules in {self.rules_path}")

        rule_files = self._get_rule_files()

        if not rule_files:
            logger.error(f"No rule files found in {self.rules_path}")
            report = self._no_rule_files_report()
            self.all_results.append(report)
            return self.all_results

        logger.info(f"Found {len(rule_files)} rule file(s) to validate")

        # First pass: collect metadata
        for rule_file in rule_files:
            self._extract_metadata(rule_file)

        # Second pass: validate rules
        for rule_file in rule_files:
            try:
                report = self.validate_rule_file(rule_file)
                self.all_results.append(report)
            except XML_READ_ERRORS as e:
                logger.error(f"Error validating {rule_file}: {str(e)}")
                result = ValidationResult(
                    check_name="file_parsing",
                    status="FAIL",
                    message=f"Failed to parse rule file: {str(e)}",
                    severity="CRITICAL"
                )
                self.all_results.append(self._build_report(str(rule_file), "UNKNOWN", [result]))

        return self.all_results

    def _no_rule_files_report(self) -> RuleValidationReport:
        """Return a failed report when the target path contains no XML rule files."""
        return build_no_rule_files_report(self.rules_path)

    def validate_rule_file(self, rule_file: Path) -> RuleValidationReport:
        """Validate a single rule file"""
        logger.info(f"Validating rule file: {rule_file}")

        results = []

        # 1. XML Well-formedness
        xml_valid, xml_root = self._validate_xml_wellformedness(rule_file)
        results.append(ValidationResult(
            check_name="xml_wellformedness",
            status="PASS" if xml_valid else "FAIL",
            message="XML is well-formed" if xml_valid else "XML parsing failed",
            severity="CRITICAL" if not xml_valid else "INFO"
        ))

        if not xml_valid or xml_root is None:
            return self._build_report(str(rule_file), "UNKNOWN", results)

        # Extract rule elements
        rule_elements = xml_root.findall('.//rule')
        if not rule_elements:
            results.append(ValidationResult(
                check_name="rule_existence",
                status="FAIL",
                message="No rule elements found in XML",
                severity="CRITICAL"
            ))
            return self._build_report(str(rule_file), "UNKNOWN", results)

        # Validate each rule
        rule_ids = []
        for rule_elem in rule_elements:
            rule_results = self._validate_rule_element(rule_elem, str(rule_file))
            results.extend(rule_results)

            rule_id_attr = rule_elem.get('id')
            if rule_id_attr:
                rule_ids.append(rule_id_attr)

        # Determine primary rule ID for report
        if rule_ids:
            rule_id = rule_ids[0] if len(rule_ids) == 1 else f"Multiple ({len(rule_ids)})"
        else:
            rule_id = "UNKNOWN"

        return self._build_report(str(rule_file), rule_id, results)

    @staticmethod
    def _build_report(
        rule_file: str,
        rule_id: str,
        results: list[ValidationResult],
    ) -> RuleValidationReport:
        """Build a validation report with counters matching its result list."""
        return build_validation_report(rule_file, rule_id, results)

    def _validate_rule_element(
        self,
        rule_elem: ET.Element,
        file_path: str,
    ) -> list[ValidationResult]:
        """Validate individual rule element"""
        results = []

        rule_id = rule_elem.get('id', 'UNKNOWN')
        level_str = rule_elem.get('level', None)

        id_check = self._validate_rule_id(rule_id, file_path)
        id_check.rule_id = rule_id
        results.append(id_check)

        results.extend(validate_required_fields(rule_elem, rule_id, level_str))
        results.extend(validate_numeric_fields(rule_elem, rule_id))
        results.extend(validate_level_range(level_str, rule_id))

        # 4. Regex pattern validation
        regex_checks = self._validate_regex_patterns(rule_elem, rule_id)
        results.extend(regex_checks)

        # 5. Decoder/ruleset reference validation
        decoder_check = self._validate_decoder_reference(rule_elem, rule_id)
        if decoder_check:
            results.append(decoder_check)

        group_check = self._validate_group_reference(rule_elem, rule_id)
        if group_check:
            results.append(group_check)

        # 6. Performance analysis
        perf_checks = self._analyze_performance(rule_elem, rule_id)
        results.extend(perf_checks)

        # 7. Test against sample logs
        if self.test_samples:
            test_results = self._test_rule_against_samples(rule_elem, rule_id)
            results.extend(test_results)

        return results

    def _validate_xml_wellformedness(self, rule_file: Path) -> tuple[bool, ET.Element | None]:
        """Validate XML well-formedness"""
        return validate_xml_wellformedness(rule_file)

    def _validate_rule_id(self, rule_id: str, file_path: str) -> ValidationResult:
        """Validate rule ID format and uniqueness"""
        return validate_rule_id(rule_id, file_path, self.rule_ids)

    def _validate_regex_patterns(
        self,
        rule_elem: ET.Element,
        rule_id: str,
    ) -> list[ValidationResult]:
        """Validate all regex patterns in the rule"""
        return validate_regex_patterns(rule_elem, rule_id)

    def _validate_single_regex(self, pattern: str, element_type: str,
                               rule_id: str) -> ValidationResult:
        """Validate a single regex pattern"""
        return validate_single_regex(pattern, element_type, rule_id)

    def _validate_decoder_reference(
        self,
        rule_elem: ET.Element,
        rule_id: str,
    ) -> ValidationResult | None:
        """Validate decoder references"""
        return validate_decoder_reference(rule_elem, rule_id, self.decoders)

    def _validate_group_reference(
        self,
        rule_elem: ET.Element,
        rule_id: str,
    ) -> ValidationResult | None:
        """Validate group references"""
        return validate_group_reference(rule_elem, rule_id, self.group_names)

    def _analyze_performance(
        self,
        rule_elem: ET.Element,
        rule_id: str,
    ) -> list[ValidationResult]:
        """Analyze rule performance implications"""
        return analyze_performance(rule_elem, rule_id)

    def _test_rule_against_samples(
        self,
        rule_elem: ET.Element,
        rule_id: str,
    ) -> list[ValidationResult]:
        """Test rule against sample log lines"""
        return test_rule_against_samples(rule_elem, rule_id, self.test_samples)

    def _extract_metadata(self, rule_file: Path) -> None:
        """Extract metadata from rule file for cross-file validation"""
        extract_reference_metadata(
            rule_file,
            decoders=self.decoders,
            group_names=self.group_names,
        )

    def _get_rule_files(self) -> list[Path]:
        """Get all XML rule files from the specified path"""
        return discover_rule_files(self.rules_path)

    def generate_report(self, output_format: str = "text") -> str:
        """Generate validation report in specified format"""
        return generate_validation_report(self.all_results, output_format)

    def _generate_text_report(self) -> str:
        """Generate human-readable text report"""
        return generate_validation_report(self.all_results, "text")

    def _generate_json_report(self) -> str:
        """Generate JSON report"""
        return generate_validation_report(self.all_results, "json")

    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        return generate_validation_report(self.all_results, "html")


def validation_exit_code(reports: list[RuleValidationReport], *, strict_mode: bool = False) -> int:
    """Return the validation process exit code for a collection of reports."""

    if not reports:
        return 1
    total_failed = sum(report.failed_checks for report in reports)
    total_warnings = sum(report.warning_checks for report in reports)
    if total_failed > 0:
        return 1
    if strict_mode and total_warnings > 0:
        return 1
    return 0


def build_parser():
    """Compatibility wrapper for the validator CLI parser."""

    from wazuh_sigma.validator.cli import build_parser as _build_parser

    return _build_parser()


def load_sample_logs(samples_file: str | Path) -> list[str]:
    """Compatibility wrapper for loading CLI sample logs."""

    from wazuh_sigma.validator.cli import load_sample_logs as _load_sample_logs

    return _load_sample_logs(samples_file)


def setup_logging(verbose: bool = False) -> None:
    """Compatibility wrapper for CLI logging setup."""

    from wazuh_sigma.validator.cli import setup_logging as _setup_logging

    _setup_logging(verbose)


def main(argv: list[str] | None = None) -> int:
    """Compatibility wrapper for the validator CLI entrypoint."""

    from wazuh_sigma.validator.cli import main as _main

    return _main(argv)


if __name__ == "__main__":
    sys.exit(main())
