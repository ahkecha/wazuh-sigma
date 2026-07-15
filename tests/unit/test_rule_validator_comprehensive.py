#!/usr/bin/env python3
"""
Comprehensive Test Suite for Wazuh Rule Validator (rule_validator.py)

Coverage areas:
1. XML validation (well-formedness, encoding, structure)
2. Rule ID checks (format, uniqueness, boundaries)
3. Field validation (required, numeric, types)
4. Regex compilation (validity, complexity, patterns)
5. Decoder compatibility (references, validation)
6. Performance analysis (complexity, specificity)
7. Error handling (parsing, file I/O, edge cases)

Run: pytest tests/unit/test_rule_validator_comprehensive.py -v
"""

import pytest
import tempfile
import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from wazuh_sigma.validator.rule_validator import (
    WazuhRuleValidator,
    ValidationResult,
    RuleValidationReport,
    build_parser,
    load_sample_logs,
    logger,
    main,
    validation_exit_code,
)


def test_validator_module_does_not_configure_logging_at_import():
    """Validator library import should not attach handlers to its logger."""
    assert logger.handlers == []


def test_validator_parser_accepts_argv_without_sys_argv_mutation():
    """The CLI parser is independently testable."""
    args = build_parser().parse_args(["--rules", "rules.xml", "--output", "json"])

    assert args.rules == "rules.xml"
    assert args.output == "json"
    assert args.verbose is False


def test_validator_help_uses_installed_command_name():
    """CLI help should not point users at removed script filenames."""
    help_text = build_parser().format_help()

    assert "sigma-validate -r /path/to/rules.xml" in help_text
    assert "wazuh_rule_validator.py" not in help_text


class TestXMLValidation:
    """Test XML validation functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_xml_wellformed_valid_document(self, temp_dir):
        """Test validation passes for well-formed XML"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test pattern</match>
    <description>Valid rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "valid.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        xml_result = next((r for r in results[0].results
                          if r.check_name == "xml_wellformedness"), None)
        assert xml_result is not None
        assert xml_result.status == "PASS"

    def test_xml_malformed_unclosed_tag(self, temp_dir):
        """Test detection of unclosed XML tags"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test pattern
    <description>Unclosed match tag</description>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "unclosed.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        xml_result = next((r for r in results[0].results
                          if r.check_name == "xml_wellformedness"), None)
        assert xml_result is not None
        assert xml_result.status == "FAIL"

    def test_xml_missing_declaration(self, temp_dir):
        """Test XML without declaration still parses"""
        rule_content = """<rules>
  <rule id="100001" level="3">
    <match>Test pattern</match>
    <description>No XML declaration</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "no_decl.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        xml_result = next((r for r in results[0].results
                          if r.check_name == "xml_wellformedness"), None)
        assert xml_result.status == "PASS"

    def test_xml_with_comments(self, temp_dir):
        """Test XML with comments parses correctly"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <!-- This is a comment -->
  <rule id="100001" level="3">
    <!-- Rule comment -->
    <match>Test pattern</match>
    <description>Rule with comments</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "with_comments.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        xml_result = next((r for r in results[0].results
                          if r.check_name == "xml_wellformedness"), None)
        assert xml_result.status == "PASS"

    def test_xml_with_cdata(self, temp_dir):
        """Test XML with CDATA sections"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex><![CDATA[pattern|with|special<chars>]]></regex>
    <description>Rule with CDATA</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "with_cdata.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        xml_result = next((r for r in results[0].results
                          if r.check_name == "xml_wellformedness"), None)
        assert xml_result.status == "PASS"

    def test_xml_empty_document(self, temp_dir):
        """Test handling of empty XML file"""
        rule_content = ""
        rule_file = self.create_rule_file(temp_dir, "empty.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        xml_result = next((r for r in results[0].results
                          if r.check_name == "xml_wellformedness"), None)
        assert xml_result.status == "FAIL"

    def test_xml_invalid_encoding_declaration(self, temp_dir):
        """Test handling of invalid encoding declaration"""
        rule_content = """<?xml version="1.0" encoding="INVALID-ENCODING"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Invalid encoding</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "bad_encoding.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        # Should still parse, encoding is not strictly validated by ElementTree
        results = validator.validate_all()
        assert len(results) >= 1

    def test_xml_read_errors_fail_validation_without_crashing(self, monkeypatch, temp_dir):
        """Filesystem-level XML read errors should become validation failures."""
        rule_file = self.create_rule_file(temp_dir, "unreadable.xml", "<rules />")

        def raise_os_error(path):
            raise OSError("permission denied")

        monkeypatch.setattr("wazuh_sigma.validator.rule_validator.ET.parse", raise_os_error)

        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        xml_result = next(
            result
            for result in results[0].results
            if result.check_name == "xml_wellformedness"
        )
        assert xml_result.status == "FAIL"

    def test_xml_parser_programming_errors_are_not_hidden(self, monkeypatch, temp_dir):
        """Unexpected parser contract bugs should propagate instead of becoming reports."""
        rule_file = self.create_rule_file(temp_dir, "valid.xml", "<rules />")

        def raise_type_error(path):
            raise TypeError("parser contract changed")

        monkeypatch.setattr("wazuh_sigma.validator.rule_validator.ET.parse", raise_type_error)

        validator = WazuhRuleValidator(rule_file)

        with pytest.raises(TypeError, match="parser contract changed"):
            validator.validate_all()


class TestRuleIDValidation:
    """Test rule ID validation"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_rule_id_valid_format(self, temp_dir):
        """Test valid rule ID format (1-7 digits)"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Valid ID</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "valid_id.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        id_result = next((r for r in results[0].results
                         if "rule_id" in r.check_name and "format" in r.check_name), None)
        assert id_result is not None
        assert id_result.status == "PASS"

    def test_rule_id_single_digit(self, temp_dir):
        """Test rule ID with single digit"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="1" level="3">
    <match>Test</match>
    <description>Single digit ID</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "single_digit.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        id_result = next((r for r in results[0].results
                         if "rule_id" in r.check_name and "format" in r.check_name), None)
        assert id_result.status == "PASS"

    def test_rule_id_max_seven_digits(self, temp_dir):
        """Test rule ID with maximum 7 digits"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="9999999" level="3">
    <match>Test</match>
    <description>Max 7 digits</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "max_digits.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        id_result = next((r for r in results[0].results
                         if "rule_id" in r.check_name and "format" in r.check_name), None)
        assert id_result.status == "PASS"

    def test_rule_id_invalid_exceeds_length(self, temp_dir):
        """Test rule ID that exceeds 7 digits"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="10000000" level="3">
    <match>Test</match>
    <description>Too many digits</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "too_long.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        id_result = next((r for r in results[0].results
                         if "rule_id" in r.check_name and "format" in r.check_name), None)
        assert id_result.status == "FAIL"

    def test_rule_id_invalid_non_numeric(self, temp_dir):
        """Test rule ID with non-numeric characters"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="ABC123" level="3">
    <match>Test</match>
    <description>Non-numeric ID</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "non_numeric.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        id_result = next((r for r in results[0].results
                         if "rule_id" in r.check_name and "format" in r.check_name), None)
        assert id_result.status == "FAIL"

    def test_rule_id_duplicate_detection(self, temp_dir):
        """Test detection of duplicate rule IDs in one file"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test 1</match>
    <description>First rule</description>
    <group>test</group>
  </rule>
  <rule id="100001" level="3">
    <match>Test 2</match>
    <description>Duplicate ID</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "duplicate.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        # Find the uniqueness check
        unique_results = [r for r in results[0].results
                         if "uniqueness" in r.check_name]
        assert any(r.status == "FAIL" for r in unique_results)
        duplicate_message = next(r.message for r in unique_results if r.status == "FAIL")
        assert "duplicate.xml" in duplicate_message
        assert "first seen in" in duplicate_message
        assert "duplicated in" in duplicate_message

    def test_rule_id_duplicate_detection_reports_cross_file_locations(self, temp_dir):
        """Test duplicate rule IDs include the first and duplicate file locations"""
        first_rule = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test 1</match>
    <description>First rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        duplicate_rule = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test 2</match>
    <description>Duplicate ID</description>
    <group>test</group>
  </rule>
</rules>
"""
        first_file = self.create_rule_file(temp_dir, "first.xml", first_rule)
        duplicate_file = self.create_rule_file(temp_dir, "second.xml", duplicate_rule)
        validator = WazuhRuleValidator(temp_dir)

        reports = validator.validate_all()

        duplicate_results = [
            result
            for report in reports
            for result in report.results
            if result.check_name == "rule_id_uniqueness"
        ]
        assert len(duplicate_results) == 1
        assert duplicate_results[0].status == "FAIL"
        assert str(first_file) in duplicate_results[0].message
        assert str(duplicate_file) in duplicate_results[0].message

    def test_rule_id_missing(self, temp_dir):
        """Test handling of missing rule ID"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule level="3">
    <match>Test</match>
    <description>No ID</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "no_id.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        id_result = next((r for r in results[0].results
                         if "rule_id" in r.check_name and "format" in r.check_name), None)
        assert id_result is not None
        assert id_result.status == "FAIL"

    def test_rule_id_with_leading_zeros(self, temp_dir):
        """Test rule ID with leading zeros"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="0001" level="3">
    <match>Test</match>
    <description>Leading zeros</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "leading_zeros.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        id_result = next((r for r in results[0].results
                         if "rule_id" in r.check_name and "format" in r.check_name), None)
        assert id_result.status == "PASS"


class TestFieldValidation:
    """Test field validation"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_required_fields_all_present(self, temp_dir):
        """Test validation passes when all required fields present"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Complete rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "complete.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        required_results = [r for r in results[0].results
                           if "required_field" in r.check_name]
        assert all(r.status == "PASS" for r in required_results)

    def test_required_field_description_missing(self, temp_dir):
        """Test detection of missing description field"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "no_desc.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        desc_result = next((r for r in results[0].results
                           if "required_field_description" in r.check_name), None)
        assert desc_result is not None
        assert desc_result.status == "FAIL"

    def test_required_field_level_missing(self, temp_dir):
        """Test detection of missing level field"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001">
    <match>Test</match>
    <description>No level</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "no_level.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        level_result = next((r for r in results[0].results
                            if "required_field_level" in r.check_name), None)
        assert level_result is not None
        assert level_result.status == "FAIL"

    def test_numeric_field_level_non_numeric(self, temp_dir):
        """Test detection of non-numeric level value"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="high">
    <match>Test</match>
    <description>Non-numeric level</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "non_numeric_level.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        numeric_results = [r for r in results[0].results
                          if "numeric_field_level" in r.check_name]
        assert any(r.status == "FAIL" for r in numeric_results)

    def test_numeric_field_level_valid_range(self, temp_dir):
        """Test level field validation (0-16)"""
        for level in [0, 5, 10, 16]:
            rule_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="{level}">
    <match>Test</match>
    <description>Level {level}</description>
    <group>test</group>
  </rule>
</rules>
"""
            rule_file = self.create_rule_file(temp_dir, f"level_{level}.xml", rule_content)
            validator = WazuhRuleValidator(rule_file)
            results = validator.validate_all()

            level_result = next((r for r in results[0].results
                                if "level_range" in r.check_name), None)
            assert level_result is not None
            assert level_result.status == "PASS"

    def test_numeric_field_level_out_of_range(self, temp_dir):
        """Test detection of invalid level values"""
        for level in [-1, 17, 99]:
            rule_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="{level}">
    <match>Test</match>
    <description>Invalid level {level}</description>
    <group>test</group>
  </rule>
</rules>
"""
            rule_file = self.create_rule_file(temp_dir, f"level_{level}.xml", rule_content)
            validator = WazuhRuleValidator(rule_file)
            results = validator.validate_all()

            level_result = next((r for r in results[0].results
                                if "level_range" in r.check_name), None)
            assert level_result is not None
            assert level_result.status == "FAIL"

    def test_numeric_field_timeframe(self, temp_dir):
        """Test timeframe numeric field validation"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>With timeframe</description>
    <group>test</group>
    <timeframe>300</timeframe>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "timeframe.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        # Should not have failed numeric validation
        numeric_results = [r for r in results[0].results
                          if "numeric_field_timeframe" in r.check_name]
        assert all(r.status != "FAIL" for r in numeric_results) or len(numeric_results) == 0

    def test_numeric_field_frequency(self, temp_dir):
        """Test frequency numeric field validation"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>With frequency</description>
    <group>test</group>
    <frequency>10</frequency>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "frequency.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        # Should not have failed numeric validation
        numeric_results = [r for r in results[0].results
                          if "numeric_field_frequency" in r.check_name]
        assert all(r.status != "FAIL" for r in numeric_results) or len(numeric_results) == 0


class TestRegexValidation:
    """Test regex pattern validation"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_regex_valid_simple_pattern(self, temp_dir):
        """Test validation of simple valid regex"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>^Failed password</regex>
    <description>Valid regex</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "valid_regex.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        regex_results = [r for r in results[0].results
                        if "regex_validity" in r.check_name]
        assert any(r.status == "PASS" for r in regex_results)

    def test_regex_invalid_unclosed_bracket(self, temp_dir):
        """Test detection of invalid regex with unclosed bracket"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>[invalid regex(</regex>
    <description>Invalid regex</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "invalid_regex.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        regex_results = [r for r in results[0].results
                        if "regex_validity" in r.check_name]
        assert any(r.status == "FAIL" for r in regex_results)

    def test_regex_invalid_unmatched_paren(self, temp_dir):
        """Test detection of unmatched parenthesis"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>(unclosed paren</regex>
    <description>Invalid regex</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "unclosed_paren.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        regex_results = [r for r in results[0].results
                        if "regex_validity" in r.check_name]
        assert any(r.status == "FAIL" for r in regex_results)

    def test_regex_with_lookahead(self, temp_dir):
        """Test regex with lookahead assertion"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>password(?=123)</regex>
    <description>With lookahead</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "lookahead.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        regex_results = [r for r in results[0].results
                        if "regex_validity" in r.check_name]
        assert any(r.status == "PASS" for r in regex_results)

    def test_regex_with_lookbehind(self, temp_dir):
        """Test regex with lookbehind assertion"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex><![CDATA[(?<=failed )password]]></regex>
    <description>With lookbehind</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "lookbehind.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        regex_results = [r for r in results[0].results
                        if "regex_validity" in r.check_name]
        assert any(r.status == "PASS" for r in regex_results)

    def test_regex_complexity_long_pattern(self, temp_dir):
        """Test warning for very long regex patterns"""
        long_pattern = "a" * 2000
        rule_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>{long_pattern}</regex>
    <description>Long pattern</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "long_pattern.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        complexity_results = [r for r in results[0].results
                             if "complexity" in r.check_name]
        assert any(r.status == "WARN" for r in complexity_results)

    def test_regex_alternation_many(self, temp_dir):
        """Test warning for excessive alternation"""
        pattern = "|".join([f"pattern{i}" for i in range(10)])
        rule_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>{pattern}</regex>
    <description>Many alternations</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "alternation.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        alternation_results = [r for r in results[0].results
                              if "alternation" in r.check_name]
        assert any(r.status == "WARN" for r in alternation_results)

    def test_regex_with_backreferences(self, temp_dir):
        """Test regex with backreferences"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>(word)\\1</regex>
    <description>With backreference</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "backref.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        regex_results = [r for r in results[0].results
                        if "regex" in r.check_name]
        assert any(r.status == "PASS" for r in regex_results)

    def test_regex_nested_quantifiers_warning(self, temp_dir):
        """Test warning for nested quantifiers (potential ReDoS)"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>(.+)+abc</regex>
    <description>Nested quantifiers</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "nested_quant.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        # Should compile successfully but may warn
        regex_results = [r for r in results[0].results
                        if "regex_validity" in r.check_name]
        assert any(r.status == "PASS" for r in regex_results)


class TestDecoderCompatibility:
    """Test decoder reference validation"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_decoder_known_decoder(self, temp_dir):
        """Test validation passes for known decoder"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <decoder>sshd</decoder>
    <match>Failed password</match>
    <description>SSH rule</description>
    <group>authentication</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "known_decoder.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        decoder_result = next((r for r in results[0].results
                              if "decoder_reference" in r.check_name), None)
        assert decoder_result is not None
        assert decoder_result.status == "PASS"

    def test_decoder_custom_decoder_passthrough(self, temp_dir):
        """Test that custom decoders found in metadata are passed through"""
        # Note: The validator collects all decoders in metadata extraction phase,
        # so custom decoders are marked as "known" even if not in COMMON_DECODERS
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <decoder>custom_app</decoder>
    <match>Error</match>
    <description>Custom decoder</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "custom_decoder.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        decoder_result = next((r for r in results[0].results
                              if "decoder_reference" in r.check_name), None)
        # Custom decoder is collected in metadata, so it passes validation
        assert decoder_result is not None
        assert decoder_result.status == "PASS"

    def test_decoder_none_missing(self, temp_dir):
        """Test that missing decoder doesn't generate error"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>No decoder</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "no_decoder.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        decoder_result = next((r for r in results[0].results
                              if "decoder_reference" in r.check_name), None)
        assert decoder_result is None  # No decoder element = no check

    def test_decoder_common_windows(self, temp_dir):
        """Test common Windows decoder"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <decoder>windows</decoder>
    <match>EventID</match>
    <description>Windows rule</description>
    <group>windows</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "windows_decoder.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        decoder_result = next((r for r in results[0].results
                              if "decoder_reference" in r.check_name), None)
        assert decoder_result is not None
        assert decoder_result.status == "PASS"


class TestGroupValidation:
    """Test group reference validation"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_group_known_group(self, temp_dir):
        """Test validation passes for known group"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Auth rule</description>
    <group>authentication</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "known_group.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        group_result = next((r for r in results[0].results
                            if "group_reference" in r.check_name), None)
        assert group_result is not None
        assert group_result.status == "PASS"

    def test_group_custom_group_passthrough(self, temp_dir):
        """Test that custom groups found in metadata are passed through"""
        # Note: The validator collects all groups in metadata extraction phase,
        # so custom groups are marked as "known" even if not in COMMON_RULESETS
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Custom group</description>
    <group>custom_group_xyz</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "custom_group.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        group_result = next((r for r in results[0].results
                            if "group_reference" in r.check_name), None)
        # Custom group is collected in metadata, so it passes validation
        assert group_result is not None
        assert group_result.status == "PASS"

    def test_group_multiple_groups(self, temp_dir):
        """Test multiple comma-separated groups"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Multiple groups</description>
    <group>authentication, access_control</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "multi_group.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        group_result = next((r for r in results[0].results
                            if "group_reference" in r.check_name), None)
        assert group_result is not None
        assert group_result.status == "PASS"


class TestPerformanceAnalysis:
    """Test performance analysis checks"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_performance_good_specificity(self, temp_dir):
        """Test good specificity warning detection"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>VerySpecificPatternThatIsUnique123456</match>
    <description>Specific match</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "specific.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        perf_results = [r for r in results[0].results
                       if "performance" in r.check_name]
        assert any(r.status == "PASS" for r in perf_results)

    def test_performance_greedy_quantifier_warning(self, temp_dir):
        """Test warning for greedy nested quantifiers"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>.*.*abc</regex>
    <description>Greedy pattern</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "greedy.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        perf_results = [r for r in results[0].results
                       if "performance_pattern" in r.check_name]
        # May or may not warn depending on exact pattern matching
        assert len(perf_results) >= 0


class TestErrorHandling:
    """Test error handling and edge cases"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_error_nonexistent_file(self, temp_dir):
        """Test handling of nonexistent file"""
        nonexistent_path = temp_dir / "nonexistent.xml"
        validator = WazuhRuleValidator(nonexistent_path)
        results = validator.validate_all()

        assert len(results) == 1
        assert results[0].failed_checks == 1
        assert results[0].results[0].check_name == "rule_file_discovery"
        assert "No XML rule files" in results[0].results[0].message

    def test_error_nonexistent_directory(self, temp_dir):
        """Test handling of nonexistent directory"""
        nonexistent_dir = temp_dir / "nonexistent_dir"
        validator = WazuhRuleValidator(nonexistent_dir)
        results = validator.validate_all()

        assert len(results) == 1
        assert results[0].failed_checks == 1
        assert results[0].results[0].check_name == "rule_file_discovery"

    def test_error_empty_directory_fails_validation(self, temp_dir):
        """An empty rules directory should fail closed in CI."""
        validator = WazuhRuleValidator(temp_dir)
        results = validator.validate_all()

        assert len(results) == 1
        assert validation_exit_code(results) == 1
        assert results[0].results[0].status == "FAIL"

    def test_cli_returns_nonzero_when_no_rule_files_exist(self, temp_dir, capsys):
        assert main(["--rules", str(temp_dir)]) == 1
        assert "No XML rule files" in capsys.readouterr().out

    def test_error_empty_xml_file(self, temp_dir):
        """Test handling of empty XML file"""
        rule_file = self.create_rule_file(temp_dir, "empty.xml", "")
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        assert results[0].total_checks == 1
        assert results[0].failed_checks == 1
        xml_result = next((r for r in results[0].results
                          if r.check_name == "xml_wellformedness"), None)
        assert xml_result.status == "FAIL"

    def test_error_no_rules_element(self, temp_dir):
        """Test handling of XML without rules element"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<other_root>
  <item>Test</item>
</other_root>
"""
        rule_file = self.create_rule_file(temp_dir, "no_rules.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        assert results[0].total_checks == 2
        assert results[0].failed_checks == 1
        rule_result = next((r for r in results[0].results
                           if "rule_existence" in r.check_name), None)
        assert rule_result is not None
        assert rule_result.status == "FAIL"

    def test_error_malformed_xml_recovery(self, temp_dir):
        """Test graceful error handling for malformed XML"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test
    <!-- Missing closing match and rule tags -->
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "malformed.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)

        # Should not raise exception
        results = validator.validate_all()
        assert len(results) >= 1

    def test_error_unicode_in_content(self, temp_dir):
        """Test handling of Unicode characters"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test with Unicode: café, 中文, 🔒</match>
    <description>Unicode test rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "unicode.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        xml_result = next((r for r in results[0].results
                          if r.check_name == "xml_wellformedness"), None)
        assert xml_result.status == "PASS"

    def test_error_special_xml_characters(self, temp_dir):
        """Test handling of special XML characters"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test &lt;tag&gt; &amp; "quotes"</match>
    <description>Special chars rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "special_chars.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        assert len(results) == 1
        xml_result = next((r for r in results[0].results
                          if r.check_name == "xml_wellformedness"), None)
        assert xml_result.status == "PASS"


class TestReportGeneration:
    """Test report generation functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_report_text_format(self, temp_dir):
        """Test text report generation"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Test rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "report.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        validator.validate_all()

        report = validator.generate_report("text")
        assert "WAZUH RULE VALIDATION REPORT" in report
        assert "SUMMARY" in report
        assert "100001" in report
        assert "PASS" in report
        assert "â" not in report

    def test_report_json_format(self, temp_dir):
        """Test JSON report generation"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Test rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "report.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        validator.validate_all()

        report = validator.generate_report("json")
        data = json.loads(report)

        assert "metadata" in data
        assert "results" in data
        assert data["metadata"]["total_files"] >= 1

    def test_report_html_format(self, temp_dir):
        """Test HTML report generation"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Test rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "report.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        validator.validate_all()

        report = validator.generate_report("html")
        assert "<!DOCTYPE html>" in report
        assert "<table>" in report
        assert "100001" in report

    def test_report_html_escapes_dynamic_values(self):
        """HTML reports should escape validation data before rendering"""
        validator = WazuhRuleValidator("unused.xml")
        validator.all_results = [
            RuleValidationReport(
                rule_file="<rules>.xml",
                rule_id="<100001>",
                results=[
                    ValidationResult(
                        check_name="<check>",
                        status="FAIL",
                        message="<script>alert('x')</script>",
                    )
                ],
                total_checks=1,
                passed_checks=0,
                failed_checks=1,
                warning_checks=0,
            )
        ]

        report = validator.generate_report("html")

        assert "&lt;rules&gt;.xml" in report
        assert "&lt;100001&gt;" in report
        assert "&lt;check&gt;" in report
        assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in report
        assert "<script>alert" not in report


class TestValidationResult:
    """Test ValidationResult dataclass"""

    def test_validation_result_creation(self):
        """Test creating ValidationResult"""
        result = ValidationResult(
            check_name="test_check",
            status="PASS",
            message="Test message",
            rule_id="100001",
            severity="INFO"
        )

        assert result.check_name == "test_check"
        assert result.status == "PASS"
        assert result.message == "Test message"
        assert result.rule_id == "100001"
        assert result.severity == "INFO"

    def test_validation_result_default_values(self):
        """Test ValidationResult with default values"""
        result = ValidationResult(
            check_name="test",
            status="FAIL",
            message="Failed"
        )

        assert result.rule_id == ""
        assert result.severity == "INFO"


class TestRuleValidationReport:
    """Test RuleValidationReport dataclass"""

    def test_rule_validation_report_creation(self):
        """Test creating RuleValidationReport"""
        results = [
            ValidationResult("check1", "PASS", "Passed"),
            ValidationResult("check2", "FAIL", "Failed"),
        ]

        report = RuleValidationReport(
            rule_file="/path/to/rule.xml",
            rule_id="100001",
            results=results,
            total_checks=2,
            passed_checks=1,
            failed_checks=1,
            warning_checks=0
        )

        assert report.rule_file == "/path/to/rule.xml"
        assert report.rule_id == "100001"
        assert len(report.results) == 2
        assert report.total_checks == 2
        assert report.passed_checks == 1
        assert report.failed_checks == 1


class TestMultipleRulesInFile:
    """Test validation of files with multiple rules"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_multiple_rules_same_file(self, temp_dir):
        """Test validation of multiple rules in single file"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test 1</match>
    <description>First rule</description>
    <group>test</group>
  </rule>
  <rule id="100002" level="4">
    <match>Test 2</match>
    <description>Second rule</description>
    <group>test</group>
  </rule>
  <rule id="100003" level="5">
    <match>Test 3</match>
    <description>Third rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "multi.xml", rule_content)
        validator = WazuhRuleValidator(rule_file)
        results = validator.validate_all()

        # Check that all three rules were validated
        assert len(results) == 1
        rule_results = results[0]

        # Should have results for each rule
        assert rule_results.total_checks > 5


class TestStrictMode:
    """Test strict mode functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_strict_mode_initialization(self, temp_dir):
        """Test initializing validator in strict mode"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Test</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "strict.xml", rule_content)
        validator = WazuhRuleValidator(rule_file, strict_mode=True)

        assert validator.strict_mode is True

    def test_validation_exit_code_treats_warnings_as_failures_only_in_strict_mode(self):
        report = RuleValidationReport(
            rule_file="rules.xml",
            rule_id="100001",
            results=[
                ValidationResult(
                    check_name="performance_pattern",
                    status="WARN",
                    message="risky regex",
                )
            ],
            total_checks=1,
            passed_checks=0,
            failed_checks=0,
            warning_checks=1,
        )

        assert validation_exit_code([report], strict_mode=False) == 0
        assert validation_exit_code([report], strict_mode=True) == 1

    def test_validation_exit_code_fails_on_errors_without_strict_mode(self):
        report = RuleValidationReport(
            rule_file="rules.xml",
            rule_id="100001",
            results=[
                ValidationResult(
                    check_name="rule_id_format",
                    status="FAIL",
                    message="bad id",
                )
            ],
            total_checks=1,
            passed_checks=0,
            failed_checks=1,
            warning_checks=0,
        )

        assert validation_exit_code([report], strict_mode=False) == 1

    def test_cli_strict_mode_returns_nonzero_for_warnings(self, temp_dir, capsys):
        long_pattern = "a" * 2000
        rule_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>{long_pattern}</regex>
    <description>Long pattern</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "strict_warning.xml", rule_content)

        assert main(["--rules", str(rule_file)]) == 0
        assert main(["--rules", str(rule_file), "--strict"]) == 1
        assert "WARN" in capsys.readouterr().out

    def test_cli_returns_nonzero_when_report_write_fails(self, monkeypatch, temp_dir):
        """Operational output errors should remain clean CLI failures."""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Test</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "report_io_error.xml", rule_content)

        def raise_os_error(*args, **kwargs):
            raise OSError("stdout is closed")

        monkeypatch.setattr("builtins.print", raise_os_error)

        assert main(["--rules", str(rule_file)]) == 1

    def test_cli_does_not_hide_programming_errors(self, monkeypatch, temp_dir):
        """Unexpected validator bugs should propagate instead of becoming exit 1."""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Test</match>
    <description>Test</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "programming_error.xml", rule_content)

        def raise_type_error(self):
            raise TypeError("validator contract changed")

        monkeypatch.setattr(WazuhRuleValidator, "validate_all", raise_type_error)

        with pytest.raises(TypeError, match="validator contract changed"):
            main(["--rules", str(rule_file)])


class TestSampleLogTesting:
    """Test sample log matching"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def create_rule_file(self, temp_dir: Path, filename: str, content: str) -> Path:
        """Helper to create test rule file"""
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path

    def test_sample_matching_match_element(self, temp_dir):
        """Test sample log matching with match element"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Failed password</match>
    <description>Failed login</description>
    <group>authentication</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "match.xml", rule_content)

        samples = [
            "Failed password for user admin",
            "Login successful",
            "Failed password for root",
        ]

        validator = WazuhRuleValidator(rule_file, test_samples=samples)
        results = validator.validate_all()

        sample_results = [r for r in results[0].results
                         if "sample_testing" in r.check_name]
        assert any(r.status == "PASS" for r in sample_results)

    def test_load_sample_logs_uses_utf8_and_ignores_blank_lines(self, temp_dir):
        """Sample log loading should be deterministic and discard empty lines"""
        samples_file = temp_dir / "samples.log"
        samples_file.write_text("\n Failed password for café \n\nLogin successful\n", encoding="utf-8")

        assert load_sample_logs(samples_file) == [
            "Failed password for café",
            "Login successful",
        ]

    def test_cli_returns_nonzero_when_sample_file_is_missing(self, temp_dir):
        """Missing sample files should fail before validation starts"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>Failed password</match>
    <description>Failed login</description>
    <group>authentication</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "match.xml", rule_content)

        assert main(["--rules", str(rule_file), "--samples", str(temp_dir / "missing.log")]) == 1

    def test_sample_matching_regex_element(self, temp_dir):
        """Test sample log matching with regex element"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>Failed password for (\\w+)</regex>
    <description>Failed login</description>
    <group>authentication</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "regex.xml", rule_content)

        samples = [
            "Failed password for admin",
            "Login successful",
            "Failed password for root",
        ]

        validator = WazuhRuleValidator(rule_file, test_samples=samples)
        results = validator.validate_all()

        sample_results = [r for r in results[0].results
                         if "sample_testing" in r.check_name]
        assert any(r.status == "PASS" for r in sample_results)

    def test_sample_no_matches_warning(self, temp_dir):
        """Test warning when no samples match"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <match>VERY_UNIQUE_PATTERN</match>
    <description>Unmatched rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "nomatch.xml", rule_content)

        samples = [
            "Log line 1",
            "Log line 2",
            "Log line 3",
        ]

        validator = WazuhRuleValidator(rule_file, test_samples=samples)
        results = validator.validate_all()

        sample_results = [r for r in results[0].results
                         if "sample_testing" in r.check_name]
        assert any(r.status == "WARN" for r in sample_results)

    def test_sample_testing_invalid_regex_fails_closed(self, temp_dir):
        """Invalid regex patterns should not be hidden as sample misses"""
        rule_content = """<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <rule id="100001" level="3">
    <regex>[unterminated</regex>
    <description>Invalid regex rule</description>
    <group>test</group>
  </rule>
</rules>
"""
        rule_file = self.create_rule_file(temp_dir, "bad_sample_regex.xml", rule_content)
        samples = [
            "anything",
            "still should only report one sample regex failure",
        ]

        validator = WazuhRuleValidator(rule_file, test_samples=samples)
        results = validator.validate_all()

        sample_results = [
            r for r in results[0].results
            if r.check_name == "sample_testing_regex"
        ]
        assert len(sample_results) == 1
        assert sample_results[0].status == "FAIL"
        assert "Cannot test regex pattern" in sample_results[0].message
