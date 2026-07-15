#!/usr/bin/env python3
"""
Comprehensive unit tests for Sigma to Wazuh Rule Converter

Tests cover:
- YAML parsing (valid, invalid, empty files)
- Field mapping (Sigma to Wazuh field conversion)
- Rule ID generation (sequential, collision detection, reserved IDs)
- XML output generation (structure, formatting, prettification)
- Error handling (file I/O, validation, malformed input)
- Edge cases (special characters, unicode, boundary values, deeply nested structures)
"""

import argparse
import json
import logging
import os
import re
import sys
import pytest
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock, mock_open
from typing import Dict, Any

import yaml
from sigma.exceptions import SigmaError

from wazuh_sigma.backend.wazuh import (
    SigmaFieldMapper,
    WazuhBackend,
    WazuhBackendConfig,
    WazuhRuleGenerator,
    WazuhRuleIDGenerator,
)
from wazuh_sigma.converter.cli import build_parser, cli, positive_int, setup_logging
from wazuh_sigma.converter.presentation import format_conversion_summary
from wazuh_sigma.converter.service import ConversionState, SigmaToWazuhConverter
from wazuh_sigma.sigma import (
    PYSIGMA_RULE_MODULE,
    SigmaParseError,
    SigmaRule,
    SigmaRule as CoreSigmaRule,
    parse_sigma_with_pysigma,
)


def test_setup_logging_is_idempotent():
    logger = setup_logging("INFO")
    handler_count = len(logger.handlers)

    setup_logging("DEBUG")
    setup_logging("ERROR")

    assert len(logger.handlers) == handler_count
    assert logger.propagate is False
    assert logger.level == logging.ERROR


def test_setup_logging_rejects_unknown_level():
    with pytest.raises(ValueError, match="log_level"):
        setup_logging("LOUD")


def test_core_sigma_rule_extracts_detection_keywords():
    rule = CoreSigmaRule(
        {
            "title": "Core",
            "logsource": {"service": "sysmon"},
            "detection": {
                "keywords": {
                    "Image": "cmd.exe",
                    "CommandLine": ["whoami", "ipconfig"],
                },
                "condition": "keywords",
            },
        }
    )

    assert rule.get_detection_keywords() == ["cmd.exe", "whoami", "ipconfig"]


def test_format_conversion_summary_is_presentation_only():
    summary = format_conversion_summary(
        {
            "total_converted": 2,
            "total_errors": 1,
            "errors": ["bad-rule.yml: invalid detection"],
        },
        "build/sigmahq/sigma_rules.xml",
    )

    assert "CONVERSION SUMMARY" in summary
    assert "Total Rules Converted: 2" in summary
    assert "bad-rule.yml: invalid detection" in summary


def test_converter_help_uses_installed_command_name(capsys):
    """CLI help should not point users at removed script filenames."""
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["--help"])

    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "sigma-convert -d ./sigma_rules -o wazuh_rules.xml" in help_text
    assert "sigma_to_wazuh_converter.py" not in help_text


def test_converter_parser_normalizes_logging_level():
    args = build_parser().parse_args(["-d", "examples/sigma", "-v", "debug"])

    assert args.verbose == "DEBUG"


def test_converter_parser_rejects_unknown_logging_level():
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["-d", "examples/sigma", "-v", "LOUD"])

    assert exit_info.value.code == 2


@pytest.mark.parametrize("value", ["1", "900000"])
def test_converter_positive_int_accepts_positive_values(value):
    assert positive_int(value) == int(value)


@pytest.mark.parametrize("value", ["0", "-1", "nope"])
def test_converter_positive_int_rejects_invalid_values(value):
    with pytest.raises(argparse.ArgumentTypeError, match="positive integer"):
        positive_int(value)


def test_converter_parser_rejects_non_positive_rule_id():
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["-d", "examples/sigma", "--start-id", "0"])

    assert exit_info.value.code == 2


def test_converter_cli_rejects_inverted_rule_id_range():
    with pytest.raises(SystemExit) as exit_info:
        cli(["-d", "examples/sigma", "--start-id", "950000", "--end-id", "900000"])

    assert exit_info.value.code == 2


class TestSigmaFieldMapper:
    """Test suite for SigmaFieldMapper class."""

    def test_map_field_known_field(self):
        """Test mapping of known Sigma fields."""
        assert SigmaFieldMapper.map_field("EventID") == "win.system.eventID"
        assert SigmaFieldMapper.map_field("Image") == "win.eventdata.image"
        assert SigmaFieldMapper.map_field("CommandLine") == "win.eventdata.commandLine"
        assert SigmaFieldMapper.map_field("ParentImage") == "win.eventdata.parentImage"
        assert SigmaFieldMapper.map_field("SourceIp") == "win.eventdata.sourceIp"
        assert SigmaFieldMapper.map_field("DestinationPort") == "win.eventdata.destinationPort"

    def test_map_field_unknown_field(self):
        """Test mapping of unknown fields uses lowercase conversion."""
        assert SigmaFieldMapper.map_field("CustomField") == "customfield"
        assert SigmaFieldMapper.map_field("Unknown") == "unknown"
        assert SigmaFieldMapper.map_field("NewProcessName") == "win.eventdata.newProcessName"

    def test_map_field_with_spaces(self):
        """Test field names with spaces are converted to underscores."""
        assert SigmaFieldMapper.map_field("Custom Field") == "custom_field"
        assert SigmaFieldMapper.map_field("Process Name") == "process_name"

    def test_map_field_hashes(self):
        """Test mapping of hash fields."""
        assert SigmaFieldMapper.map_field("MD5") == "win.eventdata.md5"
        assert SigmaFieldMapper.map_field("SHA1") == "win.eventdata.sha1"
        assert SigmaFieldMapper.map_field("SHA256") == "win.eventdata.sha256"
        assert SigmaFieldMapper.map_field("Imphash") == "win.eventdata.imphash"

    def test_is_regex_with_metacharacters(self):
        """Test regex detection with common metacharacters."""
        assert SigmaFieldMapper.is_regex(".*") is True
        assert SigmaFieldMapper.is_regex("test.*") is True
        assert SigmaFieldMapper.is_regex("[a-z]+") is True
        assert SigmaFieldMapper.is_regex("^start") is True
        assert SigmaFieldMapper.is_regex("end$") is True
        assert SigmaFieldMapper.is_regex("(a|b)") is True

    def test_is_regex_without_metacharacters(self):
        """Test regex detection with plain strings."""
        assert SigmaFieldMapper.is_regex("plain_string") is False
        assert SigmaFieldMapper.is_regex("test123") is False
        assert SigmaFieldMapper.is_regex("Program Files") is False

    def test_is_regex_with_special_chars(self):
        """Test regex detection with special characters."""
        assert SigmaFieldMapper.is_regex("test\\d") is True
        assert SigmaFieldMapper.is_regex("a{2,5}") is True
        assert SigmaFieldMapper.is_regex("test?") is True
        assert SigmaFieldMapper.is_regex("test+") is True

    def test_operator_mapping(self):
        """Test operator mapping dictionary."""
        assert "equals" in SigmaFieldMapper.OPERATOR_MAPPING
        assert "contains" in SigmaFieldMapper.OPERATOR_MAPPING
        assert "re" in SigmaFieldMapper.OPERATOR_MAPPING


class TestWazuhBackendConfig:
    """Test suite for backend configuration contracts."""

    def test_field_mapping_is_an_override_contract(self):
        """Backend config should store only configured field mapping overrides."""
        config = WazuhBackendConfig()

        assert config.field_mapping is None

    def test_backend_merges_field_mapping_overrides_with_defaults(self):
        """A custom mapping should not discard default Sigma field mappings."""
        backend = WazuhBackend(WazuhBackendConfig(field_mapping={"Image": "custom.image"}))

        assert backend.field_mapper.map("Image") == "custom.image"
        assert backend.field_mapper.map("EventID") == "win.system.eventID"

    def test_backend_emits_required_parent_rule_from_logsource(self):
        backend = WazuhBackend(
            WazuhBackendConfig(
                parent_rules={
                    "service:sysmon": [60004],
                    "product:windows": [60000],
                    "default": [60000],
                }
            )
        )
        sigma_rule = SigmaRule({
            "title": "Sysmon Parent Rule",
            "logsource": {"product": "windows", "service": "sysmon"},
            "detection": {"selection": {"Image": "cmd.exe"}},
        })

        rule = backend.convert_rule(sigma_rule)

        assert rule.findtext("if_sid") == "60004"

    def test_backend_prefers_category_parent_rule_over_product_fallback(self):
        backend = WazuhBackend(
            WazuhBackendConfig(
                parent_rules={
                    "category:process_creation": [61603],
                    "product:windows": [60000],
                    "default": [60000],
                }
            )
        )
        sigma_rule = SigmaRule({
            "title": "Process Creation Parent Rule",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {"selection": {"Image": "cmd.exe"}},
        })

        rule = backend.convert_rule(sigma_rule)

        assert rule.findtext("if_sid") == "61603"

    def test_backend_prefers_security_event_parent_rule_over_service_fallback(self):
        backend = WazuhBackend(
            WazuhBackendConfig(
                parent_rules={
                    "security_event_id:4720": [60109],
                    "service:security": [60001],
                    "product:windows": [60000],
                    "default": [60000],
                }
            )
        )
        sigma_rule = SigmaRule({
            "title": "Windows Local User Created",
            "logsource": {"product": "windows", "service": "security"},
            "detection": {
                "selection": {
                    "EventID": 4720,
                    "TargetUserName|endswith": "$",
                }
            },
        })

        rule = backend.convert_rule(sigma_rule)

        assert rule.findtext("if_sid") == "60109"

    def test_backend_emits_data_as_native_field_with_editor_safe_escaping(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Data Field",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"data|contains": "CLIENT: <local machine>"}},
        })

        rule = backend.convert_rule(sigma_rule)

        data_field = rule.find("data")
        assert data_field is not None
        assert data_field.get("type") == "pcre2"
        assert data_field.text == r"^.*CLIENT: \x3clocal machine\x3e.*$"

    def test_backend_merges_duplicate_dynamic_fields_for_editor_safe_xml(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Duplicate Field",
            "logsource": {"product": "windows"},
            "detection": {
                "selection_one": {"CommandLine|contains": "cmd.exe"},
                "selection_two": {"CommandLine|contains": "powershell.exe"},
                "condition": "selection_one or selection_two",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        command_lines = [field for field in rule.findall("field") if field.get("name") == "win.eventdata.commandLine"]
        assert len(command_lines) == 1
        assert command_lines[0].text == r"(?:^.*cmd\.exe.*$|^.*powershell\.exe.*$)"

    def test_backend_lowers_and_condition_with_duplicate_field_predicates_as_lookaheads(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Duplicate Field AND",
            "logsource": {"product": "windows"},
            "detection": {
                "selection_one": {"CommandLine|contains": "cmd.exe"},
                "selection_two": {"CommandLine|contains": "powershell.exe"},
                "condition": "selection_one and selection_two",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        command_line = rule.find("field[@name='win.eventdata.commandLine']")
        assert command_line is not None
        assert command_line.text == r"(?=^.*cmd\.exe.*$)(?=^.*powershell\.exe.*$).*"
        assert re.search(command_line.text, "cmd.exe launches powershell.exe")
        assert not re.search(command_line.text, "cmd.exe only")
        assert not re.search(command_line.text, "powershell.exe only")

    def test_backend_preserves_or_condition_duplicate_field_regex_semantics(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Duplicate Field OR Differential",
            "logsource": {"product": "windows"},
            "detection": {
                "selection_one": {"CommandLine|contains": "cmd.exe"},
                "selection_two": {"CommandLine|contains": "powershell.exe"},
                "condition": "selection_one or selection_two",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        command_line = rule.find("field[@name='win.eventdata.commandLine']")
        assert command_line is not None
        assert re.search(command_line.text, "C:\\Windows\\System32\\cmd.exe /c whoami")
        assert re.search(command_line.text, "powershell.exe -NoProfile")
        assert not re.search(command_line.text, "rundll32.exe shell32.dll,Control_RunDLL")

    def test_backend_lowers_single_field_not_with_wazuh_negation(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Negation",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"CommandLine|contains": "powershell.exe"},
                "filter": {"CommandLine|contains": "-ExecutionPolicy Bypass"},
                "condition": "selection and not filter",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        fields = rule.findall("field")
        assert [field.get("negate") for field in fields] == [None, "yes"]
        assert fields[0].text == r"^.*powershell\.exe.*$"
        assert fields[1].text == r"^.*\-ExecutionPolicy Bypass.*$"

    def test_backend_lowers_grouped_not_or_as_negated_conjunction(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Grouped Negation",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"CommandLine|contains": "powershell.exe"},
                "filter_one": {"CommandLine|contains": "-ExecutionPolicy Bypass"},
                "filter_two": {"User": "SYSTEM"},
                "condition": "selection and not (filter_one or filter_two)",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        fields = rule.findall("field")
        assert [(field.get("name"), field.get("negate"), field.text) for field in fields] == [
            ("win.eventdata.commandLine", None, r"^.*powershell\.exe.*$"),
            ("win.eventdata.commandLine", "yes", r"^.*\-ExecutionPolicy Bypass.*$"),
            ("win.eventdata.user", "yes", r"^SYSTEM$"),
        ]

    def test_backend_lowers_grouped_not_and_as_child_rule_or(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Grouped NOT AND",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"Image|endswith": "\\cmd.exe"},
                "filter_one": {"CommandLine|contains": "whoami"},
                "filter_two": {"User": "SYSTEM"},
                "condition": "selection and not (filter_one and filter_two)",
            },
        })

        rules = backend.convert_rules(sigma_rule)

        assert len(rules) == 2
        first = [(field.get("name"), field.get("negate"), field.text) for field in rules[0].findall("field")]
        second = [(field.get("name"), field.get("negate"), field.text) for field in rules[1].findall("field")]
        assert first == [
            ("win.eventdata.image", None, r"^.*\\cmd\.exe$"),
            ("win.eventdata.commandLine", "yes", r"^.*whoami.*$"),
        ]
        assert second == [
            ("win.eventdata.image", None, r"^.*\\cmd\.exe$"),
            ("win.eventdata.user", "yes", r"^SYSTEM$"),
        ]

    def test_backend_merges_duplicate_negated_same_field_predicates(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Duplicate Negated Field",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"Image|endswith": "\\cmd.exe"},
                "filter_one": {"CommandLine|contains": "whoami"},
                "filter_two": {"CommandLine|contains": "ipconfig"},
                "condition": "selection and not (filter_one or filter_two)",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        command_line = rule.find("field[@name='win.eventdata.commandLine']")
        assert command_line is not None
        assert command_line.get("negate") == "yes"
        assert command_line.text == r"(?:^.*whoami.*$|^.*ipconfig.*$)"

    def test_backend_lowers_ipv4_cidr_exactly(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "IPv4 CIDR",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"SourceIp|cidr": "192.0.2.0/24"},
                "condition": "selection",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        source_ip = rule.find("field[@name='win.eventdata.sourceIp']")
        assert source_ip is not None
        assert re.search(source_ip.text, "192.0.2.10")
        assert re.search(source_ip.text, "192.0.2.255")
        assert not re.search(source_ip.text, "11.0.0.1")
        assert not re.search(source_ip.text, "198.51.100.1")

    def test_backend_lowers_partial_octet_ipv4_cidr_exactly(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Partial IPv4 CIDR",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"DestinationIp|cidr": "172.16.0.0/12"},
                "condition": "selection",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        destination_ip = rule.find("field[@name='win.eventdata.destinationIp']")
        assert destination_ip is not None
        assert re.search(destination_ip.text, "172.16.0.1")
        assert re.search(destination_ip.text, "172.31.255.255")
        assert not re.search(destination_ip.text, "172.15.255.255")
        assert not re.search(destination_ip.text, "172.32.0.0")

    def test_backend_rejects_ipv6_cidr_until_wazuh_canonicalization_is_proven(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "IPv6 CIDR",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"DestinationIp|cidr": "2001:db8::/32"},
                "condition": "selection",
            },
        })

        with pytest.raises(ValueError, match="IPv6 CIDR is not supported"):
            backend.convert_rule(sigma_rule)

    def test_backend_rejects_cidr_modifier_combinations(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "CIDR Modifier Combination",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"DestinationIp|cidr|contains": "192.0.2.0/24"},
                "condition": "selection",
            },
        })

        with pytest.raises(ValueError, match="cidr with non-cidr modifiers"):
            backend.convert_rule(sigma_rule)

    def test_backend_lowers_same_field_and_with_safe_regex_lookahead(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Same Field Regex AND",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {
                    "CommandLine|contains": "curl.exe",
                    "CommandLine|re": r"\s-H\s",
                },
                "condition": "selection",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        command_line = rule.find("field[@name='win.eventdata.commandLine']")
        assert command_line is not None
        assert command_line.text == r"(?=^.*curl\.exe.*$)(?=.*(?:\s-H\s)).*"
        assert re.search(command_line.text, "curl.exe -H User-Agent: evil https://example.test")
        assert not re.search(command_line.text, "curl.exe --header User-Agent: evil https://example.test")
        assert not re.search(command_line.text, "powershell.exe -H User-Agent: evil https://example.test")

    def test_backend_rejects_same_field_and_with_position_unsafe_regex(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Unsafe Regex AND",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {
                    "CommandLine|contains": "curl.exe",
                    "CommandLine|re": r"foo|^bar",
                },
                "condition": "selection",
            },
        })

        with pytest.raises(ValueError, match="same-field AND"):
            backend.convert_rule(sigma_rule)

    def test_backend_lowers_grouped_same_field_or_with_common_and_predicate(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Grouped Same Field OR",
            "logsource": {"product": "windows"},
            "detection": {
                "image": {"Image|endswith": "\\cmd.exe"},
                "cli_one": {"CommandLine|contains": "whoami"},
                "cli_two": {"CommandLine|contains": "ipconfig"},
                "condition": "image and (cli_one or cli_two)",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        image = rule.find("field[@name='win.eventdata.image']")
        command_line = rule.find("field[@name='win.eventdata.commandLine']")
        assert image is not None
        assert command_line is not None
        assert image.text == r"^.*\\cmd\.exe$"
        assert command_line.text == r"(?:^.*whoami.*$|^.*ipconfig.*$)"
        assert re.search(command_line.text, "cmd.exe /c whoami")
        assert re.search(command_line.text, "cmd.exe /c ipconfig")
        assert not re.search(command_line.text, "cmd.exe /c hostname")

    def test_backend_lowers_or_across_distinct_fields_as_child_rules(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Distinct Field OR",
            "logsource": {"product": "windows"},
            "tags": ["attack.execution"],
            "detection": {
                "image": {"Image|endswith": "\\cmd.exe"},
                "user": {"User": "SYSTEM"},
                "condition": "image or user",
            },
        })

        rules = backend.convert_rules(sigma_rule)

        assert [rule.get("id") for rule in rules] == ["900000", "900001"]
        assert [rule.get("level") for rule in rules] == ["10", "10"]
        assert [rule.findtext("description") for rule in rules] == [
            "Distinct Field OR [branch 1/2]",
            "Distinct Field OR [branch 2/2]",
        ]
        assert all(rule.findtext("if_sid") == "60000" for rule in rules)
        assert all("sigma_attack_execution" in rule.findtext("group", "") for rule in rules)
        assert rules[0].find("field[@name='win.eventdata.image']").text == r"^.*\\cmd\.exe$"
        assert rules[1].find("field[@name='win.eventdata.user']").text == r"^SYSTEM$"

    def test_backend_lowers_nested_mixed_expression_as_exact_child_rules(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Nested Mixed",
            "logsource": {"product": "windows"},
            "detection": {
                "image": {"Image|endswith": "\\cmd.exe"},
                "cli_one": {"CommandLine|contains": "whoami"},
                "cli_two": {"CommandLine|contains": "ipconfig"},
                "user": {"User": "SYSTEM"},
                "condition": "(image and cli_one) or (user and cli_two)",
            },
        })

        rules = backend.convert_rules(sigma_rule)

        assert len(rules) == 2
        first_fields = {field.get("name"): field.text for field in rules[0].findall("field")}
        second_fields = {field.get("name"): field.text for field in rules[1].findall("field")}
        assert first_fields == {
            "win.eventdata.image": r"^.*\\cmd\.exe$",
            "win.eventdata.commandLine": r"^.*whoami.*$",
        }
        assert second_fields == {
            "win.eventdata.user": r"^SYSTEM$",
            "win.eventdata.commandLine": r"^.*ipconfig.*$",
        }

    def test_backend_child_rules_deduplicate_repeated_predicates_and_branches(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Repeated Predicates",
            "logsource": {"product": "windows"},
            "detection": {
                "image": {"Image|endswith": "\\cmd.exe"},
                "cli": {"CommandLine|contains": "whoami"},
                "condition": "(image and cli) or (image and cli)",
            },
        })

        rules = backend.convert_rules(sigma_rule)

        assert len(rules) == 1
        fields = rules[0].findall("field")
        assert len(fields) == 2
        assert {field.get("name") for field in fields} == {"win.eventdata.image", "win.eventdata.commandLine"}

    def test_backend_child_rule_ids_are_stable_for_same_input(self):
        sigma_rule = SigmaRule({
            "title": "Stable IDs",
            "logsource": {"product": "windows"},
            "detection": {
                "image": {"Image|endswith": "\\cmd.exe"},
                "user": {"User": "SYSTEM"},
                "condition": "image or user",
            },
        })

        first = WazuhBackend().convert_rules(sigma_rule)
        second = WazuhBackend().convert_rules(sigma_rule)

        assert [rule.get("id") for rule in first] == ["900000", "900001"]
        assert [rule.get("id") for rule in second] == ["900000", "900001"]
        assert [ET.tostring(rule, encoding="unicode") for rule in first] == [
            ET.tostring(rule, encoding="unicode") for rule in second
        ]

    def test_backend_rejects_dnf_branch_explosion_before_emitting_partial_rules(self):
        backend = WazuhBackend(WazuhBackendConfig(max_dnf_alternatives=2))
        sigma_rule = SigmaRule({
            "title": "Explosion",
            "logsource": {"product": "windows"},
            "detection": {
                "image_one": {"Image|endswith": "\\cmd.exe"},
                "image_two": {"Image|endswith": "\\powershell.exe"},
                "user_one": {"User": "SYSTEM"},
                "user_two": {"User": "Administrator"},
                "condition": "(image_one or image_two) and (user_one or user_two)",
            },
        })

        with pytest.raises(ValueError, match="DNF alternatives 4 exceeds configured maximum 2"):
            backend.convert_rules(sigma_rule)

    def test_backend_lowers_one_of_wildcard_same_field_as_or(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Wildcard One Of",
            "logsource": {"product": "windows"},
            "detection": {
                "selection_one": {"CommandLine|contains": "whoami"},
                "selection_two": {"CommandLine|contains": "ipconfig"},
                "condition": "1 of selection_*",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        command_line = rule.find("field[@name='win.eventdata.commandLine']")
        assert command_line is not None
        assert command_line.text == r"(?:^.*whoami.*$|^.*ipconfig.*$)"

    def test_backend_lowers_all_of_wildcard_same_field_as_lookaheads(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Wildcard All Of",
            "logsource": {"product": "windows"},
            "detection": {
                "selection_one": {"CommandLine|contains": "powershell"},
                "selection_two": {"CommandLine|contains": "encodedcommand"},
                "condition": "all of selection_*",
            },
        })

        rule = backend.convert_rule(sigma_rule)

        command_line = rule.find("field[@name='win.eventdata.commandLine']")
        assert command_line is not None
        assert command_line.text == r"(?=^.*powershell.*$)(?=^.*encodedcommand.*$).*"
        assert re.search(command_line.text, "powershell.exe -encodedcommand test")
        assert not re.search(command_line.text, "powershell.exe")

    def test_backend_rejects_oversized_patterns_before_wazuh_upload(self):
        backend = WazuhBackend(WazuhBackendConfig(
            max_dnf_alternatives=200,
            max_generated_child_rules=200,
            max_predicates_per_alternative=200,
        ))
        sigma_rule = SigmaRule({
            "title": "Oversized Pattern",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {
                    "Hashes|contains|all": [f"MD5={index:032x}" for index in range(150)],
                }
            },
        })

        with pytest.raises(ValueError, match="pattern length .* exceeds supported maximum"):
            backend.convert_rule(sigma_rule)

    def test_backend_splits_oversized_same_field_or_without_changing_semantics(self, monkeypatch):
        monkeypatch.setattr(WazuhRuleGenerator, "MAX_PATTERN_LENGTH", 45)
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Oversized Same Field OR",
            "logsource": {"product": "windows"},
            "detection": {
                "one": {"CommandLine|contains": "first-long-token"},
                "two": {"CommandLine|contains": "second-long-token"},
                "three": {"CommandLine|contains": "third-long-token"},
                "condition": "1 of them",
            },
        })

        rules = backend.convert_rules(sigma_rule)

        assert len(rules) == 3
        patterns = [
            rule.find("field[@name='win.eventdata.commandLine']").text
            for rule in rules
        ]
        assert patterns == [
            r"^.*first\-long\-token.*$",
            r"^.*second\-long\-token.*$",
            r"^.*third\-long\-token.*$",
        ]


class TestWazuhRuleIDGenerator:
    """Test suite for WazuhRuleIDGenerator class."""

    def test_generator_initialization(self):
        """Test ID generator initialization with default value."""
        gen = WazuhRuleIDGenerator()
        assert gen.current_id == WazuhRuleIDGenerator.START_CUSTOM_ID
        assert len(gen.used_ids) == 0

    def test_generator_initialization_custom_start(self):
        """Test ID generator initialization with custom start ID."""
        gen = WazuhRuleIDGenerator(start_id=100500)
        assert gen.current_id == 100500

    def test_generate_sequential_ids(self):
        """Test sequential ID generation."""
        gen = WazuhRuleIDGenerator(start_id=100000)
        id1 = gen.generate_id()
        id2 = gen.generate_id()
        id3 = gen.generate_id()

        assert id1 == 100000
        assert id2 == 100001
        assert id3 == 100002
        assert len(gen.used_ids) == 3

    def test_generate_id_avoids_used_ids(self):
        """Test that ID generator skips reserved IDs."""
        gen = WazuhRuleIDGenerator(start_id=100000)
        gen.used_ids.add(100000)
        gen.used_ids.add(100001)

        id1 = gen.generate_id()
        assert id1 == 100002

    def test_reserve_id(self):
        """Test reserving specific IDs."""
        gen = WazuhRuleIDGenerator(start_id=100000)
        gen.reserve_id(100000)
        gen.reserve_id(100001)

        id1 = gen.generate_id()
        assert id1 == 100002
        assert 100000 in gen.used_ids
        assert 100001 in gen.used_ids

    def test_reserve_id_updates_current(self):
        """Test that reserving high ID updates current_id."""
        gen = WazuhRuleIDGenerator(start_id=100000)
        gen.reserve_id(100100)

        # current_id should be updated to 100101
        assert gen.current_id == 100101

        id1 = gen.generate_id()
        assert id1 == 100101

    def test_reserve_multiple_ids_collision_avoidance(self):
        """Test collision detection with multiple reserved IDs."""
        gen = WazuhRuleIDGenerator(start_id=100000)
        gen.reserve_id(100000)
        gen.reserve_id(100001)
        gen.reserve_id(100002)

        id1 = gen.generate_id()
        assert id1 == 100003

    def test_generate_large_batch_of_ids(self):
        """Test generating large batch of IDs."""
        gen = WazuhRuleIDGenerator(start_id=100000)
        ids = [gen.generate_id() for _ in range(1000)]

        assert len(set(ids)) == 1000  # All unique
        assert len(ids) == 1000

    def test_owned_range_is_enforced(self):
        """Rule ID generation fails before leaving the configured owned range."""
        gen = WazuhRuleIDGenerator(start_id=900000, end_id=900001)
        assert gen.generate_id() == 900000
        assert gen.generate_id() == 900001
        with pytest.raises(ValueError, match="exhausted"):
            gen.generate_id()

    def test_reserve_id_rejects_outside_owned_range(self):
        gen = WazuhRuleIDGenerator(start_id=900000, end_id=900010)
        with pytest.raises(ValueError, match="outside owned range"):
            gen.reserve_id(899999)


class TestSigmaRule:
    """Test suite for SigmaRule class."""

    def get_minimal_rule(self) -> Dict[str, Any]:
        """Return a minimal valid Sigma rule."""
        return {
            "title": "Test Rule",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "test.exe"}},
        }

    def test_sigma_rule_initialization(self):
        """Test SigmaRule initialization with minimal data."""
        rule_dict = self.get_minimal_rule()
        sigma_rule = SigmaRule(rule_dict, source_file="test.yaml")

        assert sigma_rule.title == "Test Rule"
        assert sigma_rule.source_file == "test.yaml"
        assert sigma_rule.logsource == {"service": "sysmon"}

    def test_sigma_rule_default_values(self):
        """Test that SigmaRule provides default values."""
        rule_dict = {
            "title": "Test Rule",
            "logsource": {},
            "detection": {},
        }
        sigma_rule = SigmaRule(rule_dict)

        assert sigma_rule.description == ""
        assert sigma_rule.author == "Unknown"
        assert sigma_rule.status == "experimental"
        assert sigma_rule.level == "medium"
        assert sigma_rule.tags == []

    def test_sigma_rule_with_all_fields(self):
        """Test SigmaRule with complete metadata."""
        rule_dict = {
            "title": "Complete Rule",
            "description": "A test rule",
            "author": "John Doe",
            "date": "2024-01-01",
            "modified": "2024-01-02",
            "status": "test",
            "level": "high",
            "tags": ["attack.t1234", "detection"],
            "references": ["https://example.com"],
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"field": "value"}},
        }
        sigma_rule = SigmaRule(rule_dict)

        assert sigma_rule.title == "Complete Rule"
        assert sigma_rule.description == "A test rule"
        assert sigma_rule.author == "John Doe"
        assert sigma_rule.level == "high"
        assert len(sigma_rule.tags) == 2

    def test_sigma_rule_normalizes_optional_metadata_lists(self):
        """Optional list-shaped metadata accepts scalar and null legacy values safely."""
        scalar_rule = SigmaRule({
            "title": "Scalar Metadata",
            "tags": "attack.execution",
            "references": "https://example.com/ref",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "cmd.exe"}},
        })
        null_rule = SigmaRule({
            "title": "Null Metadata",
            "tags": None,
            "references": None,
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "cmd.exe"}},
        })

        assert scalar_rule.tags == ["attack.execution"]
        assert scalar_rule.references == ["https://example.com/ref"]
        assert null_rule.tags == []
        assert null_rule.references == []

    def test_get_detection_keywords_simple(self):
        """Test extraction of detection keywords from simple structure."""
        rule_dict = {
            "title": "Test",
            "logsource": {},
            "detection": {
                "Image": "test.exe"
            }
        }
        sigma_rule = SigmaRule(rule_dict)

        keywords = sigma_rule.get_detection_keywords()
        assert "test.exe" in keywords

    def test_get_detection_keywords_multiple_values(self):
        """Test extraction from multiple values."""
        rule_dict = {
            "title": "Test",
            "logsource": {},
            "detection": {
                "Image": ["cmd.exe", "powershell.exe"],
                "CommandLine": "*.txt"
            }
        }
        sigma_rule = SigmaRule(rule_dict)

        keywords = sigma_rule.get_detection_keywords()
        assert "cmd.exe" in keywords
        assert "powershell.exe" in keywords
        assert "*.txt" in keywords

    def test_get_event_source_from_service(self):
        """Test event source extraction from service."""
        rule_dict = self.get_minimal_rule()
        sigma_rule = SigmaRule(rule_dict)

        assert sigma_rule.get_event_source() == "sysmon"

    def test_get_event_source_from_product(self):
        """Test event source extraction from product."""
        rule_dict = {
            "title": "Test",
            "logsource": {"product": "windows"},
            "detection": {},
        }
        sigma_rule = SigmaRule(rule_dict)

        assert sigma_rule.get_event_source() == "windows"

    def test_get_event_source_prefers_service(self):
        """Test that service is preferred over product."""
        rule_dict = {
            "title": "Test",
            "logsource": {"service": "sysmon", "product": "windows"},
            "detection": {},
        }
        sigma_rule = SigmaRule(rule_dict)

        assert sigma_rule.get_event_source() == "sysmon"

    def test_validate_valid_rule(self):
        """Test validation of valid rule."""
        rule_dict = self.get_minimal_rule()
        sigma_rule = SigmaRule(rule_dict)

        is_valid, errors = sigma_rule.validate()
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_missing_title(self):
        """Test validation fails without title."""
        rule_dict = {
            "title": "",
            "logsource": {},
            "detection": {},
        }
        sigma_rule = SigmaRule(rule_dict)

        is_valid, errors = sigma_rule.validate()
        assert is_valid is False
        assert any("title" in error.lower() for error in errors)

    def test_validate_missing_detection(self):
        """Test validation fails without detection."""
        rule_dict = {
            "title": "Test",
            "logsource": {},
            "detection": {},
        }
        sigma_rule = SigmaRule(rule_dict)

        is_valid, errors = sigma_rule.validate()
        assert is_valid is False

    def test_validate_missing_logsource(self):
        """Test validation fails without logsource."""
        rule_dict = {
            "title": "Test",
            "logsource": {},
            "detection": {"selection": {}},
        }
        sigma_rule = SigmaRule(rule_dict)

        is_valid, errors = sigma_rule.validate()
        assert is_valid is False


class TestWazuhRuleGenerator:
    """Test suite for WazuhRuleGenerator class."""

    def get_test_sigma_rule(self) -> SigmaRule:
        """Create a test Sigma rule."""
        rule_dict = {
            "title": "Test Rule",
            "description": "A test rule description",
            "author": "Test Author",
            "level": "high",
            "tags": ["attack.t1234", "detection"],
            "references": ["https://example.com"],
            "logsource": {"service": "sysmon", "product": "windows"},
            "detection": {
                "selection": {
                    "Image": "cmd.exe",
                    "CommandLine": ["*.txt", "test.*"]
                }
            }
        }
        return SigmaRule(rule_dict, source_file="test.yaml")

    def test_generator_initialization(self):
        """Test WazuhRuleGenerator initialization."""
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)

        assert gen.id_generator is id_gen
        assert gen.field_mapper is not None

    def test_generate_basic_rule(self):
        """Test basic rule generation."""
        id_gen = WazuhRuleIDGenerator(start_id=100000)
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = self.get_test_sigma_rule()

        rule = gen.generate(sigma_rule)

        assert rule.tag == "rule"
        assert rule.get("id") == "100000"
        assert rule.get("level") == "12"  # High level maps to 12
        assert rule.get("overwrite") is None

    def test_generate_rule_creates_unique_ids(self):
        """Test that generated rules get unique IDs."""
        id_gen = WazuhRuleIDGenerator(start_id=100000)
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule1 = self.get_test_sigma_rule()
        sigma_rule2 = self.get_test_sigma_rule()

        rule1 = gen.generate(sigma_rule1)
        rule2 = gen.generate(sigma_rule2)

        assert rule1.get("id") != rule2.get("id")

    def test_level_mapping_critical(self):
        """Test severity level mapping for critical."""
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)

        assert gen.LEVEL_MAPPING["critical"] == 15

        rule_dict = {
            "title": "Critical Rule",
            "level": "critical",
            "logsource": {},
            "detection": {"selection": {"field": "value"}},
        }
        sigma_rule = SigmaRule(rule_dict)
        rule = gen.generate(sigma_rule)

        assert rule.get("level") == "15"

    def test_level_mapping_medium(self):
        """Test severity level mapping for medium."""
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)

        rule_dict = {
            "title": "Medium Rule",
            "level": "medium",
            "logsource": {},
            "detection": {"selection": {"field": "value"}},
        }
        sigma_rule = SigmaRule(rule_dict)
        rule = gen.generate(sigma_rule)

        assert rule.get("level") == "10"

    def test_level_override_is_applied_without_changing_default_mapping(self):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = SigmaRule({
            "title": "Override Rule",
            "level": "high",
            "logsource": {},
            "detection": {"selection": {"field": "value"}},
        })

        default_rule = gen.generate(sigma_rule)
        override_rule = gen.generate(sigma_rule, level_override=4)

        assert default_rule.get("level") == "12"
        assert override_rule.get("level") == "4"

    @pytest.mark.parametrize("level_override", [-1, 16, "10", True])
    def test_level_override_rejects_invalid_values(self, level_override):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = SigmaRule({
            "title": "Invalid Override Rule",
            "level": "high",
            "logsource": {},
            "detection": {"selection": {"field": "value"}},
        })

        with pytest.raises(ValueError, match="level_override"):
            gen.generate(sigma_rule, level_override=level_override)

        assert id_gen.used_ids == set()

    def test_backend_exposes_provider_agnostic_level_override_boundary(self):
        backend = WazuhBackend()
        sigma_rule = SigmaRule({
            "title": "Backend Override Rule",
            "level": "low",
            "logsource": {},
            "detection": {"selection": {"field": "value"}},
        })

        rule = backend.convert_rule(sigma_rule, level_override=11)

        assert rule.get("level") == "11"

    def test_backend_ruleset_timestamp_is_timezone_aware_utc(self):
        backend = WazuhBackend()
        rendered = backend.render_ruleset([], generated_at=datetime(2026, 7, 12, 10, 30, tzinfo=timezone.utc))

        assert "Sigma to Wazuh Conversion - 2026-07-12T10:30:00+00:00" in rendered

    def test_add_metadata_with_title(self):
        """Test metadata addition includes title."""
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = self.get_test_sigma_rule()

        rule = gen.generate(sigma_rule)
        descriptions = [elem for elem in rule if elem.tag == "description"]

        assert len(descriptions) > 0
        assert any("Test Rule" in (desc.text or "") for desc in descriptions)

    def test_add_metadata_omits_wazuh_unsupported_author(self):
        """Author metadata stays out of Wazuh XML because author is not a rule option."""
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = self.get_test_sigma_rule()

        rule = gen.generate(sigma_rule)
        authors = [elem for elem in rule if elem.tag == "author"]

        assert authors == []

    def test_add_metadata_with_tags(self):
        """Sigma tags are emitted as canonical Wazuh groups."""
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = self.get_test_sigma_rule()

        rule = gen.generate(sigma_rule)
        groups = rule.findtext("group", "").split(",")
        assert all(group.startswith("sigma_") for group in groups)

    def test_scalar_sigma_tag_is_one_group_not_characters(self):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = SigmaRule({
            "title": "Scalar Tag Rule",
            "tags": "attack.execution",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "cmd.exe"}},
        })

        rule = gen.generate(sigma_rule)
        groups = rule.findtext("group", "").split(",")

        assert "sigma_attack_execution" in groups
        assert "sigma_a" not in groups

    def test_null_sigma_tags_do_not_break_group_generation(self):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = SigmaRule({
            "title": "Null Tag Rule",
            "tags": None,
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "cmd.exe"}},
        })

        rule = gen.generate(sigma_rule)

        assert rule.findtext("group") == "sigma_null_tag_rule"

    def test_add_detection_fields(self):
        """Test detection field addition."""
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = self.get_test_sigma_rule()

        rule = gen.generate(sigma_rule)
        fields = [elem for elem in rule if elem.tag == "field"]

        assert len(fields) > 0

    def test_numeric_detection_lists_emit_fields(self):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = SigmaRule({
            "title": "Numeric List Rule",
            "logsource": {"service": "security"},
            "detection": {
                "selection": {
                    "EventID": [4624, 4625],
                },
                "condition": "selection",
            },
        })

        rule = gen.generate(sigma_rule)
        event_ids = [field.text for field in rule.findall("field") if field.get("name") == "win.system.eventID"]

        assert event_ids == ["(?:^4624$|^4625$)"]

    def test_null_detection_values_fail_closed_until_exact_lowering_exists(self):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = SigmaRule({
            "title": "Null Detection Rule",
            "logsource": {"service": "sysmon"},
            "detection": {
                "selection": {
                    "Image": None,
                    "CommandLine": ["whoami", None],
                },
                "condition": "selection",
            },
        })

        with pytest.raises(ValueError, match="null checks are not supported"):
            gen.generate(sigma_rule)

    def test_add_group_from_tags(self):
        """Test group generation from tags."""
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        sigma_rule = self.get_test_sigma_rule()

        rule = gen.generate(sigma_rule)
        groups = [elem for elem in rule if elem.tag == "group"]

        assert len(groups) > 0
        assert "attack" in groups[0].text.lower() or "detection" in groups[0].text.lower()

    def test_detection_with_regex_pattern(self):
        """Test detection field with regex pattern."""
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)

        rule_dict = {
            "title": "Regex Test",
            "logsource": {},
            "detection": {
                "selection": {
                    "CommandLine|re": ".*powershell.*"
                }
            },
        }
        sigma_rule = SigmaRule(rule_dict)
        rule = gen.generate(sigma_rule)

        fields = [elem for elem in rule if elem.tag == "field"]
        regex_fields = [f for f in fields if f.get("type") == "pcre2"]

        assert len(regex_fields) > 0

    @pytest.mark.parametrize(
        ("field_name", "value", "expected_pattern"),
        [
            ("CommandLine|contains", "powershell.exe", r"^.*powershell\.exe.*$"),
            ("CommandLine|contains", "CLIENT: 172.25.", r"^.*CLIENT: 172\.25\..*$"),
            ("CommandLine|contains", "CLIENT: <local machine>", r"^.*CLIENT: \x3clocal machine\x3e.*$"),
            ("Image|startswith", r"C:\Windows", r"^C:\\Windows.*$"),
            ("Image|endswith", r"\cmd.exe", r"^.*\\cmd\.exe$"),
            ("Image|contains|endswith", "cmd.exe", r"^.*cmd\.exe.*$"),
            ("CommandLine|contains|windash", " -encode", ".* [-/‐‑‒–—―]encode.*"),
            ("CommandLine|contains|windash", " /create ", ".* [-/‐‑‒–—―]create .*"),
        ],
    )
    def test_detection_string_modifiers_preserve_matching_semantics(self, field_name, value, expected_pattern):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        rule_dict = {
            "title": "Modifier Test",
            "logsource": {},
            "detection": {
                "selection": {
                    field_name: value,
                },
                "condition": "selection",
            },
        }

        rule = gen.generate(SigmaRule(rule_dict))

        field = rule.find("field")
        assert field is not None
        assert field.get("type") == "pcre2"
        if "windash" in field_name:
            assert re.search(field.text, f"powershell.exe {value.strip()} test")
            assert not re.search(field.text, "powershell.exe unrelated test")
            return
        assert field.text == expected_pattern

    def test_unsupported_sigma_modifier_fails_closed(self):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        rule_dict = {
            "title": "Unsupported Modifier",
            "logsource": {},
            "detection": {
                "selection": {
                    "CommandLine|base64": "powershell",
                },
                "condition": "selection",
            },
        }

        with pytest.raises(ValueError, match="unsupported Sigma string modifier"):
            gen.generate(SigmaRule(rule_dict))

    def test_contains_all_sigma_modifier_uses_conjunction_semantics(self):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        rule_dict = {
            "title": "All Modifier",
            "logsource": {},
            "detection": {
                "selection": {
                    "CommandLine|contains|all": ["powershell", "encodedcommand"],
                },
                "condition": "selection",
            },
        }

        rule = gen.generate(SigmaRule(rule_dict))

        field = rule.find("field")
        assert field is not None
        assert field.get("type") == "pcre2"
        assert field.text == r"(?=^.*powershell.*$)(?=^.*encodedcommand.*$).*"
        assert re.search(field.text, "powershell.exe -encodedcommand test")
        assert not re.search(field.text, "powershell.exe")

    def test_all_sigma_modifier_without_contains_fails_closed(self):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        rule_dict = {
            "title": "Bare All Modifier",
            "logsource": {},
            "detection": {
                "selection": {
                    "CommandLine|all": ["powershell", "encodedcommand"],
                },
                "condition": "selection",
            },
        }

        with pytest.raises(ValueError, match="all without contains"):
            gen.generate(SigmaRule(rule_dict))

    def test_windash_with_regex_fails_closed(self):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        rule_dict = {
            "title": "Regex Windash",
            "logsource": {},
            "detection": {
                "selection": {
                    "CommandLine|re|windash": r"\s-enc\s",
                },
                "condition": "selection",
            },
        }

        with pytest.raises(ValueError, match="re, windash"):
            gen.generate(SigmaRule(rule_dict))

    def test_merged_duplicate_fields_scope_leading_regex_flags(self):
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        rule_dict = {
            "title": "Merged Inline Regex Flags",
            "logsource": {
                "product": "windows",
                "category": "process_creation",
            },
            "detection": {
                "selection_literal": {
                    "CommandLine|contains": "--ntlm",
                },
                "selection_regex": {
                    "CommandLine|re": r"(?i)\s(-u|--user)\s*:",
                },
                "condition": "selection_literal or selection_regex",
            },
        }

        rule = gen.generate(SigmaRule(rule_dict))

        field = rule.find("field[@name='win.eventdata.commandLine']")
        assert field is not None
        assert field.text == r"(?:^.*\-\-ntlm.*$|(?i:\s(-u|--user)\s*:))"
        re.compile(field.text)

    def test_rules_exceeding_wazuh_field_limit_fail_closed(self, monkeypatch):
        monkeypatch.setattr(WazuhRuleGenerator, "MAX_FIELD_ELEMENTS", 1)
        id_gen = WazuhRuleIDGenerator()
        gen = WazuhRuleGenerator(id_gen)
        rule_dict = {
            "title": "Too Many Fields",
            "logsource": {"service": "sysmon"},
            "detection": {
                "selection": {
                    "Image": "cmd.exe",
                    "CommandLine": "cmd.exe /c whoami",
                },
                "condition": "selection",
            },
        }

        with pytest.raises(ValueError, match="exceeds supported maximum"):
            gen.generate(SigmaRule(rule_dict))

    def test_converter_records_unsupported_sigma_modifier_as_conversion_error(self):
        converter = SigmaToWazuhConverter()
        rule_dict = {
            "title": "Unsupported Modifier",
            "logsource": {"service": "sysmon"},
            "detection": {
                "selection": {
                    "CommandLine|base64": "powershell",
                },
                "condition": "selection",
            },
        }

        assert converter.convert_rule(SigmaRule(rule_dict, "unsupported.yml")) is None
        assert converter.conversion_error_details == [
            {
                "message": "Error converting Unsupported Modifier: unsupported Sigma string modifier(s): base64",
                "source_file": "unsupported.yml",
                "error_type": "ValueError",
            }
        ]


class TestSigmaToWazuhConverter:
    """Test suite for SigmaToWazuhConverter class."""

    def test_converter_initialization(self):
        """Test converter initialization."""
        converter = SigmaToWazuhConverter()

        assert converter.id_generator is not None
        assert converter.rule_generator is not None
        assert len(converter.converted_rules) == 0
        assert len(converter.conversion_errors) == 0

    def test_converter_custom_start_id(self):
        """Test converter initialization with custom start ID."""
        converter = SigmaToWazuhConverter(start_rule_id=100500)

        assert converter.id_generator.current_id == 100500

    def test_pysigma_parser_is_used_when_available(self, monkeypatch):
        """pySigma is the preferred Sigma parser when its rule module is importable."""
        source_rule = {
            "title": "Original",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "test.exe"}},
        }

        class FakePySigmaRule:
            @classmethod
            def from_dict(cls, rule_dict):
                assert rule_dict == source_rule
                return cls()

            def to_dict(self):
                return source_rule

        monkeypatch.setitem(
            sys.modules,
            "sigma.rule.rule",
            SimpleNamespace(SigmaRule=FakePySigmaRule),
        )

        parsed_rule, backend = parse_sigma_with_pysigma(source_rule)

        assert backend == "pysigma"
        assert parsed_rule == source_rule

    def test_pysigma_parser_requires_pysigma_by_default(self, monkeypatch):
        """Production conversion fails loudly when pySigma is unavailable."""
        monkeypatch.setattr(
            "wazuh_sigma.sigma.PYSIGMA_RULE_MODULE",
            "sigma.not_installed.rule",
        )
        source_rule = {
            "title": "Fallback",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "test.exe"}},
        }

        with pytest.raises(RuntimeError):
            parse_sigma_with_pysigma(source_rule)

    def test_pysigma_parser_fallback_is_explicit_when_unavailable(self, monkeypatch):
        """Loose PyYAML parsing is available only as an explicit migration mode."""
        monkeypatch.setattr(
            "wazuh_sigma.sigma.PYSIGMA_RULE_MODULE",
            "sigma.not_installed.rule",
        )
        source_rule = {
            "title": "Fallback",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "test.exe"}},
        }

        parsed_rule, backend = parse_sigma_with_pysigma(source_rule, allow_pyyaml_fallback=True)

        assert backend == "pyyaml"
        assert parsed_rule == source_rule

    def test_pysigma_parser_rejects_nonstandard_sigma_group_tags(self):
        """Source Sigma must stay standard; sigma_* groups are derived during Wazuh output."""
        source_rule = {
            "title": "Grouped",
            "tags": ["sigma_grouped", "attack.execution"],
            "logsource": {"service": "sysmon"},
            "detection": {
                "selection": {"Image": "test.exe"},
                "condition": "selection",
            },
        }

        with pytest.raises(Exception):
            parse_sigma_with_pysigma(source_rule)

    def test_pysigma_parser_wraps_rule_validation_errors(self, monkeypatch):
        """pySigma rule rejections should cross the boundary as SigmaParseError."""
        source_rule = {
            "title": "Rejected",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "test.exe"}},
        }

        class RejectingPySigmaRule:
            @classmethod
            def from_dict(cls, rule_dict):
                raise SigmaError("invalid sigma rule")

        monkeypatch.setitem(
            sys.modules,
            "sigma.rule.rule",
            SimpleNamespace(SigmaRule=RejectingPySigmaRule),
        )

        with pytest.raises(SigmaParseError, match="invalid sigma rule"):
            parse_sigma_with_pysigma(source_rule)

    def test_pysigma_parser_does_not_hide_programming_errors(self, monkeypatch):
        """Unexpected pySigma adapter bugs should fail loudly."""
        source_rule = {
            "title": "Rejected",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "test.exe"}},
        }

        class BrokenPySigmaRule:
            @classmethod
            def from_dict(cls, rule_dict):
                raise TypeError("pySigma adapter contract changed")

        monkeypatch.setitem(
            sys.modules,
            "sigma.rule.rule",
            SimpleNamespace(SigmaRule=BrokenPySigmaRule),
        )

        with pytest.raises(TypeError, match="adapter contract changed"):
            parse_sigma_with_pysigma(source_rule)

    @pytest.mark.parametrize("yaml_content,should_succeed", [
        # Valid minimal rule
        (
            "title: Test\nlogsource:\n  service: sysmon\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection\n",
            True
        ),
        # Valid complete rule
        (
            "title: Complete\nauthor: Test\nlogsource:\n  service: sysmon\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection\n",
            True
        ),
    ])
    def test_load_sigma_rule_valid(self, yaml_content, should_succeed):
        """Test loading valid Sigma rules from YAML."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            filename = f.name
        try:
            converter = SigmaToWazuhConverter()
            sigma_rule = converter.load_sigma_rule(filename)
            assert (sigma_rule is not None) == should_succeed
            if should_succeed:
                assert sigma_rule.title is not None
        finally:
            os.unlink(filename)

    def test_load_sigma_rule_file_not_found(self):
        """Test loading non-existent file."""
        converter = SigmaToWazuhConverter()
        sigma_rule = converter.load_sigma_rule("/nonexistent/file.yaml")

        assert sigma_rule is None
        assert len(converter.conversion_errors) > 0
        assert "File not found" in converter.conversion_errors[0]

    def test_load_sigma_rule_invalid_yaml(self):
        """Test loading invalid YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [")
            filename = f.name
        try:
            converter = SigmaToWazuhConverter()
            sigma_rule = converter.load_sigma_rule(filename)
            assert sigma_rule is None
            assert len(converter.conversion_errors) > 0
        finally:
            os.unlink(filename)

    def test_load_sigma_rule_empty_file(self):
        """Test loading empty YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")
            filename = f.name
        try:
            converter = SigmaToWazuhConverter()
            sigma_rule = converter.load_sigma_rule(filename)
            assert sigma_rule is None
            assert len(converter.conversion_errors) > 0
        finally:
            os.unlink(filename)

    def test_load_sigma_rule_records_pysigma_rejections(self, monkeypatch, tmp_path):
        """Input-level pySigma failures should be included in conversion reports."""
        source = tmp_path / "rejected.yaml"
        source.write_text(
            "title: Rejected\n"
            "logsource:\n"
            "  service: sysmon\n"
            "detection:\n"
            "  selection:\n"
            "    Image: test.exe\n"
            "  condition: selection\n",
            encoding="utf-8",
        )

        class RejectingPySigmaRule:
            @classmethod
            def from_dict(cls, rule_dict):
                raise SigmaError("invalid sigma rule")

        monkeypatch.setitem(
            sys.modules,
            "sigma.rule.rule",
            SimpleNamespace(SigmaRule=RejectingPySigmaRule),
        )

        converter = SigmaToWazuhConverter()
        sigma_rule = converter.load_sigma_rule(str(source))

        assert sigma_rule is None
        assert converter.conversion_error_details == [{
            "message": f"pySigma error in {source}: invalid sigma rule",
            "source_file": str(source),
            "error_type": "SigmaParseError",
        }]

    def test_load_sigma_rule_unicode_content(self):
        """Test loading YAML with unicode characters."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
            f.write("title: Test Unicode 你好\nauthor: tester\nlogsource:\n  service: sysmon\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection\n")
            filename = f.name

        try:
                converter = SigmaToWazuhConverter()
                sigma_rule = converter.load_sigma_rule(filename)

                assert sigma_rule is not None
                assert "你好" in sigma_rule.title
        finally:
                os.unlink(filename)

    def test_convert_rule_valid(self):
        """Test converting a valid rule."""
        converter = SigmaToWazuhConverter()

        rule_dict = {
            "title": "Test Rule",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "test.exe"}},
        }
        sigma_rule = SigmaRule(rule_dict)

        xml_rule = converter.convert_rule(sigma_rule)

        assert xml_rule is not None
        assert xml_rule.tag == "rule"
        assert len(converter.converted_rules) == 1

    def test_convert_rule_invalid(self):
        """Test converting an invalid rule."""
        converter = SigmaToWazuhConverter()

        rule_dict = {
            "title": "",
            "logsource": {},
            "detection": {},
        }
        sigma_rule = SigmaRule(rule_dict)

        xml_rule = converter.convert_rule(sigma_rule)

        assert xml_rule is None
        assert len(converter.conversion_errors) > 0

    def test_convert_rule_does_not_hide_programming_errors(self, monkeypatch):
        """Unexpected backend bugs must fail loudly instead of looking like bad rules."""
        converter = SigmaToWazuhConverter()
        sigma_rule = SigmaRule({
            "title": "Valid",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "test.exe"}},
        })

        def raise_type_error(rule, *, level_override=None):
            raise TypeError("backend contract changed")

        monkeypatch.setattr(converter.backend, "convert_rules", raise_type_error)

        with pytest.raises(TypeError, match="backend contract changed"):
            converter.convert_rule(sigma_rule)

        assert converter.conversion_errors == []

    def test_convert_file(self):
        """Test converting a file in one step."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("title: Test\nlogsource:\n  service: sysmon\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection\n")
            filename = f.name
        try:
            converter = SigmaToWazuhConverter()
            xml_rule = converter.convert_file(filename)
            assert xml_rule is not None
            assert xml_rule.tag == "rule"
        finally:
            os.unlink(filename)

    def test_convert_directory(self):
        """Test converting all YAML files in a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple test files
            for i in range(3):
                with open(f"{tmpdir}/rule{i}.yaml", 'w') as f:
                    f.write(f"title: Test{i}\nlogsource:\n  service: sysmon\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection\n")

            converter = SigmaToWazuhConverter()
            rules = converter.convert_directory(tmpdir)

            assert len(rules) == 3

    def test_convert_directory_nonexistent(self):
        """Test converting non-existent directory."""
        converter = SigmaToWazuhConverter()
        rules = converter.convert_directory("/nonexistent/directory")

        assert len(rules) == 0
        assert len(converter.conversion_errors) > 0

    def test_convert_directory_mixed_results(self):
        """Test converting directory with valid and invalid files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Valid file
            with open(f"{tmpdir}/valid.yaml", 'w') as f:
                f.write("title: Valid\nlogsource:\n  service: sysmon\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection\n")

            # Invalid file
            with open(f"{tmpdir}/invalid.yaml", 'w') as f:
                f.write("invalid: yaml: [")

            converter = SigmaToWazuhConverter()
            rules = converter.convert_directory(tmpdir)

            assert len(rules) == 1  # Only valid file
            assert len(converter.conversion_errors) > 0  # Has errors from invalid file
            report = converter.generate_report()
            assert report["total_discovered"] == 2
            assert report["total_failed_files"] == 1
            assert report["source_files"] == [
                str(Path(tmpdir) / "invalid.yaml"),
                str(Path(tmpdir) / "valid.yaml"),
            ]
            assert report["failed_files"] == [str(Path(tmpdir) / "invalid.yaml")]

    def test_generate_xml_output_basic(self):
        """Test XML output generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = f"{tmpdir}/output.xml"

            # Create test rules
            id_gen = WazuhRuleIDGenerator()
            rule_gen = WazuhRuleGenerator(id_gen)
            rule_dict = {
                "title": "Test",
                "logsource": {"service": "sysmon"},
                "detection": {"selection": {"Image": "test.exe"}},
            }
            sigma_rule = SigmaRule(rule_dict)
            rule = rule_gen.generate(sigma_rule)

            # Generate output
            converter = SigmaToWazuhConverter()
            success = converter.generate_xml_output([rule], output_file)

            assert success is True
            assert os.path.exists(output_file)

            # Verify XML structure
            tree = ET.parse(output_file)
            root = tree.getroot()
            assert root.tag == "group"

    def test_generate_xml_output_multiple_rules(self):
        """Test XML output with multiple rules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = f"{tmpdir}/output.xml"

            # Create multiple rules
            id_gen = WazuhRuleIDGenerator()
            rule_gen = WazuhRuleGenerator(id_gen)
            rules = []
            for i in range(3):
                rule_dict = {
                    "title": f"Test{i}",
                    "logsource": {"service": "sysmon"},
                    "detection": {"selection": {"Image": "test.exe"}},
                }
                sigma_rule = SigmaRule(rule_dict)
                rules.append(rule_gen.generate(sigma_rule))

            converter = SigmaToWazuhConverter()
            success = converter.generate_xml_output(rules, output_file)

            assert success is True

            # Verify XML contains all rules
            tree = ET.parse(output_file)
            root = tree.getroot()
            rule_elements = [elem for elem in root if elem.tag == "rule"]
            assert len(rule_elements) == 3

    def test_generate_xml_output_creates_parent_path(self, tmp_path):
        """XML generation creates missing output directories."""
        converter = SigmaToWazuhConverter()
        id_gen = WazuhRuleIDGenerator()
        rule_gen = WazuhRuleGenerator(id_gen)
        rule_dict = {
            "title": "Test",
            "logsource": {},
            "detection": {"selection": {"Image": "test.exe"}},
        }
        sigma_rule = SigmaRule(rule_dict)
        rule = rule_gen.generate(sigma_rule)

        output = tmp_path / "missing" / "nested" / "file.xml"
        success = converter.generate_xml_output([rule], str(output))
        assert success is True
        assert output.exists()

    def test_generate_xml_output_preserves_existing_file_on_write_failure(self, monkeypatch, tmp_path):
        """XML generation should not corrupt the previous artifact if writing fails."""
        converter = SigmaToWazuhConverter()
        output = tmp_path / "sigma_rules.xml"
        output.write_text("<previous />", encoding="utf-8")

        def fail_write(path, content):
            raise OSError("disk full")

        monkeypatch.setattr("wazuh_sigma.converter.service.write_text_artifact", fail_write)

        success = converter.generate_xml_output([], str(output))

        assert success is False
        assert output.read_text(encoding="utf-8") == "<previous />"
        assert "XML generation error: disk full" in converter.conversion_errors

    def test_generate_xml_output_does_not_hide_rendering_bugs(self, monkeypatch, tmp_path):
        """Unexpected renderer failures should propagate as implementation defects."""
        converter = SigmaToWazuhConverter()

        def raise_type_error(rules):
            raise TypeError("renderer contract changed")

        monkeypatch.setattr(converter.backend, "render_ruleset", raise_type_error)

        with pytest.raises(TypeError, match="renderer contract changed"):
            converter.generate_xml_output([], str(tmp_path / "rules.xml"))

        assert converter.conversion_errors == []

    def test_generate_report(self):
        """Test report generation."""
        converter = SigmaToWazuhConverter()

        # Convert a rule to populate report data
        rule_dict = {
            "title": "Test",
            "logsource": {"service": "sysmon"},
            "detection": {"selection": {"Image": "test.exe"}},
        }
        sigma_rule = SigmaRule(rule_dict)
        converter.convert_rule(sigma_rule)

        report = converter.generate_report()

        assert "timestamp" in report
        assert datetime.fromisoformat(report["timestamp"]).tzinfo is not None
        assert "total_converted" in report
        assert "total_errors" in report
        assert "parser_backends" in report
        assert "total_discovered" in report
        assert "total_failed_files" in report
        assert "source_files" in report
        assert "failed_files" in report
        assert "converted_rules" in report
        assert "errors" in report
        assert "error_details" in report
        assert report["total_converted"] == 1
        assert report["total_discovered"] == 0
        assert report["total_failed_files"] == 0

    def test_generate_report_normalizes_injected_naive_timestamp_to_utc(self):
        state = ConversionState()

        report = state.as_report(
            backend=WazuhBackend(),
            generated_at=datetime(2026, 7, 12, 10, 30),
        )

        assert report["timestamp"] == "2026-07-12T10:30:00+00:00"

    def test_generate_report_with_errors(self):
        """Test report includes conversion errors."""
        converter = SigmaToWazuhConverter()

        # Try to load non-existent file
        converter.load_sigma_rule("/nonexistent/file.yaml")

        report = converter.generate_report()

        assert report["total_errors"] == 1
        assert report["total_discovered"] == 1
        assert report["total_failed_files"] == 1
        assert report["failed_files"] == ["/nonexistent/file.yaml"]
        assert len(report["errors"]) > 0
        assert report["error_details"] == [
            {
                "message": "File not found: /nonexistent/file.yaml",
                "source_file": "/nonexistent/file.yaml",
                "error_type": "FileNotFoundError",
            }
        ]

    def test_generate_report_returns_state_snapshot(self):
        """Report callers should not mutate converter telemetry by accident."""
        converter = SigmaToWazuhConverter()
        converter._record_error("bad rule", source_file="rule.yaml", error_type="BadRuleError")

        report = converter.generate_report()
        report["source_files"].append("mutated.yaml")
        report["failed_files"].clear()
        report["errors"].clear()
        report["error_details"][0]["message"] = "mutated"

        assert converter.source_files == []
        assert converter.failed_files == ["rule.yaml"]
        assert converter.conversion_errors == ["bad rule"]
        assert converter.conversion_error_details == [
            {
                "message": "bad rule",
                "source_file": "rule.yaml",
                "error_type": "BadRuleError",
            }
        ]


class TestConversionState:
    """Test conversion telemetry state independently from conversion logic."""

    def test_records_unique_sources_and_failures(self):
        state = ConversionState()

        state.record_source_file("one.yaml")
        state.record_source_file("one.yaml")
        state.record_error("first failure", source_file="one.yaml", error_type="FirstError")
        state.record_error("second failure", source_file="one.yaml", error_type="SecondError")

        assert state.source_files == ["one.yaml"]
        assert state.failed_files == ["one.yaml"]
        assert state.conversion_errors == ["first failure", "second failure"]
        assert state.conversion_error_details == [
            {
                "message": "first failure",
                "source_file": "one.yaml",
                "error_type": "FirstError",
            },
            {
                "message": "second failure",
                "source_file": "one.yaml",
                "error_type": "SecondError",
            },
        ]


class TestSigmaConverterIntegration:
    """Integration tests for the complete conversion pipeline."""

    def test_cli_creates_report_parent_directory(self, tmp_path, monkeypatch):
        """CLI creates missing directories for XML and JSON outputs."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "simple.yml").write_text(
            """
title: Simple CLI Rule
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: cmd.exe
  condition: selection
""",
            encoding="utf-8",
        )
        output = tmp_path / "generated" / "rules.xml"
        report = tmp_path / "reports" / "conversion.json"
        assert cli(
            [
                "-d",
                str(rules_dir),
                "-o",
                str(output),
                "-r",
                str(report),
            ]
        ) == 0
        assert output.exists()
        assert report.exists()

    def test_full_conversion_pipeline(self):
        """Test complete conversion pipeline from YAML to XML."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create input YAML file
            yaml_file = f"{tmpdir}/test_rule.yaml"
            with open(yaml_file, 'w') as f:
                f.write("""
title: Test Process Execution Rule
description: Detects execution of suspicious processes
author: Test Author
level: high
tags:
  - attack.t1234
  - test.detection
logsource:
  service: sysmon
  product: windows
detection:
  selection:
    EventID: 1
    Image: cmd.exe
    CommandLine:
      - '*.txt'
      - 'powershell*'
  condition: selection
references:
  - https://example.com
""")

            # Convert
            output_file = f"{tmpdir}/output.xml"
            converter = SigmaToWazuhConverter()

            sigma_rule = converter.load_sigma_rule(yaml_file)
            assert sigma_rule is not None

            xml_rule = converter.convert_rule(sigma_rule)
            assert xml_rule is not None

            success = converter.generate_xml_output([xml_rule], output_file)
            assert success is True

            # Verify output
            assert os.path.exists(output_file)
            tree = ET.parse(output_file)
            root = tree.getroot()
            assert root.tag == "group"

    def test_batch_conversion_with_errors(self):
        """Test batch conversion handling mixed valid/invalid files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Valid rule
            with open(f"{tmpdir}/valid.yaml", 'w') as f:
                f.write("title: Valid\nlogsource:\n  service: sysmon\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection\n")

            # Invalid YAML
            with open(f"{tmpdir}/invalid_yaml.yaml", 'w') as f:
                f.write("title: Invalid\ninvalid: [yaml")

            # Missing required fields
            with open(f"{tmpdir}/incomplete.yaml", 'w') as f:
                f.write("title: Missing Fields\n")

            converter = SigmaToWazuhConverter()
            rules = converter.convert_directory(tmpdir)
            report = converter.generate_report()

            assert report["total_converted"] >= 1
            assert report["total_errors"] > 0
            assert report["total_discovered"] == 3
            assert report["total_failed_files"] == 2
            assert report["failed_files"] == [
                str(Path(tmpdir) / "incomplete.yaml"),
                str(Path(tmpdir) / "invalid_yaml.yaml"),
            ]

    def test_special_characters_in_detection(self):
        """Test handling special characters in detection values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_file = f"{tmpdir}/special_chars.yaml"
            with open(yaml_file, 'w', encoding='utf-8') as f:
                f.write("""
title: Special Characters Test
logsource:
  service: sysmon
detection:
  selection:
    Image: C:\\Program Files\\test.exe
    CommandLine: 'cmd.exe /c "echo test"'
    Domain: 你好世界
  condition: selection
""")

            converter = SigmaToWazuhConverter()
            sigma_rule = converter.load_sigma_rule(yaml_file)

            assert sigma_rule is not None
            assert "你好世界" in sigma_rule.detection.get("selection", {}).get("Domain", "")

    def test_deeply_nested_detection_structure(self):
        """Test handling deeply nested detection structures."""
        rule_dict = {
            "title": "Nested Detection",
            "logsource": {"service": "sysmon"},
            "detection": {
                "selection_parent": {
                    "ParentImage": "explorer.exe"
                },
                "selection_child": {
                    "Image": {
                        "nested_field": "value1"
                    }
                },
                "filter": {
                    "CommandLine": "test"
                },
                "condition": "selection_parent and selection_child"
            },
        }

        sigma_rule = SigmaRule(rule_dict)
        assert sigma_rule.title == "Nested Detection"

        converter = SigmaToWazuhConverter()
        xml_rule = converter.convert_rule(sigma_rule)

        assert xml_rule is None
        assert "Unsupported type" in converter.conversion_errors[-1]


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_very_large_rule_id(self):
        """Test handling very large rule IDs."""
        gen = WazuhRuleIDGenerator(start_id=999999999, end_id=999999999)
        id1 = gen.generate_id()

        assert id1 == 999999999

    def test_rule_with_empty_strings(self):
        """Test rule with empty string values."""
        rule_dict = {
            "title": "Test",
            "description": "",
            "author": "",
            "logsource": {"service": ""},
            "detection": {
                "selection": {
                    "Image": "",
                    "CommandLine": ["", "value"]
                }
            },
        }

        sigma_rule = SigmaRule(rule_dict)
        assert sigma_rule.title == "Test"

    def test_rule_with_null_values(self):
        """Test rule with None/null values."""
        rule_dict = {
            "title": "Test",
            "description": None,
            "author": None,
            "logsource": None,
            "detection": None,
        }

        sigma_rule = SigmaRule(rule_dict)
        assert sigma_rule.title == "Test"

    def test_extremely_long_field_value(self):
        """Test handling extremely long field values."""
        long_value = "A" * 10000
        rule_dict = {
            "title": "Long Value Test",
            "logsource": {"service": "sysmon"},
            "detection": {
                "CommandLine": long_value
            },
        }

        sigma_rule = SigmaRule(rule_dict)
        keywords = sigma_rule.get_detection_keywords()

        assert long_value in keywords

    def test_regex_pattern_with_special_chars(self):
        """Test regex patterns with complex special characters."""
        pattern = r"^C:\\Users\\.*\\AppData\\.*\.exe$"

        assert SigmaFieldMapper.is_regex(pattern) is True

    def test_field_mapper_with_consecutive_spaces(self):
        """Test field mapping with multiple consecutive spaces."""
        mapped = SigmaFieldMapper.map_field("Field  With   Spaces")

        assert "field" in mapped.lower()
