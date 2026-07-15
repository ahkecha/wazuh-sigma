"""End-to-end tests for the production converter path."""

import xml.etree.ElementTree as ET

import yaml
from wazuh_sigma.converter.service import SigmaToWazuhConverter
from wazuh_sigma.naming import sigma_group_name


def _write_safe_examples(tmp_path):
    rules_dir = tmp_path / "safe_sigma"
    rules_dir.mkdir()
    (rules_dir / "process.yml").write_text(
        """
title: Safe Process Example
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith: '\\cmd.exe'
  selection_cli:
    CommandLine|contains: whoami
  condition: selection_img and selection_cli
tags:
  - attack.execution
""",
        encoding="utf-8",
    )
    (rules_dir / "network.yml").write_text(
        """
title: Safe Network Example
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationPort:
      - 4444
      - 5555
  condition: selection
tags:
  - attack.command-and-control
""",
        encoding="utf-8",
    )
    return rules_dir


def test_examples_preserve_not_filters_and_fail_closed_only_on_limits():
    converter = SigmaToWazuhConverter()
    rules = converter.convert_directory("examples/sigma")

    assert len(rules) == 50
    assert len(converter.conversion_error_details) == 1
    assert "generated child rules 88 exceeds configured maximum 64" in converter.conversion_error_details[0]["message"]


def test_safe_examples_convert_validate_and_use_canonical_groups(tmp_path):
    converter = SigmaToWazuhConverter()
    rules = converter.convert_directory(str(_write_safe_examples(tmp_path)))
    output = tmp_path / "nested" / "sigma_rules.xml"

    assert len(rules) == 2
    assert converter.parser_backends == {"pysigma"}
    assert converter.generate_xml_output(rules, str(output))

    root = ET.parse(output).getroot()
    assert root.tag == "group"
    assert root.get("name") == "sigma_rules,"
    for rule in root.findall("rule"):
        groups = rule.findtext("group", "").split(",")
        assert groups
        assert all(group.startswith("sigma_") for group in groups)
        assert rule.find("tag") is None


def test_sigma_modifiers_are_not_part_of_wazuh_field_names(tmp_path):
    converter = SigmaToWazuhConverter()
    assert converter.convert_file("examples/sigma/process_creation_cmd_execution.yml") is None
    assert "generated child rules 88 exceeds configured maximum 64" in converter.conversion_errors[-1]

    safe_dir = _write_safe_examples(tmp_path)
    rule = converter.convert_file(str(safe_dir / "process.yml"))

    assert rule is not None
    names = {field.get("name") for field in rule.findall("field")}
    assert "win.eventdata.image" in names
    assert "win.eventdata.commandLine" in names
    assert not any("|" in name for name in names if name)


def test_example_rules_use_standard_sigma_tags_only():
    for path in ("examples/sigma/process_creation_cmd_execution.yml", "examples/sigma/network_connection_suspicious_ports.yml"):
        with open(path, encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
        assert all("." in tag for tag in document["tags"])
        assert not any(tag.startswith("sigma_") for tag in document["tags"])


def test_canonical_group_naming_is_idempotent():
    assert sigma_group_name("Suspicious PowerShell") == "sigma_suspicious_powershell"
    assert sigma_group_name("sigma_suspicious_powershell") == "sigma_suspicious_powershell"
