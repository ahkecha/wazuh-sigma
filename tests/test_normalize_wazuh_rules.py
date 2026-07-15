"""Tests for Wazuh native-parser compatibility normalization."""

import xml.etree.ElementTree as ET

from scripts.normalize_wazuh_rules import (
    chunk_alternatives,
    normalize_directory,
    normalize_native_ip_fields,
    prune_unavailable_dependencies,
    normalize_static_fields,
    write_xml_tree,
)


def test_chunk_alternatives_preserves_all_values():
    chunks = chunk_alternatives("alpha|beta|gamma", 10)

    assert chunks == ["alpha|beta", "gamma"]


def test_normalizer_expands_oversized_rule_with_unique_ids(tmp_path):
    rules = tmp_path / "rules.xml"
    rules.write_text(
        '<group name="sigma,"><rule id="900000" level="10">'
        '<field name="value" type="pcre2">alpha|beta|gamma</field>'
        '<description>test</description></rule></group>',
        encoding="utf-8",
    )

    report = normalize_directory(tmp_path, maximum=10)
    content = rules.read_text(encoding="utf-8")

    assert report["final_rules"] == 2
    assert 'id="900000"' in content
    assert 'id="900001"' in content
    assert "<?xml" not in content


def test_static_field_is_converted_to_native_wazuh_element():
    rule = ET.fromstring(
        '<rule id="900000" level="10">'
        '<field name="action" type="pcre2">(?i)blocked</field>'
        '<description>test</description></rule>'
    )

    assert normalize_static_fields(rule) == 1
    action = rule.find("action")
    assert action is not None
    assert action.get("type") == "pcre2"
    assert action.text == "(?i)blocked"


def test_unavailable_if_sid_values_are_pruned():
    rule = ET.fromstring(
        '<rule id="900000" level="10">'
        "<if_sid>100, 200, 300</if_sid>"
        "<description>test</description></rule>"
    )

    missing_sids, removed_sids, missing_groups, removed_groups = prune_unavailable_dependencies(
        rule, {100, 300}, set()
    )

    assert missing_sids == 1
    assert removed_sids == 0
    assert missing_groups == 0
    assert removed_groups == 0
    assert rule.find("if_sid").text == "100, 300"


def test_unavailable_if_group_element_is_removed():
    rule = ET.fromstring(
        '<rule id="900000" level="10">'
        "<if_group>missing_group</if_group>"
        "<description>test</description></rule>"
    )

    missing_sids, removed_sids, missing_groups, removed_groups = prune_unavailable_dependencies(
        rule, set(), {"existing_group"}
    )

    assert missing_sids == 0
    assert removed_sids == 0
    assert missing_groups == 1
    assert removed_groups == 1
    assert rule.find("if_group") is None


def test_native_ip_field_cleanup_removes_regex_syntax():
    private_cidr = ".".join(("10", "0", "0", "0")) + "/8"
    rule = ET.fromstring(
        '<rule id="900000" level="10">'
        f'<dstip negate="yes" type="pcre2">(?i){private_cidr}</dstip>'
        "<description>test</description></rule>"
    )

    assert normalize_native_ip_fields(rule) == 1
    dstip = rule.find("dstip")
    assert dstip.text == private_cidr
    assert dstip.get("type") is None
    assert dstip.get("negate") == "yes"


def test_normalizer_xml_write_preserves_existing_file_when_replace_fails(monkeypatch, tmp_path):
    rules = tmp_path / "rules.xml"
    rules.write_text("<previous />", encoding="utf-8")
    tree = ET.ElementTree(ET.fromstring("<group />"))

    def fail_replace(self, target):
        raise OSError("replace failed")

    monkeypatch.setattr("pathlib.Path.replace", fail_replace)

    try:
        write_xml_tree(rules, tree)
    except OSError as error:
        assert str(error) == "replace failed"
    else:
        raise AssertionError("expected replace failure")

    assert rules.read_text(encoding="utf-8") == "<previous />"
    assert list(tmp_path.glob(".rules.xml.*.tmp")) == []
