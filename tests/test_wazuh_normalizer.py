"""Tests for native-Wazuh XML normalization."""

import xml.etree.ElementTree as ET

from scripts.normalize_wazuh_rules import (
    chunk_alternatives,
    normalize_directory,
    split_top_level_alternatives,
)


def test_top_level_split_preserves_escaped_and_grouped_pipes():
    pattern = r"one\|literal|(?:two|three)|[a|b]|four"
    assert split_top_level_alternatives(pattern) == [
        r"one\|literal",
        r"(?:two|three)",
        r"[a|b]",
        "four",
    ]


def test_chunk_alternatives_respects_limit():
    chunks = chunk_alternatives("a" * 10 + "|" + "b" * 10 + "|" + "c" * 10, 21)
    assert chunks == ["a" * 10 + "|" + "b" * 10, "c" * 10]


def test_normalize_clones_oversized_rule_and_removes_declaration(tmp_path):
    path = tmp_path / "rules.xml"
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<group name="sigma,"><rule id="900000" level="10">'
        '<field name="value" type="pcre2">aaaa|bbbb|cccc</field>'
        '<description>test</description></rule></group>',
        encoding="utf-8",
    )

    report = normalize_directory(tmp_path, maximum=9)

    content = path.read_text(encoding="utf-8")
    tree = ET.parse(path)
    rules = tree.getroot().findall("rule")
    assert not content.startswith("<?xml")
    assert [rule.get("id") for rule in rules] == ["900000", "900001"]
    assert [rule.findtext("field") for rule in rules] == ["aaaa|bbbb", "cccc"]
    assert report["added_rules"] == 1
