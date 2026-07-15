import xml.etree.ElementTree as ET

from wazuh_sigma.backend.wazuh import WazuhBackend
from wazuh_sigma.ruleset_chunks import split_rules_evenly, write_ruleset_chunks


def _rule(rule_id: int) -> ET.Element:
    element = ET.Element("rule", id=str(rule_id), level="10")
    ET.SubElement(element, "description").text = f"rule {rule_id}"
    ET.SubElement(element, "group").text = "sigma_test"
    return element


def test_split_rules_evenly_balances_four_default_chunks():
    chunks = split_rules_evenly([_rule(rule_id) for rule_id in range(10)], 4)

    assert [len(chunk) for chunk in chunks] == [3, 3, 2, 2]


def test_write_ruleset_chunks_writes_manifest_and_xml_files(tmp_path):
    output_file = tmp_path / "sigma_rules.xml"
    rules = [_rule(rule_id) for rule_id in range(900000, 900005)]

    manifest = write_ruleset_chunks(
        backend=WazuhBackend(),
        rules=rules,
        output_file=output_file,
        chunk_count=4,
    )

    assert manifest.chunk_count == 4
    assert manifest.rules_per_chunk == [2, 1, 1, 1]
    assert (tmp_path / "chunks" / "manifest.json").is_file()
    for path in manifest.files:
        content = path.read_text(encoding="utf-8")
        assert content.startswith('<group name="sigma_rules,">')
        assert "<?xml" not in content
        assert "<rule " in content
