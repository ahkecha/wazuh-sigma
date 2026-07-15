"""Normalize generated Wazuh XML for the native Wazuh 4.x parser.

The Wazuh XML parser does not accept XML declarations in custom rule files and
has a bounded text buffer. Large Sigma value lists therefore need to become
multiple equivalent Wazuh rules instead of one oversized PCRE2 alternation.
"""

from __future__ import annotations

import argparse
import copy
import itertools
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from pathlib import Path

from wazuh_sigma.reporting import write_json_report, write_text_artifact


DEFAULT_MAX_PATTERN_LENGTH = 1800
STATIC_FIELDS = {
    "action",
    "dstip",
    "dstport",
    "extra_data",
    "hostname",
    "id",
    "location",
    "program_name",
    "protocol",
    "srcip",
    "srcport",
    "status",
    "system_name",
    "url",
    "user",
}
NATIVE_IP_FIELDS = {"srcip", "dstip"}


def split_top_level_alternatives(pattern: str) -> list[str]:
    """Split unescaped regex alternations outside groups and character classes."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    escaped = False
    in_class = False

    for char in pattern:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == "[" and not in_class:
            in_class = True
        elif char == "]" and in_class:
            in_class = False
        elif not in_class and char == "(":
            depth += 1
        elif not in_class and char == ")" and depth:
            depth -= 1
        if char == "|" and not in_class and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)

    parts.append("".join(current))
    return parts


def chunk_alternatives(pattern: str, maximum: int) -> list[str]:
    """Pack top-level alternatives into patterns no longer than ``maximum``."""
    alternatives = split_top_level_alternatives(pattern)
    if any(len(item) > maximum for item in alternatives):
        longest = max(len(item) for item in alternatives)
        raise ValueError(f"single regex alternative is too long ({longest} > {maximum})")

    chunks: list[str] = []
    current = ""
    for alternative in alternatives:
        candidate = alternative if not current else f"{current}|{alternative}"
        if len(candidate) <= maximum:
            current = candidate
        else:
            chunks.append(current)
            current = alternative
    if current:
        chunks.append(current)
    return chunks


def _xml_parser() -> ET.XMLParser:
    return ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))


def _parse_wazuh_fragment(path: Path) -> ET.Element:
    text = path.read_text(encoding="utf-8")
    if text.lstrip().startswith("<?xml"):
        text = text.split("?>", 1)[1]
    try:
        return ET.fromstring(f"<wazuh_rules>{text}</wazuh_rules>", parser=_xml_parser())
    except ET.ParseError as error:
        raise ET.ParseError(f"{path}: {error}") from error


def write_xml_tree(path: Path, tree: ET.ElementTree) -> None:
    """Atomically write a normalized XML tree without an XML declaration."""
    write_text_artifact(path, ET.tostring(tree.getroot(), encoding="unicode", short_empty_elements=True))


def normalize_static_fields(rule: ET.Element) -> int:
    """Use native Wazuh elements for fields that are not dynamic fields."""
    replaced = 0
    for position, field in enumerate(list(rule)):
        if field.tag != "field" or field.get("name") not in STATIC_FIELDS:
            continue
        native = ET.Element(field.get("name", ""))
        native.text = field.text
        for name, value in field.attrib.items():
            if name != "name":
                native.set(name, value)
        rule.remove(field)
        rule.insert(position, native)
        replaced += 1
    return replaced


def _clean_native_ip_value(value: str) -> str:
    cleaned = value.strip()
    if cleaned.startswith("(?i)"):
        cleaned = cleaned[4:]
    if cleaned.startswith("^") and cleaned.endswith("$"):
        cleaned = cleaned[1:-1]
    return cleaned.replace(r"\.", ".")


def normalize_native_ip_fields(rule: ET.Element) -> int:
    """Convert regex-looking srcip/dstip values into native Wazuh IP/CIDR values."""
    cleaned = 0
    for element in rule:
        if element.tag not in NATIVE_IP_FIELDS:
            continue
        original_text = element.text or ""
        original_type = element.get("type")
        element.text = _clean_native_ip_value(original_text)
        element.attrib.pop("type", None)
        if element.text != original_text or original_type is not None:
            cleaned += 1
    return cleaned


def _iter_xml_files(directories: Iterable[Path]) -> Iterable[Path]:
    for directory in directories:
        if directory.exists():
            yield from sorted(directory.glob("*.xml"))


def collect_rule_ids_and_groups(directories: Iterable[Path]) -> tuple[set[int], set[str]]:
    """Collect Wazuh rule IDs and group names from rule XML directories."""
    rule_ids: set[int] = set()
    groups: set[str] = set()
    for path in _iter_xml_files(directories):
        text = path.read_text(encoding="utf-8", errors="replace")
        text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
        rule_ids.update(int(rule_id) for rule_id in re.findall(r"<rule\s+[^>]*id=\"(\d+)\"", text))
        for group_names in re.findall(r"<group\s+[^>]*name=\"([^\"]+)\"", text):
            groups.update(group.strip() for group in group_names.split(",") if group.strip())
        for group_text in re.findall(r"<group>([^<]+)</group>", text):
            groups.update(group.strip() for group in group_text.split(",") if group.strip())
    return rule_ids, groups


def prune_unavailable_dependencies(
    rule: ET.Element,
    available_rule_ids: set[int],
    available_groups: set[str],
) -> tuple[int, int, int, int]:
    """Remove if_sid/if_group values that are unavailable in the target Wazuh ruleset."""
    missing_sids = 0
    removed_if_sid_elements = 0
    missing_groups = 0
    removed_if_group_elements = 0

    for if_sid in list(rule.findall("if_sid")):
        values = [item.strip() for item in (if_sid.text or "").split(",") if item.strip()]
        kept: list[str] = []
        for value in values:
            try:
                rule_id = int(value)
            except ValueError:
                missing_sids += 1
                continue
            if rule_id in available_rule_ids:
                kept.append(value)
            else:
                missing_sids += 1
        if kept:
            if_sid.text = ", ".join(kept)
        else:
            rule.remove(if_sid)
            removed_if_sid_elements += 1

    for if_group in list(rule.findall("if_group")):
        values = [item.strip() for item in (if_group.text or "").split(",") if item.strip()]
        kept = [value for value in values if value in available_groups]
        missing_groups += len(values) - len(kept)
        if kept:
            if_group.text = ", ".join(kept)
        else:
            rule.remove(if_group)
            removed_if_group_elements += 1

    return missing_sids, removed_if_sid_elements, missing_groups, removed_if_group_elements


def normalize_directory(
    directory: Path,
    maximum: int = DEFAULT_MAX_PATTERN_LENGTH,
    target_rules_dirs: Iterable[Path] = (),
) -> dict:
    """Normalize every XML rule file in ``directory`` and return a report."""
    paths = sorted(directory.glob("*.xml"))
    if not paths:
        raise ValueError(f"no XML files found in {directory}")

    trees: list[tuple[Path, ET.ElementTree]] = []
    all_ids: set[int] = set()
    for path in paths:
        tree = ET.parse(path, parser=_xml_parser())
        trees.append((path, tree))
        for rule in tree.getroot().findall("rule"):
            rule_id = int(rule.attrib["id"])
            if rule_id in all_ids:
                raise ValueError(f"duplicate rule ID before normalization: {rule_id}")
            all_ids.add(rule_id)

    target_rule_ids, target_groups = collect_rule_ids_and_groups(target_rules_dirs)
    available_rule_ids = target_rule_ids | all_ids

    next_id = max(all_ids) + 1
    split_source_rules = 0
    added_rules = 0
    split_fields = 0
    static_fields_replaced = 0
    native_ip_fields_cleaned = 0
    pruned_if_sid_values = 0
    removed_if_sid_elements = 0
    pruned_if_group_values = 0
    removed_if_group_elements = 0

    for path, tree in trees:
        root = tree.getroot()
        normalized_children: list[ET.Element] = []
        for child in list(root):
            if child.tag != "rule":
                normalized_children.append(child)
                continue

            static_fields_replaced += normalize_static_fields(child)
            native_ip_fields_cleaned += normalize_native_ip_fields(child)
            pruned = prune_unavailable_dependencies(child, available_rule_ids, target_groups)
            pruned_if_sid_values += pruned[0]
            removed_if_sid_elements += pruned[1]
            pruned_if_group_values += pruned[2]
            removed_if_group_elements += pruned[3]

            oversized: list[tuple[int, list[str]]] = []
            fields = child.findall("field")
            for index, field in enumerate(fields):
                text = field.text or ""
                if len(text) > maximum:
                    oversized.append((index, chunk_alternatives(text, maximum)))

            if not oversized:
                normalized_children.append(child)
                continue

            split_source_rules += 1
            split_fields += len(oversized)
            variants = itertools.product(*(chunks for _, chunks in oversized))
            for variant_index, values in enumerate(variants):
                clone = copy.deepcopy(child)
                clone_fields = clone.findall("field")
                for (field_index, _), value in zip(oversized, values):
                    clone_fields[field_index].text = value
                if variant_index:
                    clone.set("id", str(next_id))
                    all_ids.add(next_id)
                    next_id += 1
                    added_rules += 1
                normalized_children.append(clone)

        root[:] = normalized_children
        ET.indent(tree, space="    ")
        write_xml_tree(path, tree)

    report = {
        "files": len(paths),
        "original_rules": len(all_ids) - added_rules,
        "final_rules": len(all_ids),
        "split_source_rules": split_source_rules,
        "split_fields": split_fields,
        "added_rules": added_rules,
        "static_fields_replaced": static_fields_replaced,
        "native_ip_fields_cleaned": native_ip_fields_cleaned,
        "target_rule_ids": len(target_rule_ids),
        "target_groups": len(target_groups),
        "pruned_if_sid_values": pruned_if_sid_values,
        "removed_if_sid_elements": removed_if_sid_elements,
        "pruned_if_group_values": pruned_if_group_values,
        "removed_if_group_elements": removed_if_group_elements,
        "maximum_pattern_length": maximum,
        "max_rule_id": max(all_ids),
    }
    write_json_report(directory / "normalization-report.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--max-pattern-length", type=int, default=DEFAULT_MAX_PATTERN_LENGTH)
    parser.add_argument(
        "--target-rules-dir",
        action="append",
        default=[],
        type=Path,
        help="Directory containing Wazuh target rule XML used to prune unavailable if_sid/if_group values.",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            normalize_directory(args.directory, args.max_pattern_length, args.target_rules_dir),
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
