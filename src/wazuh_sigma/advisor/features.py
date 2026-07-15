"""Pure, deterministic feature extraction from normalized Sigma rules.

No network calls, no filesystem access, no global mutable state. Given the
same normalized :class:`~wazuh_sigma.sigma.SigmaRule`, :func:`extract_features`
always returns an identical :class:`SigmaFeatureSet`. This is what gets
sanitized and (optionally) sent to an advisor provider — never the raw
Sigma YAML.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterator

from wazuh_sigma.advisor.models import SigmaFeatureSet
from wazuh_sigma.backend.wazuh import WazuhRuleGenerator
from wazuh_sigma.sigma import SigmaRule

#: Bumped whenever extraction logic changes the shape or meaning of a feature.
#: Part of the advisor cache key; a version bump invalidates all cache entries.
FEATURE_SCHEMA_VERSION = "features-v1"

_ONE_OF_PATTERN = re.compile(r"\b1\s+of\b", re.IGNORECASE)
_ALL_OF_PATTERN = re.compile(r"\ball\s+of\b", re.IGNORECASE)
_BOOL_OPERATOR_PATTERN = re.compile(r"\b(and|or|not)\b", re.IGNORECASE)

#: Windows administrative binaries commonly seen in living-off-the-land activity.
#: Presence alone is not malicious; this is a coarse signal for the advisor.
ADMIN_BINARIES: frozenset[str] = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wmic.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "psexec.exe",
        "net.exe",
        "net1.exe",
        "netsh.exe",
        "schtasks.exe",
        "bitsadmin.exe",
        "reg.exe",
        "sc.exe",
        "at.exe",
        "taskkill.exe",
        "whoami.exe",
        "nslookup.exe",
        "ipconfig.exe",
        "tasklist.exe",
        "systeminfo.exe",
    }
)

#: Command substrings often associated with recon, credential access, or
#: defense evasion primitives. Coarse signal only.
SUSPICIOUS_COMMAND_PRIMITIVES: frozenset[str] = frozenset(
    {
        "whoami",
        "nltest",
        "net user",
        "net group",
        "net localgroup",
        "reg add",
        "reg query",
        "vssadmin delete shadows",
        "wevtutil cl",
        "invoke-mimikatz",
        "-enc",
        "-encodedcommand",
        "downloadstring",
        "certutil -urlcache",
        "invoke-expression",
        "start-bitstransfer",
        "new-object net.webclient",
    }
)

#: Base field names (lowercased) that are only populated by endpoint/EDR
#: telemetry (e.g. Sysmon) rather than default OS event logs.
TELEMETRY_DEPENDENT_FIELDS: frozenset[str] = frozenset(
    {
        "image",
        "commandline",
        "parentimage",
        "parentcommandline",
        "hashes",
        "targetfilename",
        "registry",
        "registrypath",
        "imphash",
        "destinationip",
        "destinationport",
        "sourceip",
        "sourceport",
    }
)

MAX_TAG_COUNT = 32
MAX_FIELD_NAME_COUNT = 256


def extract_features(sigma_rule: SigmaRule) -> SigmaFeatureSet:
    """Return the deterministic feature set for a normalized Sigma rule."""
    detection = sigma_rule.detection
    condition = str(detection.get("condition", ""))
    field_value_pairs = list(_iter_field_values(detection))

    selection_count, filter_count = _count_selections_and_filters(detection)
    tactics, techniques = _extract_attack_tags(sigma_rule.tags)
    field_names = _collect_field_names(field_value_pairs)
    modifier_types = _collect_modifier_types(field_value_pairs)
    documented_fps, fp_count = _false_positive_info(sigma_rule.raw_rule)
    telemetry_implied = bool(sigma_rule.get_event_source())

    boolean_operator_count = len(_BOOL_OPERATOR_PATTERN.findall(condition))
    condition_depth = boolean_operator_count + condition.count("(")
    is_single_indicator = (
        selection_count == 1
        and filter_count == 0
        and len(field_value_pairs) <= 1
        and not _ONE_OF_PATTERN.search(condition)
        and not _ALL_OF_PATTERN.search(condition)
    )
    baseline_level = WazuhRuleGenerator.LEVEL_MAPPING.get(sigma_rule.level, 10)

    return SigmaFeatureSet(
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        rule_content_hash=hash_rule_content(sigma_rule.raw_rule),
        title=sigma_rule.title,
        description=sigma_rule.description,
        sigma_level=sigma_rule.level,
        sigma_status=sigma_rule.status,
        logsource_product=sigma_rule.logsource.get("product"),
        logsource_category=sigma_rule.logsource.get("category"),
        logsource_service=sigma_rule.logsource.get("service"),
        attack_tactics=tactics,
        attack_techniques=techniques,
        field_names=field_names,
        modifier_types=modifier_types,
        selection_count=selection_count,
        filter_count=filter_count,
        condition_depth=condition_depth,
        boolean_operator_count=boolean_operator_count,
        has_negation=bool(re.search(r"\bnot\b", condition, re.IGNORECASE)),
        uses_one_of_selection=bool(_ONE_OF_PATTERN.search(condition)),
        uses_all_of_selection=bool(_ALL_OF_PATTERN.search(condition)),
        uses_wildcard_selection="*" in condition,
        has_broad_regex=_has_broad_regex(field_value_pairs),
        has_broad_wildcard=_has_broad_wildcard(field_value_pairs),
        has_admin_binary_reference=_matches_any(field_value_pairs, ADMIN_BINARIES),
        has_suspicious_command_primitive=_matches_any(
            field_value_pairs, SUSPICIOUS_COMMAND_PRIMITIVES
        ),
        documented_false_positives=documented_fps,
        false_positive_count=fp_count,
        likely_requires_telemetry=_requires_telemetry(field_names),
        telemetry_implied_by_logsource=telemetry_implied,
        is_single_indicator=is_single_indicator,
        current_deterministic_level=baseline_level,
        policy_baseline_level=baseline_level,
    )


def hash_rule_content(raw_rule: dict[str, Any]) -> str:
    """Return a stable SHA-256 hex digest of a rule's canonical JSON form."""
    canonical = json.dumps(raw_rule, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _iter_field_values(node: Any) -> Iterator[tuple[str, str]]:
    """Yield (field-name-with-modifiers, value) pairs from a Sigma detection tree."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in {"condition", "timeframe"}:
                continue
            if isinstance(value, dict):
                yield from _iter_field_values(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield from _iter_field_values(item)
                    elif item is not None:
                        yield key, str(item)
            elif value is not None:
                yield key, str(value)


def _count_selections_and_filters(detection: dict[str, Any]) -> tuple[int, int]:
    selection_count = 0
    filter_count = 0
    for key in detection:
        if key in {"condition", "timeframe"}:
            continue
        if key.lower().startswith("filter"):
            filter_count += 1
        else:
            selection_count += 1
    return selection_count, filter_count


def _extract_attack_tags(tags: list[Any]) -> tuple[list[str], list[str]]:
    tactics: list[str] = []
    techniques: list[str] = []
    for raw_tag in tags:
        tag = str(raw_tag).lower()
        if not tag.startswith("attack."):
            continue
        suffix = tag[len("attack.") :]
        if re.fullmatch(r"t\d{4}(\.\d{3})?", suffix):
            techniques.append(suffix)
        elif suffix:
            tactics.append(suffix)
    return tactics[:MAX_TAG_COUNT], techniques[:MAX_TAG_COUNT]


def _collect_field_names(pairs: list[tuple[str, str]]) -> list[str]:
    names: dict[str, None] = {}
    for field_key, _value in pairs:
        base_name = field_key.split("|", 1)[0]
        names.setdefault(base_name, None)
    return sorted(names)[:MAX_FIELD_NAME_COUNT]


def _collect_modifier_types(pairs: list[tuple[str, str]]) -> list[str]:
    modifiers: dict[str, None] = {}
    for field_key, _value in pairs:
        parts = field_key.split("|")[1:]
        for modifier in parts:
            modifiers.setdefault(modifier, None)
    return sorted(modifiers)


def _has_broad_wildcard(pairs: list[tuple[str, str]]) -> bool:
    return any(re.fullmatch(r"\*+", value.strip()) for _field, value in pairs)


def _has_broad_regex(pairs: list[tuple[str, str]]) -> bool:
    broad_patterns = {".*", ".+", "^.*$", "^.+$"}
    for field_key, value in pairs:
        modifiers = field_key.split("|")[1:]
        if "re" not in modifiers:
            continue
        if value.strip() in broad_patterns or len(value.strip()) <= 2:
            return True
    return False


def _matches_any(pairs: list[tuple[str, str]], needles: frozenset[str]) -> bool:
    for _field, value in pairs:
        lowered = value.lower()
        if any(needle in lowered for needle in needles):
            return True
    return False


def _false_positive_info(raw_rule: dict[str, Any]) -> tuple[bool, int]:
    false_positives = raw_rule.get("falsepositives")
    if false_positives is None:
        return False, 0
    if isinstance(false_positives, str):
        false_positives = [false_positives]
    if not isinstance(false_positives, list):
        return False, 0
    normalized = [str(item).strip().lower() for item in false_positives if str(item).strip()]
    documented = any(item not in {"unknown", "none"} for item in normalized)
    return documented, len(normalized)


def _requires_telemetry(field_names: list[str]) -> bool:
    return any(name.lower() in TELEMETRY_DEPENDENT_FIELDS for name in field_names)
