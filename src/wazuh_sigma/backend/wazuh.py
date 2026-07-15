"""Wazuh XML backend for pySigma-normalized Sigma rules."""

from __future__ import annotations

import ipaddress
import logging
import re
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
from xml.etree.ElementTree import Comment, Element, SubElement

from wazuh_sigma.fields.errors import UnsupportedWindowsFieldError
from wazuh_sigma.fields.models import FieldResolutionResult
from wazuh_sigma.fields.registry import FieldMappingRegistry
from wazuh_sigma.naming import sigma_group_name

logger = logging.getLogger(__name__)


DEFAULT_FIELD_MAPPING_VERSION = "wazuh-windows-eventdata-v1"
DEFAULT_PARENT_RULE_MAPPING_VERSION = "wazuh-4.14-windows-parent-v1"
DEFAULT_RULE_ID_START = 900000
DEFAULT_RULE_ID_END = 949999
DEFAULT_WINDOWS_FIELD_MAPPING_MODE = "strict"
DEFAULT_PARENT_RULES = {
    "product:windows": [60000],
    "service:security": [60001],
    "service:system": [60002],
    "service:application": [60003],
    "service:sysmon": [60004],
    "service:windefend": [60005],
    "service:windows-defender": [60005],
    "service:powershell": [60000],
    "service:wmi": [60018],
    "security_event_id:4720": [60109],
    "category:process_creation": [61603],
    "category:file_change": [61604],
    "category:network_connection": [61605],
    "category:driver_load": [61608],
    "category:image_load": [61609],
    "category:create_remote_thread": [61610],
    "category:raw_access_thread": [61611],
    "category:process_access": [61612],
    "category:file_event": [61613],
    "category:registry_add": [61614],
    "category:registry_delete": [61614],
    "category:registry_event": [61614, 61615, 61616],
    "category:registry_rename": [61616],
    "category:registry_set": [61615],
    "category:create_stream_hash": [61617],
    "category:pipe_created": [61645, 61646],
    "category:wmi_event": [61647, 61648, 61649],
    "category:dns_query": [61650],
    "category:file_delete": [61651, 61654],
    "category:process_tampering": [61653],
    "category:ps_script": [91802],
    "category:ps_module": [91801],
    "category:ps_classic_start": [91801],
    "category:ps_classic_provider_start": [91801],
    "default": [60000],
}
DEFAULT_FIELD_MAPPING = {
    "EventID": "win.system.eventID",
    "event_id": "win.system.eventID",
    "Image": "win.eventdata.image",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "User": "win.eventdata.user",
    "TargetFilename": "win.eventdata.targetFilename",
    "SourceIp": "win.eventdata.sourceIp",
    "DestinationIp": "win.eventdata.destinationIp",
    "DestinationPort": "win.eventdata.destinationPort",
    "SourcePort": "win.eventdata.sourcePort",
    "Protocol": "win.eventdata.protocol",
    "Registry": "win.eventdata.registryPath",
    "RegistryPath": "win.eventdata.registryPath",
    "Details": "win.eventdata.details",
    "ProcessId": "win.eventdata.processId",
    "ParentProcessId": "win.eventdata.parentProcessId",
    "LogonType": "win.eventdata.logonType",
    "LogonGuid": "win.eventdata.logonGuid",
    "TargetUserName": "win.eventdata.targetUserName",
    "SubjectUserName": "win.eventdata.subjectUserName",
    "Hashes": "win.eventdata.hashes",
    "MD5": "win.eventdata.md5",
    "SHA1": "win.eventdata.sha1",
    "SHA256": "win.eventdata.sha256",
    "Imphash": "win.eventdata.imphash",
    "ComputerName": "win.system.computer",
    "Hostname": "win.system.computer",
    "TargetHostname": "win.eventdata.targetHostname",
    "Provider_Name": "win.system.providerName",
    "Channel": "win.system.channel",
    "Domain": "win.eventdata.domain",
    "DomainName": "win.eventdata.domainName",
    "Account": "win.eventdata.accountName",
    "ServiceName": "win.eventdata.serviceName",
    "CallerProcessName": "win.eventdata.callerProcessName",
    "NewProcessName": "win.eventdata.newProcessName",
    "ParentCommandLine": "win.eventdata.parentCommandLine",
}


@dataclass(frozen=True)
class WazuhBackendConfig:
    """Configuration for the Wazuh XML backend."""

    rule_id_start: int = DEFAULT_RULE_ID_START
    rule_id_end: int = DEFAULT_RULE_ID_END
    field_mapping_version: str = DEFAULT_FIELD_MAPPING_VERSION
    parent_rule_mapping_version: str = DEFAULT_PARENT_RULE_MAPPING_VERSION
    windows_field_mapping_mode: str = DEFAULT_WINDOWS_FIELD_MAPPING_MODE
    field_mapping: dict[str, str] | None = None
    parent_rules: dict[str, list[int]] | None = None
    root_group_name: str = "sigma_rules,"
    max_dnf_alternatives: int = 128
    max_predicates_per_alternative: int = 32
    max_generated_child_rules: int = 64
    max_condition_recursion_depth: int = 32
    max_generated_rule_xml_bytes: int = 262144

    def __post_init__(self) -> None:
        if self.windows_field_mapping_mode not in ("strict", "warn", "legacy"):
            raise ValueError(
                f"windows_field_mapping_mode must be 'strict', 'warn', or 'legacy', "
                f"got: {self.windows_field_mapping_mode!r}"
            )
        for name in (
            "max_dnf_alternatives",
            "max_predicates_per_alternative",
            "max_generated_child_rules",
            "max_condition_recursion_depth",
            "max_generated_rule_xml_bytes",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


class SigmaRuleLike(Protocol):
    """Minimal normalized Sigma rule shape required by the Wazuh backend."""

    title: str
    detection: dict[str, Any]
    tags: list[Any]
    level: str

    def get_event_source(self) -> str | None:
        """Return the Sigma logsource service or product, when present."""


@dataclass(frozen=True)
class FieldPredicateIR:
    """Atomic Sigma field predicate from the pySigma condition tree."""

    field: str
    value: Any


@dataclass(frozen=True)
class AndIR:
    """Boolean conjunction preserving Sigma condition grouping."""

    children: tuple["ConditionIR", ...]


@dataclass(frozen=True)
class OrIR:
    """Boolean disjunction preserving Sigma condition grouping."""

    children: tuple["ConditionIR", ...]


@dataclass(frozen=True)
class NotIR:
    """Boolean negation preserving Sigma condition grouping."""

    child: "ConditionIR"


ConditionIR = FieldPredicateIR | AndIR | OrIR | NotIR


@dataclass(frozen=True)
class LoweredPredicate:
    """Wazuh field predicate ready for XML emission."""

    sigma_field: str
    wazuh_field: str
    pattern: str
    negated: bool = False
    lookahead_safe: bool = True


LoweredAlternative = tuple[LoweredPredicate, ...]


@dataclass(frozen=True)
class LoweringLimits:
    """Hard limits that prevent unsafe DNF/XML explosion."""

    max_dnf_alternatives: int
    max_predicates_per_alternative: int
    max_generated_child_rules: int
    max_condition_recursion_depth: int
    max_generated_rule_xml_bytes: int


@dataclass(frozen=True)
class ChildRulePlan:
    """Exact Wazuh emission plan for one Sigma rule."""

    alternatives: tuple[LoweredAlternative, ...]
    child_rule_required: bool
    common_predicates: tuple[LoweredPredicate, ...] = ()
    max_dnf_size: int = 0


class SigmaFieldMapper:
    """Versioned mapping from Sigma fields to Wazuh event fields.

    Supports context-aware mapping with registry-based lookup and multiple
    fallback modes (strict, warn, legacy).
    """

    OPERATOR_MAPPING = {
        "equals": "equals",
        "contains": "substring",
        "startswith": "starts_with",
        "endswith": "ends_with",
        "re": "regex",
        "all": "all_of",
        "selection": "selection",
    }

    FIELD_MAPPING = DEFAULT_FIELD_MAPPING

    def __init__(
        self,
        mapping: dict[str, str] | None = None,
        version: str = DEFAULT_FIELD_MAPPING_VERSION,
        registry: FieldMappingRegistry | None = None,
        mode: str = "strict",
        overrides: dict[str, str] | None = None,
    ):
        # Legacy default mappings (lower priority than registry, for backward compat)
        self.mapping = mapping or dict(DEFAULT_FIELD_MAPPING)
        # User-provided overrides (higher priority than registry)
        self.overrides = overrides or {}
        self.version = version
        self.registry = registry or FieldMappingRegistry()
        self.mode = mode

    def resolve_field(
        self,
        sigma_field: str,
        *,
        product: str | None = None,
        service: str | None = None,
        category: str | None = None,
    ) -> FieldResolutionResult:
        """Resolve a Sigma field to a Wazuh field with structured result.

        Priority:
        1. Native Wazuh static fields (always allowed)
        2. User-provided overrides (if given to constructor)
        3. Registry (verified mappings)
        4. Default legacy mappings (for backward compatibility)
        5. Mode-based fallback (legacy, warn, strict)

        Args:
            sigma_field: The Sigma field name
            product: Log source product (e.g., 'windows')
            service: Log source service (e.g., 'sysmon', 'security')
            category: Log source category (e.g., 'process_creation')

        Returns:
            FieldResolutionResult with status and field_name

        Raises:
            UnsupportedWindowsFieldError: If field is unsupported Windows field and mode is 'strict'
        """
        # Native Wazuh static fields are always allowed (highest priority)
        if sigma_field in WazuhRuleGenerator.STATIC_FIELDS:
            return FieldResolutionResult(
                field_name=sigma_field,
                status="resolved",
                verification=None,
            )

        # User-provided overrides take precedence over registry
        if sigma_field in self.overrides:
            return FieldResolutionResult(
                field_name=self.overrides[sigma_field],
                status="resolved",
                verification=None,
            )

        # Try registry (verified mappings)
        result = self.registry.resolve(
            sigma_field,
            product=product,
            service=service,
            category=category,
            mode=self.mode,
        )

        # If registry found something, return it immediately
        if result.status == "resolved":
            return result

        # Check default legacy mappings only if registry didn't find anything
        if sigma_field in self.mapping:
            if self.mode == "legacy":
                # In legacy mode, defaults are acceptable
                return FieldResolutionResult(
                    field_name=self.mapping[sigma_field],
                    status="resolved",
                    verification=None,
                )
            # In strict/warn mode, legacy defaults for Windows fields are not used
            normalized_product = product.lower() if product else None
            if normalized_product != "windows":
                # Non-Windows fields can use legacy defaults in all modes
                return FieldResolutionResult(
                    field_name=self.mapping[sigma_field],
                    status="resolved",
                    verification=None,
                )

        # Return the registry result (which may be unsupported, warning, or legacy_fallback)
        return result

    def map(self, sigma_field: str, *, product: str | None = None, service: str | None = None, category: str | None = None) -> str:
        """Map a Sigma field to a Wazuh field, with optional context.

        Args:
            sigma_field: The Sigma field name
            product: Log source product (e.g., 'windows')
            service: Log source service (e.g., 'sysmon', 'security')
            category: Log source category (e.g., 'process_creation')

        Returns:
            Wazuh field name

        Raises:
            UnsupportedWindowsFieldError: If field is unsupported Windows field and mode is 'strict'
            ValueError: If field should not be emitted (warning status)
        """
        result = self.resolve_field(
            sigma_field,
            product=product,
            service=service,
            category=category,
        )

        if result.status == "resolved" or result.status == "legacy_fallback":
            if result.field_name is None:
                raise ValueError(
                    f"Field {sigma_field!r} has status {result.status!r} but no field_name"
                )
            return result.field_name

        # warning or unsupported status: must not emit
        if result.status == "warning":
            raise ValueError(
                f"Field {sigma_field!r} cannot be emitted in {self.mode!r} mode: {result.warning_message}"
            )

        # unsupported status
        raise ValueError(
            f"Field {sigma_field!r} is unsupported: {result.warning_message}"
        )

    @staticmethod
    def map_field(sigma_field: str) -> str:
        """Backward-compatible default field mapping helper.

        Uses DEFAULT_FIELD_MAPPING only; does not use the new registry.
        This is preserved for backward compatibility.
        """
        return DEFAULT_FIELD_MAPPING.get(sigma_field, sigma_field.lower().replace(" ", "_"))

    @staticmethod
    def is_regex(value: str) -> bool:
        regex_chars = r"[\^\$\.\*\+\?\{\}\[\]\(\)\|\\]"
        return bool(re.search(regex_chars, value))


class WazuhRuleIDGenerator:
    """Generates Wazuh rule IDs inside an owned range."""

    START_CUSTOM_ID = DEFAULT_RULE_ID_START
    END_CUSTOM_ID = DEFAULT_RULE_ID_END

    def __init__(self, start_id: int = START_CUSTOM_ID, end_id: int = END_CUSTOM_ID):
        if start_id > end_id:
            raise ValueError(f"rule_id_start {start_id} must be <= rule_id_end {end_id}")
        self.current_id = start_id
        self.start_id = start_id
        self.end_id = end_id
        self.used_ids: set[int] = set()

    def generate_id(self) -> int:
        while self.current_id in self.used_ids:
            self.current_id += 1
        if self.current_id > self.end_id:
            raise ValueError(f"exhausted Wazuh rule ID range {self.start_id}-{self.end_id}")
        self.used_ids.add(self.current_id)
        result = self.current_id
        self.current_id += 1
        return result

    def reserve_id(self, rule_id: int) -> None:
        if rule_id < self.start_id or rule_id > self.end_id:
            raise ValueError(f"rule ID {rule_id} is outside owned range {self.start_id}-{self.end_id}")
        if rule_id in self.used_ids:
            raise ValueError(f"rule ID {rule_id} is already reserved")
        self.used_ids.add(rule_id)
        if rule_id >= self.current_id:
            self.current_id = rule_id + 1


class WazuhRuleGenerator:
    """Generates Wazuh XML rule elements from normalized Sigma rule objects."""

    SUPPORTED_STRING_MODIFIERS = frozenset({"all", "cidr", "contains", "endswith", "re", "startswith", "windash"})
    MAX_FIELD_ELEMENTS = 64
    MAX_PATTERN_LENGTH = 1800

    STATIC_FIELDS = {
        "action",
        "data",
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

    LEVEL_MAPPING = {
        "critical": 15,
        "high": 12,
        "medium": 10,
        "low": 5,
        "informational": 3,
        "experimental": 2,
    }

    def __init__(
        self,
        id_generator: WazuhRuleIDGenerator,
        field_mapper: SigmaFieldMapper | None = None,
        parent_rules: dict[str, list[int]] | None = None,
        limits: LoweringLimits | None = None,
    ):
        self.id_generator = id_generator
        self.field_mapper = field_mapper or SigmaFieldMapper()
        self.parent_rules = parent_rules or {}
        self.limits = limits or LoweringLimits(
            max_dnf_alternatives=128,
            max_predicates_per_alternative=32,
            max_generated_child_rules=64,
            max_condition_recursion_depth=32,
            max_generated_rule_xml_bytes=262144,
        )

    def generate(
        self,
        sigma_rule: SigmaRuleLike,
        *,
        level_override: int | None = None,
        wazuh_rule_id: int | None = None,
    ) -> Element:
        return self.generate_rules(
            sigma_rule,
            level_override=level_override,
            wazuh_rule_id=wazuh_rule_id,
        )[0]

    def generate_rules(
        self,
        sigma_rule: SigmaRuleLike,
        *,
        level_override: int | None = None,
        wazuh_rule_id: int | None = None,
    ) -> list[Element]:
        level = self._resolve_level(sigma_rule, level_override=level_override)

        # Extract logsource context for field mapping
        logsource = getattr(sigma_rule, "logsource", {}) or {}
        if not isinstance(logsource, dict):
            logsource = {}

        condition_ir = self._build_condition_ir(sigma_rule)
        normalized_ir = self._normalize_condition_ir(condition_ir)
        alternatives = self._lower_condition_ir(normalized_ir, logsource=logsource)
        plan = self._plan_child_rules(alternatives)
        rule_ids = self._allocate_rule_ids(len(plan.alternatives), wazuh_rule_id=wazuh_rule_id)
        rules = [
            self._emit_rule(
                sigma_rule,
                level=level,
                rule_id=rule_id,
                predicates=predicates,
                child_index=index,
                child_count=len(plan.alternatives),
            )
            for index, (rule_id, predicates) in enumerate(zip(rule_ids, plan.alternatives, strict=True), start=1)
        ]
        self._assert_total_xml_size(rules, sigma_rule)
        return rules

    def _allocate_rule_ids(self, count: int, *, wazuh_rule_id: int | None) -> list[int]:
        if count <= 0:
            raise ValueError("unsupported Sigma condition semantics: no Wazuh rules planned")
        if wazuh_rule_id is None:
            return [self.id_generator.generate_id() for _ in range(count)]
        self.id_generator.reserve_id(wazuh_rule_id)
        rule_ids = [wazuh_rule_id]
        for _ in range(count - 1):
            rule_ids.append(self.id_generator.generate_id())
        return rule_ids

    def _emit_rule(
        self,
        sigma_rule: SigmaRuleLike,
        *,
        level: int,
        rule_id: int,
        predicates: LoweredAlternative,
        child_index: int,
        child_count: int,
    ) -> Element:
        rule = Element("rule")
        rule.set("id", str(rule_id))
        rule.set("level", str(level))
        self._add_metadata(rule, sigma_rule, child_index=child_index, child_count=child_count)
        self._add_parent_rules(rule, sigma_rule)
        self._emit_lowered_predicates(rule, predicates)
        self._add_group(rule, sigma_rule)
        self._assert_wazuh_field_limit(rule, sigma_rule)
        self._assert_wazuh_pattern_lengths(rule, sigma_rule)
        return rule

    @classmethod
    def _resolve_level(cls, sigma_rule: SigmaRuleLike, *, level_override: int | None) -> int:
        if level_override is None:
            return cls.LEVEL_MAPPING.get(sigma_rule.level, 10)
        if not isinstance(level_override, int) or isinstance(level_override, bool):
            raise ValueError("level_override must be an integer between 0 and 15")
        if level_override < 0 or level_override > 15:
            raise ValueError("level_override must be between 0 and 15")
        return level_override

    def _add_metadata(
        self,
        rule: Element,
        sigma_rule: SigmaRuleLike,
        *,
        child_index: int = 1,
        child_count: int = 1,
    ) -> None:
        if sigma_rule.title:
            description = sigma_rule.title
            if child_count > 1:
                description = f"{description} [branch {child_index}/{child_count}]"
            SubElement(rule, "description").text = description

    def _add_parent_rules(self, rule: Element, sigma_rule: SigmaRuleLike) -> None:
        parent_ids = self._resolve_parent_rule_ids(sigma_rule)
        if parent_ids:
            SubElement(rule, "if_sid").text = ",".join(str(rule_id) for rule_id in parent_ids)

    def _resolve_parent_rule_ids(self, sigma_rule: SigmaRuleLike) -> list[int]:
        if not self.parent_rules:
            return []

        logsource = getattr(sigma_rule, "logsource", {}) or {}
        if not isinstance(logsource, dict):
            logsource = {}

        candidate_keys = []
        service = str(logsource.get("service", "")).strip().lower()
        if service == "security":
            for event_id in self._detection_event_ids(sigma_rule):
                candidate_keys.append(f"security_event_id:{event_id}")

        for field_name in ("service", "category", "product"):
            value = logsource.get(field_name)
            if value:
                normalized = str(value).strip().lower()
                candidate_keys.append(f"{field_name}:{normalized}")
                candidate_keys.append(normalized)

        event_source = sigma_rule.get_event_source()
        if event_source:
            candidate_keys.append(str(event_source).strip().lower())
        candidate_keys.append("default")

        for key in dict.fromkeys(candidate_keys):
            parent_ids = self.parent_rules.get(key)
            if parent_ids:
                return list(parent_ids)
        return []

    def _detection_event_ids(self, sigma_rule: SigmaRuleLike) -> list[str]:
        """Return normalized Windows event IDs referenced by a Sigma detection."""
        event_ids: list[str] = []

        def collect(value: Any) -> None:
            if isinstance(value, dict):
                for field_name, field_value in value.items():
                    base_field = str(field_name).split("|", 1)[0].strip().lower()
                    if base_field in {"eventid", "event_id", "event.code", "win.system.eventid"}:
                        collect_event_value(field_value)
                    else:
                        collect(field_value)
            elif isinstance(value, (list, tuple, set)):
                for item in value:
                    collect(item)

        def collect_event_value(value: Any) -> None:
            if isinstance(value, dict):
                for item in value.values():
                    collect_event_value(item)
            elif isinstance(value, (list, tuple, set)):
                for item in value:
                    collect_event_value(item)
            elif value is not None:
                normalized = str(value).strip()
                if normalized:
                    event_ids.append(normalized)

        collect(getattr(sigma_rule, "detection", {}) or {})
        return list(dict.fromkeys(event_ids))

    def _build_condition_ir(self, sigma_rule: SigmaRuleLike) -> ConditionIR:
        """Build a backend IR from pySigma's parsed condition tree.

        pySigma resolves selection identifiers, grouped expressions, wildcard
        selectors (``1 of``/``all of``), list linking and modifier expansion
        before this method runs. The backend therefore lowers a structured tree
        rather than interpreting Sigma condition text.
        """
        raw_rule = getattr(sigma_rule, "raw_rule", None)
        if not isinstance(raw_rule, dict):
            raw_rule = {
                "title": getattr(sigma_rule, "title", ""),
                "logsource": getattr(sigma_rule, "logsource", {}) or {},
                "detection": getattr(sigma_rule, "detection", {}) or {},
                "level": getattr(sigma_rule, "level", "medium"),
            }
        self._assert_supported_raw_modifiers(raw_rule)

        raw_rule = dict(raw_rule)
        raw_rule["tags"] = []
        if not raw_rule.get("logsource"):
            raw_rule["logsource"] = {"product": "generic"}
        detection = dict(raw_rule.get("detection", {}) or {})
        if "condition" not in detection:
            selection_keys = [
                key
                for key, value in detection.items()
                if key != "timeframe" and isinstance(value, (dict, list, str))
            ]
            if len(selection_keys) == 1:
                detection["condition"] = selection_keys[0]
        raw_rule["detection"] = detection

        try:
            from sigma.conditions import (
                ConditionAND,
                ConditionFieldEqualsValueExpression,
                ConditionNOT,
                ConditionOR,
                ConditionValueExpression,
                SigmaCondition,
            )
            from sigma.rule.rule import SigmaRule as PySigmaRule
        except ImportError as error:  # pragma: no cover - production dependency
            raise RuntimeError("pySigma is required for Sigma condition lowering") from error

        parsed_rule = PySigmaRule.from_dict(raw_rule)
        conditions = list(parsed_rule.detection.condition or [])
        if len(conditions) != 1:
            raise ValueError("unsupported Sigma condition semantics: exactly one condition is required")

        parsed_condition = SigmaCondition(conditions[0], parsed_rule.detection).parsed

        def convert(node: Any) -> ConditionIR:
            if isinstance(node, ConditionAND):
                return AndIR(tuple(convert(child) for child in node.args))
            if isinstance(node, ConditionOR):
                return OrIR(tuple(convert(child) for child in node.args))
            if isinstance(node, ConditionNOT):
                if len(node.args) != 1:
                    raise ValueError("unsupported Sigma condition semantics: NOT expects one child")
                return NotIR(convert(node.args[0]))
            if isinstance(node, ConditionFieldEqualsValueExpression):
                if type(node.value).__name__ == "SigmaExpansion":
                    return OrIR(tuple(FieldPredicateIR(str(node.field), value) for value in node.value.values))
                return FieldPredicateIR(str(node.field), node.value)
            if isinstance(node, ConditionValueExpression):
                raise ValueError("unsupported Sigma condition semantics: fieldless value expressions are not supported")
            raise ValueError(f"unsupported Sigma condition semantics: unsupported pySigma condition node {type(node).__name__}")

        return convert(parsed_condition)

    def _assert_supported_raw_modifiers(self, raw_rule: dict[str, Any]) -> None:
        """Reject Sigma modifiers the Wazuh backend cannot lower exactly."""

        def check_value(field_name: str, value: Any) -> None:
            base_field, *modifiers = str(field_name).split("|")
            if modifiers and base_field not in {"condition", "timeframe"}:
                modifier_set = set(modifiers)
                unsupported = sorted(modifier_set - self.SUPPORTED_STRING_MODIFIERS)
                if unsupported:
                    raise ValueError(f"unsupported Sigma string modifier(s): {', '.join(unsupported)}")
                if "cidr" in modifier_set and modifier_set != {"cidr"}:
                    raise ValueError("unsupported Sigma string modifier combination: cidr with non-cidr modifiers")
                if "re" in modifier_set and "windash" in modifier_set:
                    raise ValueError("unsupported Sigma string modifier combination: re, windash")
                if "all" in modifier_set and "contains" not in modifier_set:
                    raise ValueError("unsupported Sigma string modifier combination: all without contains")
            if isinstance(value, dict):
                for child_field, child_value in value.items():
                    check_value(str(child_field), child_value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        for child_field, child_value in item.items():
                            check_value(str(child_field), child_value)

        detection = raw_rule.get("detection", {}) or {}
        if isinstance(detection, dict):
            for key, value in detection.items():
                if key not in {"condition", "timeframe"}:
                    check_value(str(key), value)

    def _normalize_condition_ir(self, ir: ConditionIR, *, depth: int = 0) -> ConditionIR:
        """Normalize boolean IR without changing semantics.

        Current normalization performs constant-free structural cleanup:
        flatten nested AND/OR nodes, remove duplicate child subtrees, and keep
        NOT boundaries explicit. More aggressive rewrites are intentionally not
        done here unless they are semantics-preserving for the Wazuh target.
        """
        if depth > self.limits.max_condition_recursion_depth:
            raise ValueError(
                "unsupported Sigma condition semantics: condition recursion depth exceeds "
                f"{self.limits.max_condition_recursion_depth}"
            )
        if isinstance(ir, FieldPredicateIR):
            return ir
        if isinstance(ir, NotIR):
            return self._normalize_not_ir(ir.child, depth=depth + 1)
        if isinstance(ir, AndIR):
            children: list[ConditionIR] = []
            for child in ir.children:
                normalized = self._normalize_condition_ir(child, depth=depth + 1)
                if isinstance(normalized, AndIR):
                    children.extend(normalized.children)
                else:
                    children.append(normalized)
            return AndIR(self._dedupe_ir_children(children))
        if isinstance(ir, OrIR):
            children = []
            for child in ir.children:
                normalized = self._normalize_condition_ir(child, depth=depth + 1)
                if isinstance(normalized, OrIR):
                    children.extend(normalized.children)
                else:
                    children.append(normalized)
            return OrIR(self._dedupe_ir_children(children))
        raise ValueError(f"unsupported Sigma condition semantics: unsupported IR node {type(ir).__name__}")

    def _normalize_not_ir(self, child: ConditionIR, *, depth: int) -> ConditionIR:
        """Push NOT down to predicates using De Morgan rewrites.

        Wazuh can represent negation on individual field predicates. These
        rewrites are boolean identities, so they preserve Sigma semantics while
        avoiding a special grouped-NOT lowering path later in the backend.
        """
        normalized = self._normalize_condition_ir(child, depth=depth)
        if isinstance(normalized, FieldPredicateIR):
            return NotIR(normalized)
        if isinstance(normalized, NotIR):
            return self._normalize_condition_ir(normalized.child, depth=depth + 1)
        if isinstance(normalized, AndIR):
            return OrIR(self._dedupe_ir_children([
                self._normalize_not_ir(grandchild, depth=depth + 1)
                for grandchild in normalized.children
            ]))
        if isinstance(normalized, OrIR):
            return AndIR(self._dedupe_ir_children([
                self._normalize_not_ir(grandchild, depth=depth + 1)
                for grandchild in normalized.children
            ]))
        raise ValueError(f"unsupported Sigma condition semantics: unsupported NOT child {type(normalized).__name__}")

    @staticmethod
    def _dedupe_ir_children(children: list[ConditionIR]) -> tuple[ConditionIR, ...]:
        deduped: list[ConditionIR] = []
        seen: set[str] = set()
        for child in children:
            key = repr(child)
            if key not in seen:
                seen.add(key)
                deduped.append(child)
        return tuple(deduped)

    def _lower_condition_ir(
        self,
        ir: ConditionIR,
        *,
        logsource: dict[str, Any],
        depth: int = 0,
    ) -> tuple[LoweredAlternative, ...]:
        """Lower the boolean IR to DNF alternatives without changing semantics."""
        if depth > self.limits.max_condition_recursion_depth:
            raise ValueError(
                "unsupported Sigma condition semantics: DNF recursion depth exceeds "
                f"{self.limits.max_condition_recursion_depth}"
            )
        if isinstance(ir, FieldPredicateIR):
            return ((self._lower_field_predicate(ir, logsource=logsource),),)

        if isinstance(ir, AndIR):
            alternatives: tuple[LoweredAlternative, ...] = ((),)
            for child in ir.children:
                child_alternatives = self._lower_condition_ir(child, logsource=logsource, depth=depth + 1)
                expanded = tuple(
                    self._dedupe_predicates(left + right)
                    for left in alternatives
                    for right in child_alternatives
                )
                alternatives = self._normalize_alternatives(expanded)
                self._assert_dnf_limits(alternatives)
            return alternatives

        if isinstance(ir, OrIR):
            alternatives = tuple(
                alternative
                for child in ir.children
                for alternative in self._lower_condition_ir(child, logsource=logsource, depth=depth + 1)
            )
            alternatives = self._normalize_alternatives(alternatives)
            self._assert_dnf_limits(alternatives)
            return alternatives

        if isinstance(ir, NotIR):
            child_alternatives = self._lower_condition_ir(ir.child, logsource=logsource, depth=depth + 1)
            if len(child_alternatives) != 1 or len(child_alternatives[0]) != 1:
                raise ValueError("unsupported Sigma condition semantics: grouped NOT cannot be represented exactly")
            predicate = child_alternatives[0][0]
            return ((LoweredPredicate(
                sigma_field=predicate.sigma_field,
                wazuh_field=predicate.wazuh_field,
                pattern=predicate.pattern,
                negated=not predicate.negated,
                lookahead_safe=predicate.lookahead_safe,
            ),),)

        raise ValueError(f"unsupported Sigma condition semantics: unsupported IR node {type(ir).__name__}")

    @staticmethod
    def _dedupe_predicates(predicates: LoweredAlternative) -> LoweredAlternative:
        return tuple(dict.fromkeys(predicates))

    @classmethod
    def _normalize_alternatives(cls, alternatives: tuple[LoweredAlternative, ...]) -> tuple[LoweredAlternative, ...]:
        normalized = tuple(cls._dedupe_predicates(alternative) for alternative in alternatives)
        return tuple(dict.fromkeys(normalized))

    def _assert_dnf_limits(self, alternatives: tuple[LoweredAlternative, ...]) -> None:
        if len(alternatives) > self.limits.max_dnf_alternatives:
            raise ValueError(
                "unsupported Sigma condition semantics: DNF alternatives "
                f"{len(alternatives)} exceeds configured maximum {self.limits.max_dnf_alternatives}"
            )
        for alternative in alternatives:
            if len(alternative) > self.limits.max_predicates_per_alternative:
                raise ValueError(
                    "unsupported Sigma condition semantics: DNF predicates per alternative "
                    f"{len(alternative)} exceeds configured maximum {self.limits.max_predicates_per_alternative}"
                )

    def _lower_field_predicate(self, predicate: FieldPredicateIR, *, logsource: dict[str, Any]) -> LoweredPredicate:
        base_field = predicate.field
        resolution = self.field_mapper.resolve_field(
            base_field,
            product=logsource.get("product"),
            service=logsource.get("service"),
            category=logsource.get("category"),
        )
        if not resolution.should_emit():
            if not any(logsource.get(key) for key in ("product", "service", "category")):
                pattern, lookahead_safe = self._pattern_for_sigma_value(predicate.value)
                return LoweredPredicate(
                    sigma_field=base_field,
                    wazuh_field=base_field,
                    pattern=pattern,
                    lookahead_safe=lookahead_safe,
                )
            if resolution.warning_message:
                logger.warning("Skipping field %r in rule detection: %s", base_field, resolution.warning_message)
            raise ValueError(f"unsupported Sigma condition semantics: field {base_field!r} does not resolve to Wazuh")
        pattern, lookahead_safe = self._pattern_for_sigma_value(predicate.value)
        return LoweredPredicate(
            sigma_field=base_field,
            wazuh_field=resolution.get_field_name_or_raise(),
            pattern=pattern,
            lookahead_safe=lookahead_safe,
        )

    def _collapse_lowered_alternatives(
        self,
        alternatives: tuple[LoweredAlternative, ...],
    ) -> tuple[LoweredPredicate, ...]:
        """Collapse DNF alternatives into one Wazuh rule when exact.

        A single Wazuh rule naturally represents conjunction across emitted
        fields. Disjunction is only collapsed when branch predicates share the
        same field and can be expressed as one PCRE alternation, or when a
        common conjunction can be factored out and the remaining branch is a
        same-field alternation. Other DNF shapes require child rules and are
        rejected until that lowering is implemented.
        """
        if not alternatives:
            raise ValueError("unsupported Sigma condition semantics: empty condition")
        if len(alternatives) == 1:
            return self._collapse_conjunction(alternatives[0])

        normalized = [self._collapse_conjunction(alternative) for alternative in alternatives]
        common = self._common_predicates(normalized)
        remainders = [tuple(predicate for predicate in alternative if predicate not in common) for alternative in normalized]
        if all(len(remainder) == 1 for remainder in remainders):
            disjunction = tuple(remainder[0] for remainder in remainders)
            collapsed_or = self._collapse_same_field_or(disjunction)
            return tuple(common) + (collapsed_or,)
        if all(len(remainder) == 0 for remainder in remainders):
            return tuple(common)
        raise ValueError(
            "unsupported Sigma condition semantics: OR branches across distinct field sets require child-rule lowering"
        )

    def _plan_child_rules(self, alternatives: tuple[LoweredAlternative, ...]) -> ChildRulePlan:
        """Plan exact Wazuh rules for a normalized DNF expression.

        Single-rule lowering is preferred when exact. When one rule cannot
        encode the DNF, every DNF alternative becomes one Wazuh branch rule.
        This preserves OR semantics without flattening branch conjunctions.
        """
        alternatives = self._normalize_alternatives(alternatives)
        self._assert_dnf_limits(alternatives)
        max_dnf_size = len(alternatives)

        try:
            single_rule = self._collapse_lowered_alternatives(alternatives)
            if not self._has_oversized_pattern(single_rule) or len(alternatives) == 1:
                return ChildRulePlan(
                    alternatives=(single_rule,),
                    child_rule_required=False,
                    max_dnf_size=max_dnf_size,
                )
        except ValueError as error:
            if "child-rule lowering" not in str(error):
                raise

        branch_rules = tuple(self._collapse_conjunction(alternative) for alternative in alternatives)
        branch_rules = tuple(dict.fromkeys(branch_rules))
        if len(branch_rules) > self.limits.max_generated_child_rules:
            raise ValueError(
                "unsupported Sigma condition semantics: generated child rules "
                f"{len(branch_rules)} exceeds configured maximum {self.limits.max_generated_child_rules}"
            )
        return ChildRulePlan(
            alternatives=branch_rules,
            child_rule_required=True,
            common_predicates=self._common_predicates(list(branch_rules)) if branch_rules else (),
            max_dnf_size=max_dnf_size,
        )

    @classmethod
    def _has_oversized_pattern(cls, predicates: tuple[LoweredPredicate, ...]) -> bool:
        return any(len(predicate.pattern) > cls.MAX_PATTERN_LENGTH for predicate in predicates)

    @staticmethod
    def _common_predicates(alternatives: list[tuple[LoweredPredicate, ...]]) -> tuple[LoweredPredicate, ...]:
        common: list[LoweredPredicate] = []
        for predicate in alternatives[0]:
            if all(predicate in alternative for alternative in alternatives[1:]):
                common.append(predicate)
        return tuple(common)

    def _collapse_conjunction(self, predicates: LoweredAlternative) -> tuple[LoweredPredicate, ...]:
        grouped: dict[tuple[str, bool], list[LoweredPredicate]] = {}
        ordered_keys: list[tuple[str, bool]] = []
        for predicate in predicates:
            key = (predicate.wazuh_field, predicate.negated)
            if key not in grouped:
                ordered_keys.append(key)
                grouped[key] = []
            grouped[key].append(predicate)

        collapsed: list[LoweredPredicate] = []
        for key in ordered_keys:
            group = grouped[key]
            if len(group) == 1:
                collapsed.append(group[0])
                continue
            if group[0].negated:
                collapsed.append(self._collapse_same_field_negated_and(tuple(group)))
                continue
            collapsed.append(self._collapse_same_field_and(tuple(group)))
        return tuple(collapsed)

    @classmethod
    def _collapse_same_field_and(cls, predicates: tuple[LoweredPredicate, ...]) -> LoweredPredicate:
        if not all(predicate.lookahead_safe for predicate in predicates):
            raise ValueError(
                "unsupported Sigma condition semantics: same-field AND contains predicates that cannot be lookahead-lowered"
            )
        unique_patterns = list(dict.fromkeys(predicate.pattern for predicate in predicates))
        lookaheads = "".join(cls._lookahead_for_pattern(pattern) for pattern in unique_patterns)
        first = predicates[0]
        return LoweredPredicate(
            sigma_field=first.sigma_field,
            wazuh_field=first.wazuh_field,
            pattern=lookaheads + ".*",
            lookahead_safe=True,
        )

    @classmethod
    def _lookahead_for_pattern(cls, pattern: str) -> str:
        scoped = cls._scope_leading_global_regex_flags(pattern)
        if cls._first_unescaped_start_anchor_index(scoped) == 0:
            return f"(?={scoped})"
        return f"(?=.*(?:{scoped}))"

    @classmethod
    def _collapse_same_field_or(cls, predicates: tuple[LoweredPredicate, ...]) -> LoweredPredicate:
        first = predicates[0]
        if not all(predicate.wazuh_field == first.wazuh_field for predicate in predicates):
            raise ValueError("unsupported Sigma condition semantics: OR across distinct Wazuh fields requires child-rule lowering")
        if any(predicate.negated for predicate in predicates):
            raise ValueError("unsupported Sigma condition semantics: OR with negated predicates requires child-rule lowering")
        branch_patterns = [cls._scope_leading_global_regex_flags(predicate.pattern) for predicate in predicates]
        return LoweredPredicate(
            sigma_field=first.sigma_field,
            wazuh_field=first.wazuh_field,
            pattern="(?:" + "|".join(dict.fromkeys(branch_patterns)) + ")",
            lookahead_safe=False,
        )

    @classmethod
    def _collapse_same_field_negated_and(cls, predicates: tuple[LoweredPredicate, ...]) -> LoweredPredicate:
        """Collapse ``not A and not B`` into ``not (A or B)`` for one field."""
        if not all(predicate.negated for predicate in predicates):
            raise ValueError("internal lowering error: expected only negated predicates")
        positive = tuple(
            LoweredPredicate(
                sigma_field=predicate.sigma_field,
                wazuh_field=predicate.wazuh_field,
                pattern=predicate.pattern,
                negated=False,
                lookahead_safe=predicate.lookahead_safe,
            )
            for predicate in predicates
        )
        collapsed = cls._collapse_same_field_or(positive)
        return LoweredPredicate(
            sigma_field=collapsed.sigma_field,
            wazuh_field=collapsed.wazuh_field,
            pattern=collapsed.pattern,
            negated=True,
            lookahead_safe=False,
        )

    def _emit_lowered_predicates(self, rule: Element, predicates: tuple[LoweredPredicate, ...]) -> None:
        for predicate in predicates:
            if predicate.wazuh_field in self.STATIC_FIELDS:
                field_elem = SubElement(rule, predicate.wazuh_field)
            else:
                field_elem = SubElement(rule, "field")
                field_elem.set("name", predicate.wazuh_field)
            field_elem.set("type", "pcre2")
            if predicate.negated:
                field_elem.set("negate", "yes")
            field_elem.text = predicate.pattern

    def _assert_total_xml_size(self, rules: list[Element], sigma_rule: SigmaRuleLike) -> None:
        total_size = sum(len(ET.tostring(rule, encoding="utf-8")) for rule in rules)
        if total_size > self.limits.max_generated_rule_xml_bytes:
            raise ValueError(
                "unsupported Sigma condition semantics: generated XML size "
                f"{total_size} exceeds configured maximum {self.limits.max_generated_rule_xml_bytes} "
                f"for {sigma_rule.title!r}"
            )

    def _add_detection(
        self,
        rule: Element,
        sigma_rule: SigmaRuleLike,
        logsource: dict | None = None,
        selected_keys: tuple[str, ...] = (),
    ) -> None:
        if logsource is None:
            logsource = {}

        for key in selected_keys:
            value = sigma_rule.detection.get(key)
            if key in {"condition", "timeframe"}:
                continue
            if isinstance(value, dict):
                self._add_detection_dict(rule, value, logsource=logsource)
            elif isinstance(value, list):
                self._add_detection_list(rule, key, value, logsource=logsource)
            elif isinstance(value, str):
                self._add_detection_field(rule, key, value, logsource=logsource)

    def _add_detection_dict(self, rule: Element, detection_dict: dict[str, Any], logsource: dict | None = None) -> None:
        if logsource is None:
            logsource = {}

        for field_name, value in detection_dict.items():
            if isinstance(value, (list, tuple)):
                self._add_detection_list(rule, field_name, list(value), logsource=logsource)
            elif isinstance(value, dict):
                self._add_detection_dict(rule, value, logsource=logsource)
            elif value is not None:
                self._add_detection_field(rule, field_name, str(value), logsource=logsource)

    def _add_detection_list(self, rule: Element, field_name: str, values: list[Any], logsource: dict | None = None) -> None:
        if logsource is None:
            logsource = {}

        scalar_values = [value for value in values if value is not None and not isinstance(value, dict)]
        if scalar_values:
            base_field, *modifiers = field_name.split("|")
            if "all" in modifiers:
                pattern = self._pattern_for_all_modifier([str(value) for value in scalar_values], modifiers)
                self._add_detection_pattern(rule, base_field, pattern, logsource=logsource)
                for value in values:
                    if isinstance(value, dict):
                        self._add_detection_dict(rule, value, logsource=logsource)
                return
            patterns = [self._pattern_for_modifiers(str(value), modifiers) for value in scalar_values]
            if len(patterns) == 1:
                self._add_detection_pattern(rule, base_field, patterns[0], logsource=logsource)
            else:
                self._add_detection_pattern(rule, base_field, "(?:" + "|".join(patterns) + ")", logsource=logsource)
        for value in values:
            if isinstance(value, dict):
                self._add_detection_dict(rule, value, logsource=logsource)

    def _add_detection_field(self, rule: Element, field_name: str, value: str, logsource: dict | None = None) -> None:
        if not value or field_name in {"condition", "timeframe", "selection"}:
            return

        if logsource is None:
            logsource = {}

        base_field, *modifiers = field_name.split("|")
        if "all" in modifiers:
            raise ValueError("unsupported Sigma string modifier combination: all requires a list value")
        self._add_detection_pattern(rule, base_field, self._pattern_for_modifiers(value, modifiers), logsource=logsource)

    def _add_detection_pattern(self, rule: Element, base_field: str, pattern: str, logsource: dict | None = None) -> None:
        if logsource is None:
            logsource = {}

        product = logsource.get("product")
        service = logsource.get("service")
        category = logsource.get("category")

        # Resolve field with structured result to check if it should be emitted
        resolution = self.field_mapper.resolve_field(
            base_field,
            product=product,
            service=service,
            category=category,
        )

        # Check if this field should be emitted
        if not resolution.should_emit():
            # Log warning if applicable
            if resolution.warning_message:
                logger.warning(
                    "Skipping field %r in rule detection: %s",
                    base_field,
                    resolution.warning_message,
                )
            # Do not emit this field
            return

        # Field is safe to emit
        mapped_field = resolution.get_field_name_or_raise()

        if mapped_field in self.STATIC_FIELDS:
            field_elem = SubElement(rule, mapped_field)
        else:
            field_elem = SubElement(rule, "field")
            field_elem.set("name", mapped_field)
        field_elem.set("type", "pcre2")
        field_elem.text = pattern

    @classmethod
    def _pattern_for_sigma_value(cls, value: Any) -> tuple[str, bool]:
        """Translate a pySigma normalized value to a Wazuh PCRE2 pattern.

        pySigma has already applied Sigma modifiers at this point. Literal
        strings, contains, startswith, endswith and wildcard forms arrive as
        ``SigmaString`` parts. Regex values arrive as ``SigmaRegularExpression``.
        """
        try:
            from sigma.types import (
                SigmaBool,
                SigmaCasedString,
                SigmaCIDRExpression,
                SigmaExists,
                SigmaExpansion,
                SigmaNull,
                SigmaNumber,
                SigmaRegularExpression,
                SigmaString,
                SpecialChars,
            )
        except ImportError as error:  # pragma: no cover - production dependency
            raise RuntimeError("pySigma is required for Sigma value lowering") from error

        if isinstance(value, SigmaExpansion):
            raise ValueError("unsupported Sigma condition semantics: unexpanded Sigma value expansion")
        if isinstance(value, SigmaExists):
            raise ValueError("unsupported Sigma condition semantics: exists checks are not supported")
        if isinstance(value, SigmaNull):
            raise ValueError("unsupported Sigma condition semantics: null checks are not supported")
        if isinstance(value, SigmaCIDRExpression):
            return cls._pattern_for_sigma_cidr(value), True
        if isinstance(value, SigmaRegularExpression):
            if getattr(value, "flags", set()):
                raise ValueError("unsupported Sigma condition semantics: regex flags are not supported")
            pattern = str(value.regexp)
            return pattern, cls._is_regex_lookahead_safe(pattern)
        if isinstance(value, (SigmaString, SigmaCasedString)):
            return cls._pattern_for_sigma_string(value, SpecialChars), True
        if isinstance(value, SigmaNumber):
            return "^" + cls._escape_literal_pattern(str(value.number)) + "$", True
        if isinstance(value, SigmaBool):
            return "^" + cls._escape_literal_pattern(str(value.boolean).lower()) + "$", True
        if isinstance(value, str):
            return "^" + cls._escape_literal_pattern(value) + "$", True
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return "^" + cls._escape_literal_pattern(str(value)) + "$", True
        if isinstance(value, bool):
            return "^" + cls._escape_literal_pattern(str(value).lower()) + "$", True
        raise ValueError(f"unsupported Sigma condition semantics: unsupported value type {type(value).__name__}")

    @classmethod
    def _pattern_for_sigma_cidr(cls, value: Any) -> str:
        """Translate a pySigma CIDR value into an exact bounded IPv4 PCRE2 pattern.

        Wazuh fields store decoded IP addresses as textual values. IPv4 CIDR can
        be represented exactly as a dotted-quad regular expression by fixing the
        full prefix octets, constraining the partial prefix octet if present, and
        allowing any valid value for remaining host octets. IPv6 remains rejected
        because compressed textual forms make exact regex equivalence target-
        dependent without a confirmed Wazuh canonicalization contract.
        """
        network = getattr(value, "network", None)
        if network is None:
            network = ipaddress.ip_network(str(getattr(value, "cidr", value)), strict=False)
        if isinstance(network, ipaddress.IPv6Network):
            raise ValueError("unsupported Sigma condition semantics: IPv6 CIDR is not supported")
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError(f"unsupported Sigma condition semantics: unsupported CIDR type {type(network).__name__}")

        octet_any = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        address_octets = [int(part) for part in str(network.network_address).split(".")]
        full_octets, partial_bits = divmod(network.prefixlen, 8)
        pattern_octets: list[str] = []

        for index in range(full_octets):
            pattern_octets.append(str(address_octets[index]))

        if partial_bits:
            host_bits = 8 - partial_bits
            low = address_octets[full_octets]
            high = low + (2**host_bits) - 1
            pattern_octets.append(cls._pattern_for_octet_range(low, high))

        while len(pattern_octets) < 4:
            pattern_octets.append(octet_any)

        pattern = r"^" + r"\.".join(pattern_octets) + r"$"
        if len(pattern) > cls.MAX_PATTERN_LENGTH:
            raise ValueError(
                "unsupported Sigma condition semantics: CIDR regex length "
                f"{len(pattern)} exceeds supported maximum {cls.MAX_PATTERN_LENGTH}"
            )
        return pattern

    @staticmethod
    def _pattern_for_octet_range(low: int, high: int) -> str:
        """Return an exact regex for a bounded IPv4 octet range."""
        if low < 0 or high > 255 or low > high:
            raise ValueError(f"invalid IPv4 octet range {low}-{high}")
        if low == 0 and high == 255:
            return r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        return "(?:" + "|".join(str(value) for value in range(low, high + 1)) + ")"

    @classmethod
    def _is_regex_lookahead_safe(cls, pattern: str) -> bool:
        """Return whether a regex can be embedded as an independent lookahead.

        This keeps support intentionally narrow: unanchored search regexes are
        safe as ``(?=.*(?:regex))`` and start-anchored regexes are safe as
        ``(?=^regex)``. Regexes with a start anchor after the first token remain
        rejected because rewriting them into a same-field conjunction can change
        their match position semantics.
        """
        scoped = cls._scope_leading_global_regex_flags(pattern)
        return cls._first_unescaped_start_anchor_index(scoped) in {-1, 0}

    @staticmethod
    def _first_unescaped_start_anchor_index(pattern: str) -> int:
        in_character_class = False
        escaped = False
        for index, char in enumerate(pattern):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == "[":
                in_character_class = True
                continue
            if char == "]":
                in_character_class = False
                continue
            if char == "^" and not in_character_class:
                return index
        return -1

    @classmethod
    def _pattern_for_sigma_string(cls, value: Any, special_chars: Any) -> str:
        parts: list[str] = ["^"]
        for part in value.s:
            if part == special_chars.WILDCARD_MULTI:
                parts.append(".*")
            elif part == special_chars.WILDCARD_SINGLE:
                parts.append(".")
            elif isinstance(part, str):
                parts.append(cls._escape_literal_pattern(part))
            else:
                raise ValueError(
                    f"unsupported Sigma condition semantics: unsupported Sigma string part {type(part).__name__}"
                )
        parts.append("$")
        return "".join(parts)

    @staticmethod
    def _pattern_for_modifiers(value: str, modifiers: list[str]) -> str:
        """Translate supported Sigma string modifiers into a Wazuh pcre2 pattern."""
        modifier_set = set(modifiers)
        unsupported = sorted(modifier_set - WazuhRuleGenerator.SUPPORTED_STRING_MODIFIERS)
        if unsupported:
            raise ValueError(f"unsupported Sigma string modifier(s): {', '.join(unsupported)}")

        if "re" in modifier_set and "windash" in modifier_set:
            raise ValueError("unsupported Sigma string modifier combination: re, windash")

        if "all" in modifier_set:
            raise ValueError("unsupported Sigma string modifier combination: all requires list handling")

        if "re" in modifier_set:
            return value

        escaped = WazuhRuleGenerator._escape_literal_pattern(value, expand_windash="windash" in modifier_set)
        if "contains" in modifier_set:
            escaped = f".*{escaped}.*"
        if "startswith" in modifier_set:
            escaped = f"^{escaped}"
        if "endswith" in modifier_set:
            escaped = f"{escaped}$"
        return escaped

    @staticmethod
    def _escape_literal_pattern(value: str, *, expand_windash: bool = False) -> str:
        """Escape a literal for PCRE without Wazuh-hostile escaped spaces."""
        if expand_windash:
            dash_class = "[-/‐‑‒–—―]"
            return "".join(
                dash_class if char in {"-", "/"} else re.escape(char)
                for char in value
            ).replace(r"\ ", " ").replace("<", r"\x3c").replace(">", r"\x3e")
        return (
            re.escape(value)
            .replace(r"\ ", " ")
            .replace("<", r"\x3c")
            .replace(">", r"\x3e")
        )

    @staticmethod
    def _pattern_for_all_modifier(values: list[str], modifiers: list[str]) -> str:
        """Translate supported Sigma ``all`` list semantics into one PCRE2 pattern.

        The safe subset implemented here is ``contains|all`` for scalar lists:
        every listed literal must occur somewhere in the same field. This maps
        cleanly to positive lookaheads and avoids the previous unsafe OR merge.
        Other combinations remain rejected because they require different
        semantics or a fieldless log-message target.
        """
        modifier_set = set(modifiers)
        unsupported = sorted(modifier_set - WazuhRuleGenerator.SUPPORTED_STRING_MODIFIERS)
        if unsupported:
            raise ValueError(f"unsupported Sigma string modifier(s): {', '.join(unsupported)}")

        if "re" in modifier_set:
            raise ValueError("unsupported Sigma string modifier combination: re, all")
        if "contains" not in modifier_set:
            raise ValueError("unsupported Sigma string modifier combination: all without contains")
        if "startswith" in modifier_set or "endswith" in modifier_set:
            raise ValueError("unsupported Sigma string modifier combination: all with startswith/endswith")

        unique_values = list(dict.fromkeys(values))
        if not unique_values:
            raise ValueError("unsupported Sigma string modifier combination: all requires at least one value")

        lookaheads = []
        for value in unique_values:
            escaped = WazuhRuleGenerator._escape_literal_pattern(value, expand_windash="windash" in modifier_set)
            lookaheads.append(f"(?=.*{escaped})")
        return "".join(lookaheads) + ".*"

    @staticmethod
    def _scope_leading_global_regex_flags(pattern: str) -> str:
        """Convert leading global inline flags into branch-local scoped flags.

        Sigma regex values can start with constructs such as ``(?i)``. Those are
        valid at the beginning of a single pattern, but become invalid once
        duplicate Wazuh fields are merged into an alternation:
        ``(?:literal|(?i)regex)``. Scoping the flags to the branch keeps the
        generated PCRE valid without changing sibling alternation branches.
        """
        match = re.match(r"^\(\?([aiLmsux]+(?:-[imsx]+)?)\)(.*)\Z", pattern, re.DOTALL)
        if not match:
            return pattern
        flags, body = match.groups()
        return f"(?{flags}:{body})"

    def _add_group(self, rule: Element, sigma_rule: SigmaRuleLike) -> None:
        groups = [sigma_group_name(sigma_rule.title)]
        groups.extend(sigma_group_name(str(tag)) for tag in sigma_rule.tags)
        SubElement(rule, "group").text = ",".join(dict.fromkeys(groups))

    @classmethod
    def _assert_wazuh_field_limit(cls, rule: Element, sigma_rule: SigmaRuleLike) -> None:
        field_count = len(rule.findall("field"))
        if field_count > cls.MAX_FIELD_ELEMENTS:
            raise ValueError(
                f"Wazuh rule field count {field_count} exceeds supported maximum "
                f"{cls.MAX_FIELD_ELEMENTS} for {sigma_rule.title!r}"
            )

    @classmethod
    def _assert_wazuh_pattern_lengths(cls, rule: Element, sigma_rule: SigmaRuleLike) -> None:
        for element in rule:
            if element.tag not in cls.STATIC_FIELDS and element.tag != "field":
                continue
            text = element.text or ""
            if len(text) > cls.MAX_PATTERN_LENGTH:
                field_name = element.get("name") or element.tag
                raise ValueError(
                    f"Wazuh pattern length {len(text)} for field {field_name!r} exceeds supported maximum "
                    f"{cls.MAX_PATTERN_LENGTH} for {sigma_rule.title!r}"
                )


class WazuhBackend:
    """Backend boundary: normalized Sigma rule objects in, Wazuh XML out."""

    def __init__(self, config: WazuhBackendConfig | None = None):
        self.config = config or WazuhBackendConfig()

        # Initialize field mapping registry
        registry = FieldMappingRegistry()

        # Setup parent rules
        parent_rules = dict(DEFAULT_PARENT_RULES)
        if self.config.parent_rules is not None:
            parent_rules = dict(self.config.parent_rules)

        # Create ID generator
        self.id_generator = WazuhRuleIDGenerator(
            self.config.rule_id_start,
            self.config.rule_id_end,
        )

        # Create field mapper with registry and mode
        # mapping: legacy defaults for backward compatibility
        # overrides: user-provided overrides from config
        self.field_mapper = SigmaFieldMapper(
            mapping=dict(DEFAULT_FIELD_MAPPING),
            version=self.config.field_mapping_version,
            registry=registry,
            mode=self.config.windows_field_mapping_mode,
            overrides=self.config.field_mapping or {},
        )

        # Create rule generator
        self.rule_generator = WazuhRuleGenerator(
            self.id_generator,
            self.field_mapper,
            parent_rules=parent_rules,
            limits=LoweringLimits(
                max_dnf_alternatives=self.config.max_dnf_alternatives,
                max_predicates_per_alternative=self.config.max_predicates_per_alternative,
                max_generated_child_rules=self.config.max_generated_child_rules,
                max_condition_recursion_depth=self.config.max_condition_recursion_depth,
                max_generated_rule_xml_bytes=self.config.max_generated_rule_xml_bytes,
            ),
        )

    def convert_rule(
        self,
        sigma_rule: SigmaRuleLike,
        *,
        level_override: int | None = None,
        wazuh_rule_id: int | None = None,
    ) -> Element:
        return self.rule_generator.generate(
            sigma_rule,
            level_override=level_override,
            wazuh_rule_id=wazuh_rule_id,
        )

    def convert_rules(
        self,
        sigma_rule: SigmaRuleLike,
        *,
        level_override: int | None = None,
        wazuh_rule_id: int | None = None,
    ) -> list[Element]:
        return self.rule_generator.generate_rules(
            sigma_rule,
            level_override=level_override,
            wazuh_rule_id=wazuh_rule_id,
        )

    def render_ruleset(self, rules: list[Element], *, generated_at: datetime | None = None) -> str:
        timestamp = generated_at or datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        root = Element("group")
        root.set("name", self.config.root_group_name)
        root.append(Comment(f" Sigma to Wazuh Conversion - {timestamp.isoformat()} "))
        for rule in rules:
            root.append(rule)
        return self.prettify(root)

    @staticmethod
    def prettify(elem: Element) -> str:
        rough_string = ET.tostring(elem, encoding="unicode")
        reparsed = minidom.parseString(rough_string)
        pretty_xml = reparsed.toprettyxml(indent="  ")
        lines = [
            line
            for line in pretty_xml.splitlines()
            if line.strip() and not line.lstrip().startswith("<?xml")
        ]
        return "\n".join(lines) + "\n"
