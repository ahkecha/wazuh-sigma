"""Sigma rule model and pySigma normalization boundary."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any

from sigma.exceptions import SigmaError


PYSIGMA_RULE_MODULE = "sigma.rule.rule"
PARSER_NORMALIZATION_VERSION = "pysigma-normalization-v1"
SigmaRuleDict = dict[str, Any]
ValidationResult = tuple[bool, list[str]]


class SigmaParseError(ValueError):
    """Raised when pySigma rejects a rule during normalization."""


def parse_sigma_with_pysigma(
    rule_dict: SigmaRuleDict,
    allow_pyyaml_fallback: bool = False,
) -> tuple[SigmaRuleDict, str]:
    """Parse and normalize a Sigma rule through pySigma.

    Production conversion requires pySigma. The loose PyYAML fallback exists only
    for migration/testing and must be explicitly requested by the caller.
    """
    try:
        sigma_rule_module = importlib.import_module(PYSIGMA_RULE_MODULE)
    except ImportError as error:
        if not allow_pyyaml_fallback:
            raise RuntimeError("pySigma is required for production conversion") from error
        return rule_dict, "pyyaml"

    sigma_rule_class = getattr(sigma_rule_module, "SigmaRule")
    try:
        parsed_rule = sigma_rule_class.from_dict(rule_dict)
    except SigmaError as error:
        if not allow_pyyaml_fallback:
            raise SigmaParseError(str(error)) from error
        return rule_dict, "pyyaml_after_pysigma_error"
    return parsed_rule.to_dict(), "pysigma"


@dataclass
class SigmaRule:
    """Project-local Sigma rule wrapper after pySigma normalization."""

    raw_rule: SigmaRuleDict
    source_file: str = ""

    def __post_init__(self) -> None:
        self.title = self.raw_rule.get("title", "Untitled Rule")
        self.description = self.raw_rule.get("description", "")
        self.logsource = self.raw_rule.get("logsource", {})
        self.detection = self.raw_rule.get("detection", {})
        self.tags = _metadata_list(self.raw_rule.get("tags"))
        self.references = _metadata_list(self.raw_rule.get("references"))
        self.author = self.raw_rule.get("author", "Unknown")
        self.date = self.raw_rule.get("date", "")
        self.status = self.raw_rule.get("status", "experimental")
        self.modified = self.raw_rule.get("modified", "")
        self.level = self.raw_rule.get("level", "medium")

    def get_detection_keywords(self) -> list[str]:
        """Extract string detection values for diagnostics/tests."""
        keywords: list[str] = []

        def extract_values(obj: Any) -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key not in {"condition", "selection", "filter"}:
                        extract_values(value)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, str):
                        keywords.append(item)
                    else:
                        extract_values(item)
            elif isinstance(obj, str):
                keywords.append(obj)

        extract_values(self.detection)
        return keywords

    def get_event_source(self) -> str | None:
        """Return the Sigma logsource service or product."""
        return self.logsource.get("service") or self.logsource.get("product")

    def validate(self) -> ValidationResult:
        """Return project-level validation errors for conversion."""
        errors = []
        if not self.title:
            errors.append("Rule must have a title")
        if not self.detection:
            errors.append("Rule must have detection section")
        if not self.logsource:
            errors.append("Rule must have logsource section")
        return not errors, errors


def _metadata_list(value: Any) -> list[Any]:
    """Normalize optional Sigma metadata fields that are semantically lists."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
