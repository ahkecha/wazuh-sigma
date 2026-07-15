"""Models and manifest loading for autonomous active detection tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml


class ActiveTestError(RuntimeError):
    """Raised when an autonomous active detection test cannot complete safely."""


@dataclass(frozen=True)
class CalderaAbilitySpec:
    """Safe command stimulus executed by a Caldera agent."""

    executor: str
    platform: str
    command: str
    cleanup: tuple[str, ...] = ()
    timeout: int = 60
    tactic: str = "execution"
    technique_id: str = "T1059"
    technique_name: str = "Command and Scripting Interpreter"


@dataclass(frozen=True)
class ExpectedAlertSpec:
    """Evidence required from Wazuh alert storage after the command runs."""

    rule_id: str | None = None
    rule_group: str | None = None
    marker: str | None = None
    query: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class ActiveDetectionTest:
    """One Sigma/Wazuh detection test case backed by Caldera execution."""

    name: str
    sigma_id: str | None
    caldera: CalderaAbilitySpec
    expect: ExpectedAlertSpec
    path: Path


def load_active_tests(directory: Path) -> list[ActiveDetectionTest]:
    """Load active detection test manifests from a directory of YAML files."""
    if not directory.is_dir():
        raise ActiveTestError(f"active test directory does not exist: {directory}")
    manifests = sorted([*directory.rglob("*.yml"), *directory.rglob("*.yaml")])
    if not manifests:
        raise ActiveTestError(f"no active test manifests found in {directory}")
    return [_load_active_test(path) for path in manifests]


def _load_active_test(path: Path) -> ActiveDetectionTest:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, Mapping):
        raise ActiveTestError(f"active test manifest must be a mapping: {path}")

    caldera_payload = _mapping(payload.get("caldera"), f"{path}: caldera")
    expect_payload = _mapping(payload.get("expect"), f"{path}: expect")

    caldera = CalderaAbilitySpec(
        executor=_required_str(caldera_payload, "executor", path),
        platform=str(caldera_payload.get("platform", "windows")).strip().lower(),
        command=_required_str(caldera_payload, "command", path),
        cleanup=tuple(_string_list(caldera_payload.get("cleanup", []), "cleanup", path)),
        timeout=_positive_int(caldera_payload.get("timeout", 60), "caldera.timeout", path),
        tactic=str(caldera_payload.get("tactic", "execution")),
        technique_id=str(caldera_payload.get("technique_id", "T1059")),
        technique_name=str(caldera_payload.get("technique_name", "Command and Scripting Interpreter")),
    )
    if caldera.executor not in {"cmd", "psh", "powershell", "pwsh", "sh"}:
        raise ActiveTestError(f"{path}: unsupported caldera.executor: {caldera.executor}")

    expected = ExpectedAlertSpec(
        rule_id=_optional_str(expect_payload.get("rule_id")),
        rule_group=_optional_str(expect_payload.get("rule_group")),
        marker=_optional_str(expect_payload.get("marker")),
        query=_optional_mapping(expect_payload.get("query"), path),
    )
    if not any((expected.rule_id, expected.rule_group, expected.marker, expected.query)):
        raise ActiveTestError(f"{path}: expect must include rule_id, rule_group, marker, or query")

    name = _required_str(payload, "name", path)
    return ActiveDetectionTest(
        name=name,
        sigma_id=_optional_str(payload.get("sigma_id")),
        caldera=caldera,
        expect=expected,
        path=path,
    )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ActiveTestError(f"{label} must be a mapping")
    return value


def _optional_mapping(value: Any, path: Path) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ActiveTestError(f"{path}: expect.query must be a mapping")
    return value


def _required_str(payload: Mapping[str, Any], field: str, path: Path) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ActiveTestError(f"{path}: {field} must be a non-empty string")
    return value.strip()


def _optional_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ActiveTestError("optional string fields must be strings when provided")
    normalized = value.strip()
    return normalized or None


def _string_list(value: Any, field: str, path: Path) -> list[str]:
    if not isinstance(value, list):
        raise ActiveTestError(f"{path}: {field} must be a list")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ActiveTestError(f"{path}: {field} entries must be non-empty strings")
        items.append(item.strip())
    return items


def _positive_int(value: Any, field: str, path: Path) -> int:
    if isinstance(value, bool):
        raise ActiveTestError(f"{path}: {field} must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ActiveTestError(f"{path}: {field} must be a positive integer") from error
    if parsed <= 0:
        raise ActiveTestError(f"{path}: {field} must be a positive integer")
    return parsed
