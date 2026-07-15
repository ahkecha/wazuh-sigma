"""Configuration loading for the Wazuh Sigma pipeline."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from wazuh_sigma.backend import (
    DEFAULT_FIELD_MAPPING_VERSION,
    DEFAULT_PARENT_RULES,
    DEFAULT_RULE_ID_END,
    DEFAULT_RULE_ID_START,
)
from wazuh_sigma.wazuh_contract import validate_remote_rule_filename, validate_wazuh_host


DEFAULT_SIGMA_DIR = Path("rules/sigma")
DEFAULT_BUILD_DIR = Path("build")
DEFAULT_OUTPUT_FILE = Path("build/sigmahq/sigma_rules.xml")
DEFAULT_CONVERSION_REPORT = Path("build/conversion-report.json")
DEFAULT_SMOKE_REPORT = Path("build/sigma-smoke-report.json")
DEFAULT_ACTIVE_TEST_DIR = Path("tests/active")
DEFAULT_GENERATED_ACTIVE_TEST_DIR = Path("build/active-tests")
DEFAULT_ACTIVE_TEST_REPORT = Path("build/active-test-report.json")
DEFAULT_STRICT_VALIDATION = False
DEFAULT_WAZUH_HOST = "https://example:55000"
DEFAULT_REMOTE_FILE = "sigma_rules.xml"
DEFAULT_BACKUP_DIR = Path("backups/wazuh")
DEFAULT_WAZUH_TIMEOUT = 30
DEFAULT_ADVISOR_CACHE_DIR = Path("build/advisor-cache")
DEFAULT_INCREMENTAL_CACHE_DIR = Path("build/conversion-cache")
DEFAULT_INCREMENTAL_MANIFEST = Path("build/conversion-cache/manifest.json")
DEFAULT_CALDERA_URL = "http://localhost:8888"
DEFAULT_ALERT_INDEX = "wazuh-alerts-*"
ADVISOR_MODES = frozenset({"report-only", "review", "apply"})
PIPELINE_CONFIG_KEYS = frozenset({
    "sigma_dir",
    "build_dir",
    "output_file",
    "conversion_report",
    "smoke_report",
    "strict_validation",
    "wazuh",
    "advisor",
    "incremental_cache",
    "active_test",
})
ADVISOR_CONFIG_KEYS = frozenset({
    "enabled",
    "mode",
    "provider",
    "primary_model",
    "escalation_model",
    "timeout_seconds",
    "max_retries",
    "max_output_tokens",
    "minimum_confidence",
    "maximum_level_delta",
    "fail_open",
    "cache_enabled",
    "cache_directory",
    "changed_only",
    "strict_sanitization",
    "escalation",
})
ADVISOR_ESCALATION_KEYS = frozenset({
    "enabled",
    "confidence_below",
    "max_requests",
})
WAZUH_CONFIG_KEYS = frozenset({
    "host",
    "insecure",
    "timeout",
    "ca_bundle",
    "rule_id_start",
    "rule_id_end",
    "field_mapping_version",
    "field_mapping",
    "parent_rules",
    "remote_file",
    "backup_dir",
})
INCREMENTAL_CACHE_CONFIG_KEYS = frozenset({
    "enabled",
    "directory",
    "manifest",
    "strict",
})
ACTIVE_TEST_CONFIG_KEYS = frozenset({
    "enabled",
    "test_dir",
    "generated_test_dir",
    "report",
    "generate_with_openai",
    "openai_model",
    "openai_api_key_env",
    "openai_timeout_seconds",
    "openai_max_output_tokens",
    "openai_max_retries",
    "caldera_url",
    "caldera_api_key_env",
    "caldera_auth_header",
    "caldera_auth_scheme",
    "agent_platform",
    "agent_group",
    "operation_timeout_seconds",
    "operation_poll_interval_seconds",
    "alert_indexer_url",
    "alert_index",
    "alert_username_env",
    "alert_password_env",
    "alert_timeout_seconds",
    "alert_poll_interval_seconds",
    "insecure",
    "ca_bundle",
})


class PipelineConfigError(ValueError):
    """Raised when pipeline.yml contains invalid values."""


@dataclass(frozen=True)
class WazuhDeployConfig:
    host: str = DEFAULT_WAZUH_HOST
    insecure: bool = False
    timeout: int = DEFAULT_WAZUH_TIMEOUT
    ca_bundle: Path | None = None
    rule_id_start: int = DEFAULT_RULE_ID_START
    rule_id_end: int = DEFAULT_RULE_ID_END
    field_mapping_version: str = DEFAULT_FIELD_MAPPING_VERSION
    field_mapping: dict[str, str] | None = None
    parent_rules: dict[str, list[int]] | None = None
    remote_file: str = DEFAULT_REMOTE_FILE
    backup_dir: Path = DEFAULT_BACKUP_DIR

    def __post_init__(self) -> None:
        normalized_host = validate_wazuh_host(self.host, error_type=PipelineConfigError).rstrip("/")
        if self.timeout <= 0:
            raise PipelineConfigError("wazuh.timeout must be a positive integer")
        if self.rule_id_start <= 0 or self.rule_id_end <= 0:
            raise PipelineConfigError("wazuh rule IDs must be positive integers")
        if self.rule_id_start > self.rule_id_end:
            raise PipelineConfigError("wazuh.rule_id_start must be <= wazuh.rule_id_end")
        if self.rule_id_end > 9_999_999:
            raise PipelineConfigError("wazuh.rule_id_end must be at most 9999999")
        normalized_mapping_version = _as_non_empty_str(
            self.field_mapping_version,
            "wazuh.field_mapping_version",
        )
        normalized_remote_file = validate_remote_rule_filename(self.remote_file, error_type=PipelineConfigError)
        object.__setattr__(self, "host", normalized_host)
        object.__setattr__(self, "field_mapping_version", normalized_mapping_version)
        object.__setattr__(self, "field_mapping", _normalize_field_mapping(self.field_mapping))
        object.__setattr__(self, "parent_rules", _normalize_parent_rules(self.parent_rules))
        object.__setattr__(self, "remote_file", normalized_remote_file)


@dataclass(frozen=True)
class AdvisorConfig:
    """Typed, validated configuration for the optional OpenAI advisor.

    The advisor is disabled by default and defaults to report-only mode, so a
    default-constructed config never changes deterministic conversion. All
    numeric bounds are validated at construction; unknown YAML keys are rejected
    during parsing (see :func:`_advisor_from_value`).
    """

    enabled: bool = False
    mode: str = "report-only"
    provider: str = "openai"
    primary_model: str | None = None
    escalation_model: str | None = None
    timeout_seconds: int = 30
    max_retries: int = 3
    max_output_tokens: int = 400
    minimum_confidence: float = 0.80
    maximum_level_delta: int = 2
    fail_open: bool = True
    cache_enabled: bool = True
    cache_directory: Path = DEFAULT_ADVISOR_CACHE_DIR
    changed_only: bool = True
    strict_sanitization: bool = False
    escalation_enabled: bool = True
    escalation_confidence_below: float = 0.70
    max_requests: int | None = None

    def __post_init__(self) -> None:
        if self.mode not in ADVISOR_MODES:
            raise PipelineConfigError(f"advisor.mode must be one of: {', '.join(sorted(ADVISOR_MODES))}")
        if self.provider != "openai":
            raise PipelineConfigError("advisor.provider must be 'openai'")
        # No speculative default model IDs: an enabled advisor must name a model
        # the account actually has access to.
        if self.enabled and not self.primary_model:
            raise PipelineConfigError(
                "advisor.primary_model is required when the advisor is enabled"
            )
        if self.primary_model is not None:
            _as_non_empty_str(self.primary_model, "advisor.primary_model")
        if self.escalation_model is not None:
            _as_non_empty_str(self.escalation_model, "advisor.escalation_model")
        if self.timeout_seconds <= 0:
            raise PipelineConfigError("advisor.timeout_seconds must be a positive integer")
        if self.max_retries < 0:
            raise PipelineConfigError("advisor.max_retries must be non-negative")
        if self.max_output_tokens <= 0:
            raise PipelineConfigError("advisor.max_output_tokens must be a positive integer")
        if not 0.0 <= self.minimum_confidence <= 1.0:
            raise PipelineConfigError("advisor.minimum_confidence must be within 0.0-1.0")
        if self.maximum_level_delta < 0:
            raise PipelineConfigError("advisor.maximum_level_delta must be non-negative")
        if not 0.0 <= self.escalation_confidence_below <= 1.0:
            raise PipelineConfigError("advisor.escalation.confidence_below must be within 0.0-1.0")
        if self.max_requests is not None and self.max_requests <= 0:
            raise PipelineConfigError("advisor.escalation.max_requests must be a positive integer")


@dataclass(frozen=True)
class IncrementalCacheConfig:
    """Configuration for optional incremental conversion caching.

    The incremental cache is disabled by default. When enabled, it maintains
    persistent rule IDs and reuses unchanged rule XML from prior conversions.

    Manifest and cache are stored separately; the manifest is the source of
    truth for rule identity and ID allocation. Unknown YAML keys are rejected
    during parsing (see :func:`_incremental_cache_from_value`).
    """

    enabled: bool = False
    directory: Path = DEFAULT_INCREMENTAL_CACHE_DIR
    manifest: Path = DEFAULT_INCREMENTAL_MANIFEST
    strict: bool = False

    def __post_init__(self) -> None:
        if self.manifest.suffix.lower() != ".json":
            raise PipelineConfigError("incremental_cache.manifest must be a .json file")
        if self.manifest.name in {"", ".", ".."}:
            raise PipelineConfigError("incremental_cache.manifest must be a file path")
        if self.directory == self.manifest:
            raise PipelineConfigError("incremental_cache.directory and manifest must be different paths")


@dataclass(frozen=True)
class ActiveTestConfig:
    """Configuration for autonomous Caldera-to-Wazuh detection validation."""

    enabled: bool = False
    test_dir: Path = DEFAULT_ACTIVE_TEST_DIR
    generated_test_dir: Path = DEFAULT_GENERATED_ACTIVE_TEST_DIR
    report: Path = DEFAULT_ACTIVE_TEST_REPORT
    generate_with_openai: bool = False
    openai_model: str | None = None
    openai_api_key_env: str = "OPENAI_API_KEY"
    openai_timeout_seconds: int = 30
    openai_max_output_tokens: int = 800
    openai_max_retries: int = 3
    caldera_url: str = DEFAULT_CALDERA_URL
    caldera_api_key_env: str = "CALDERA_API_KEY"
    caldera_auth_header: str = "KEY"
    caldera_auth_scheme: str = ""
    agent_platform: str = "windows"
    agent_group: str | None = None
    operation_timeout_seconds: int = 180
    operation_poll_interval_seconds: int = 5
    alert_indexer_url: str | None = None
    alert_index: str = DEFAULT_ALERT_INDEX
    alert_username_env: str = "WAZUH_INDEXER_USER"
    alert_password_env: str = "WAZUH_INDEXER_PASSWORD"
    alert_timeout_seconds: int = 120
    alert_poll_interval_seconds: int = 5
    insecure: bool = False
    ca_bundle: Path | None = None

    def __post_init__(self) -> None:
        normalized_caldera_url = validate_wazuh_host(
            self.caldera_url,
            error_type=PipelineConfigError,
        ).rstrip("/")
        if self.alert_indexer_url is not None:
            normalized_alert_url = validate_wazuh_host(
                self.alert_indexer_url,
                error_type=PipelineConfigError,
            ).rstrip("/")
            object.__setattr__(self, "alert_indexer_url", normalized_alert_url)
        if not self.caldera_auth_header.strip():
            raise PipelineConfigError("active_test.caldera_auth_header must not be empty")
        if not self.caldera_api_key_env.strip():
            raise PipelineConfigError("active_test.caldera_api_key_env must not be empty")
        if not self.openai_api_key_env.strip():
            raise PipelineConfigError("active_test.openai_api_key_env must not be empty")
        if self.generate_with_openai and not self.openai_model:
            raise PipelineConfigError("active_test.openai_model is required when generate_with_openai is true")
        if self.openai_model is not None:
            _as_non_empty_str(self.openai_model, "active_test.openai_model")
        if not self.alert_username_env.strip() or not self.alert_password_env.strip():
            raise PipelineConfigError("active_test alert credential env names must not be empty")
        if not self.alert_index.strip():
            raise PipelineConfigError("active_test.alert_index must not be empty")
        if self.agent_platform.lower() != self.agent_platform:
            object.__setattr__(self, "agent_platform", self.agent_platform.lower())
        for field_name in (
            "operation_timeout_seconds",
            "operation_poll_interval_seconds",
            "openai_timeout_seconds",
            "openai_max_output_tokens",
            "alert_timeout_seconds",
            "alert_poll_interval_seconds",
        ):
            if getattr(self, field_name) <= 0:
                raise PipelineConfigError(f"active_test.{field_name} must be a positive integer")
        if self.openai_max_retries < 0:
            raise PipelineConfigError("active_test.openai_max_retries must be non-negative")
        object.__setattr__(self, "caldera_url", normalized_caldera_url)


@dataclass(frozen=True)
class PipelineConfig:
    sigma_dir: Path = DEFAULT_SIGMA_DIR
    build_dir: Path = DEFAULT_BUILD_DIR
    output_file: Path = DEFAULT_OUTPUT_FILE
    conversion_report: Path = DEFAULT_CONVERSION_REPORT
    smoke_report: Path = DEFAULT_SMOKE_REPORT
    strict_validation: bool = DEFAULT_STRICT_VALIDATION
    wazuh: WazuhDeployConfig = field(default_factory=WazuhDeployConfig)
    advisor: AdvisorConfig = field(default_factory=AdvisorConfig)
    incremental_cache: IncrementalCacheConfig = field(default_factory=IncrementalCacheConfig)
    active_test: ActiveTestConfig = field(default_factory=ActiveTestConfig)

    @classmethod
    def from_file(cls, path: Path | str) -> "PipelineConfig":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"pipeline config does not exist: {path}")
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(payload, Mapping):
            raise ValueError(f"pipeline config must be a YAML mapping: {path}")
        return cls.from_mapping(payload, base_dir=path.resolve().parent)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any], *, base_dir: Path | None = None) -> "PipelineConfig":
        _reject_unknown_keys(payload, PIPELINE_CONFIG_KEYS, namespace="pipeline")
        wazuh_payload = payload.get("wazuh", {}) or {}
        if not isinstance(wazuh_payload, Mapping):
            raise PipelineConfigError("wazuh config must be a mapping")
        _reject_unknown_keys(wazuh_payload, WAZUH_CONFIG_KEYS, namespace="wazuh")
        wazuh = WazuhDeployConfig(
            host=str(wazuh_payload.get("host", DEFAULT_WAZUH_HOST)),
            insecure=_as_bool(wazuh_payload.get("insecure", False), field_name="wazuh.insecure"),
            timeout=_as_positive_int(wazuh_payload.get("timeout", DEFAULT_WAZUH_TIMEOUT), "wazuh.timeout"),
            ca_bundle=_optional_path(wazuh_payload.get("ca_bundle"), "wazuh.ca_bundle", base_dir=base_dir),
            rule_id_start=_as_int(
                wazuh_payload.get("rule_id_start", DEFAULT_RULE_ID_START),
                "wazuh.rule_id_start",
            ),
            rule_id_end=_as_int(
                wazuh_payload.get("rule_id_end", DEFAULT_RULE_ID_END),
                "wazuh.rule_id_end",
            ),
            field_mapping_version=_as_non_empty_str(
                wazuh_payload.get("field_mapping_version", DEFAULT_FIELD_MAPPING_VERSION),
                "wazuh.field_mapping_version",
            ),
            field_mapping=_field_mapping_from_value(wazuh_payload.get("field_mapping")),
            parent_rules=_parent_rules_from_value(wazuh_payload.get("parent_rules")),
            remote_file=str(wazuh_payload.get("remote_file", DEFAULT_REMOTE_FILE)),
            backup_dir=_path_from_value(wazuh_payload.get("backup_dir", DEFAULT_BACKUP_DIR), base_dir=base_dir),
        )
        return cls(
            sigma_dir=_path_from_value(payload.get("sigma_dir", DEFAULT_SIGMA_DIR), base_dir=base_dir),
            build_dir=_path_from_value(payload.get("build_dir", DEFAULT_BUILD_DIR), base_dir=base_dir),
            output_file=_path_from_value(payload.get("output_file", DEFAULT_OUTPUT_FILE), base_dir=base_dir),
            conversion_report=_path_from_value(
                payload.get("conversion_report", DEFAULT_CONVERSION_REPORT),
                base_dir=base_dir,
            ),
            smoke_report=_path_from_value(payload.get("smoke_report", DEFAULT_SMOKE_REPORT), base_dir=base_dir),
            strict_validation=_as_bool(
                payload.get("strict_validation", DEFAULT_STRICT_VALIDATION),
                field_name="strict_validation",
            ),
            wazuh=wazuh,
            advisor=_advisor_from_value(payload.get("advisor"), base_dir=base_dir),
            incremental_cache=_incremental_cache_from_value(payload.get("incremental_cache"), base_dir=base_dir),
            active_test=_active_test_from_value(payload.get("active_test"), base_dir=base_dir),
        )


def _as_bool(value: Any, *, field_name: str = "value") -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise PipelineConfigError(f"{field_name} must be a boolean")


def _as_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise PipelineConfigError(f"{field_name} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise PipelineConfigError(f"{field_name} must be an integer") from error


def _as_positive_int(value: Any, field_name: str) -> int:
    parsed = _as_int(value, field_name)
    if parsed <= 0:
        raise PipelineConfigError(f"{field_name} must be a positive integer")
    return parsed


def _as_non_empty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise PipelineConfigError(f"{field_name} must be a string")
    normalized = value.strip()
    if not normalized:
        raise PipelineConfigError(f"{field_name} must not be empty")
    return normalized


def _as_float(value: Any, field_name: str) -> float:
    if isinstance(value, bool):
        raise PipelineConfigError(f"{field_name} must be a number")
    if isinstance(value, (int, float)):
        return float(value)
    raise PipelineConfigError(f"{field_name} must be a number")


def _optional_non_empty_str(value: Any, field_name: str) -> str | None:
    if value in (None, ""):
        return None
    return _as_non_empty_str(value, field_name)


def _advisor_from_value(value: Any, *, base_dir: Path | None = None) -> "AdvisorConfig":
    if value is None:
        return AdvisorConfig()
    if not isinstance(value, Mapping):
        raise PipelineConfigError("advisor config must be a mapping")
    _reject_unknown_keys(value, ADVISOR_CONFIG_KEYS, namespace="advisor")

    escalation_payload = value.get("escalation", {}) or {}
    if not isinstance(escalation_payload, Mapping):
        raise PipelineConfigError("advisor.escalation config must be a mapping")
    _reject_unknown_keys(escalation_payload, ADVISOR_ESCALATION_KEYS, namespace="advisor.escalation")

    max_requests_value = escalation_payload.get("max_requests")
    max_requests = (
        None if max_requests_value in (None, "")
        else _as_positive_int(max_requests_value, "advisor.escalation.max_requests")
    )

    return AdvisorConfig(
        enabled=_as_bool(value.get("enabled", False), field_name="advisor.enabled"),
        mode=str(value.get("mode", "report-only")),
        provider=str(value.get("provider", "openai")),
        primary_model=_optional_non_empty_str(
            value.get("primary_model"),
            "advisor.primary_model",
        ),
        escalation_model=_optional_non_empty_str(
            value.get("escalation_model"),
            "advisor.escalation_model",
        ),
        timeout_seconds=_as_positive_int(value.get("timeout_seconds", 30), "advisor.timeout_seconds"),
        max_retries=_as_int(value.get("max_retries", 3), "advisor.max_retries"),
        max_output_tokens=_as_positive_int(value.get("max_output_tokens", 400), "advisor.max_output_tokens"),
        minimum_confidence=_as_float(value.get("minimum_confidence", 0.80), "advisor.minimum_confidence"),
        maximum_level_delta=_as_int(value.get("maximum_level_delta", 2), "advisor.maximum_level_delta"),
        fail_open=_as_bool(value.get("fail_open", True), field_name="advisor.fail_open"),
        cache_enabled=_as_bool(value.get("cache_enabled", True), field_name="advisor.cache_enabled"),
        cache_directory=_path_from_value(
            value.get("cache_directory", DEFAULT_ADVISOR_CACHE_DIR),
            base_dir=base_dir,
        ),
        changed_only=_as_bool(value.get("changed_only", True), field_name="advisor.changed_only"),
        strict_sanitization=_as_bool(
            value.get("strict_sanitization", False),
            field_name="advisor.strict_sanitization",
        ),
        escalation_enabled=_as_bool(
            escalation_payload.get("enabled", True),
            field_name="advisor.escalation.enabled",
        ),
        escalation_confidence_below=_as_float(
            escalation_payload.get("confidence_below", 0.70),
            "advisor.escalation.confidence_below",
        ),
        max_requests=max_requests,
    )


def _incremental_cache_from_value(value: Any, *, base_dir: Path | None = None) -> "IncrementalCacheConfig":
    if value is None:
        return IncrementalCacheConfig()
    if not isinstance(value, Mapping):
        raise PipelineConfigError("incremental_cache config must be a mapping")
    _reject_unknown_keys(value, INCREMENTAL_CACHE_CONFIG_KEYS, namespace="incremental_cache")

    return IncrementalCacheConfig(
        enabled=_as_bool(value.get("enabled", False), field_name="incremental_cache.enabled"),
        directory=_path_from_value(
            value.get("directory", DEFAULT_INCREMENTAL_CACHE_DIR),
            base_dir=base_dir,
        ),
        manifest=_path_from_value(
            value.get("manifest", DEFAULT_INCREMENTAL_MANIFEST),
            base_dir=base_dir,
        ),
        strict=_as_bool(value.get("strict", False), field_name="incremental_cache.strict"),
    )


def _active_test_from_value(value: Any, *, base_dir: Path | None = None) -> "ActiveTestConfig":
    if value is None:
        return ActiveTestConfig()
    if not isinstance(value, Mapping):
        raise PipelineConfigError("active_test config must be a mapping")
    _reject_unknown_keys(value, ACTIVE_TEST_CONFIG_KEYS, namespace="active_test")
    return ActiveTestConfig(
        enabled=_as_bool(value.get("enabled", False), field_name="active_test.enabled"),
        test_dir=_path_from_value(value.get("test_dir", DEFAULT_ACTIVE_TEST_DIR), base_dir=base_dir),
        generated_test_dir=_path_from_value(
            value.get("generated_test_dir", DEFAULT_GENERATED_ACTIVE_TEST_DIR),
            base_dir=base_dir,
        ),
        report=_path_from_value(value.get("report", DEFAULT_ACTIVE_TEST_REPORT), base_dir=base_dir),
        generate_with_openai=_as_bool(
            value.get("generate_with_openai", False),
            field_name="active_test.generate_with_openai",
        ),
        openai_model=_optional_non_empty_str(value.get("openai_model"), "active_test.openai_model"),
        openai_api_key_env=str(value.get("openai_api_key_env", "OPENAI_API_KEY")),
        openai_timeout_seconds=_as_positive_int(
            value.get("openai_timeout_seconds", 30),
            "active_test.openai_timeout_seconds",
        ),
        openai_max_output_tokens=_as_positive_int(
            value.get("openai_max_output_tokens", 800),
            "active_test.openai_max_output_tokens",
        ),
        openai_max_retries=_as_int(
            value.get("openai_max_retries", 3),
            "active_test.openai_max_retries",
        ),
        caldera_url=str(value.get("caldera_url", DEFAULT_CALDERA_URL)),
        caldera_api_key_env=str(value.get("caldera_api_key_env", "CALDERA_API_KEY")),
        caldera_auth_header=str(value.get("caldera_auth_header", "KEY")),
        caldera_auth_scheme=str(value.get("caldera_auth_scheme", "")),
        agent_platform=str(value.get("agent_platform", "windows")).strip().lower(),
        agent_group=_optional_non_empty_str(value.get("agent_group"), "active_test.agent_group"),
        operation_timeout_seconds=_as_positive_int(
            value.get("operation_timeout_seconds", 180),
            "active_test.operation_timeout_seconds",
        ),
        operation_poll_interval_seconds=_as_positive_int(
            value.get("operation_poll_interval_seconds", 5),
            "active_test.operation_poll_interval_seconds",
        ),
        alert_indexer_url=_optional_non_empty_str(
            value.get("alert_indexer_url"),
            "active_test.alert_indexer_url",
        ),
        alert_index=str(value.get("alert_index", DEFAULT_ALERT_INDEX)),
        alert_username_env=str(value.get("alert_username_env", "WAZUH_INDEXER_USER")),
        alert_password_env=str(value.get("alert_password_env", "WAZUH_INDEXER_PASSWORD")),
        alert_timeout_seconds=_as_positive_int(
            value.get("alert_timeout_seconds", 120),
            "active_test.alert_timeout_seconds",
        ),
        alert_poll_interval_seconds=_as_positive_int(
            value.get("alert_poll_interval_seconds", 5),
            "active_test.alert_poll_interval_seconds",
        ),
        insecure=_as_bool(value.get("insecure", False), field_name="active_test.insecure"),
        ca_bundle=_optional_path(value.get("ca_bundle"), "active_test.ca_bundle", base_dir=base_dir),
    )


def _path_from_value(value: Any, *, base_dir: Path | None = None) -> Path:
    if isinstance(value, bool) or not isinstance(value, (str, Path)):
        raise PipelineConfigError("pipeline path values must be filesystem paths")
    path = Path(value)
    if base_dir is not None and not path.is_absolute():
        return base_dir / path
    return path


def _optional_path(value: Any, field_name: str, *, base_dir: Path | None = None) -> Path | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool) or not isinstance(value, (str, Path)):
        raise PipelineConfigError(f"{field_name} must be a filesystem path")
    if not str(value).strip():
        return None
    return _path_from_value(value, base_dir=base_dir)


def _field_mapping_from_value(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise PipelineConfigError("wazuh.field_mapping must be a mapping")
    return {
        _as_non_empty_str(key, "wazuh.field_mapping keys"): _as_non_empty_str(
            mapped,
            f"wazuh.field_mapping.{key}",
        )
        for key, mapped in value.items()
    }


def _parent_rules_from_value(value: Any) -> dict[str, list[int]] | None:
    if value is None:
        return dict(DEFAULT_PARENT_RULES)
    if not isinstance(value, Mapping):
        raise PipelineConfigError("wazuh.parent_rules must be a mapping")

    normalized: dict[str, list[int]] = {}
    for section, section_value in value.items():
        section_name = _as_non_empty_str(str(section), "wazuh.parent_rules keys").lower()
        if section_name in {"product", "service", "category", "security_event_id"}:
            if not isinstance(section_value, Mapping):
                raise PipelineConfigError(f"wazuh.parent_rules.{section_name} must be a mapping")
            for source, rule_ids in section_value.items():
                source_name = _as_non_empty_str(
                    str(source),
                    f"wazuh.parent_rules.{section_name} keys",
                ).lower()
                normalized[f"{section_name}:{source_name}"] = _parent_rule_ids_from_value(
                    rule_ids,
                    f"wazuh.parent_rules.{section_name}.{source}",
                )
            continue

        normalized[section_name] = _parent_rule_ids_from_value(
            section_value,
            f"wazuh.parent_rules.{section}",
        )

    return normalized


def _parent_rule_ids_from_value(value: Any, field_name: str) -> list[int]:
    raw_values = value if isinstance(value, list) else [value]
    if not raw_values:
        raise PipelineConfigError(f"{field_name} must contain at least one rule ID")
    rule_ids = [_as_int(raw_value, field_name) for raw_value in raw_values]
    if any(rule_id <= 0 for rule_id in rule_ids):
        raise PipelineConfigError(f"{field_name} rule IDs must be positive integers")
    return list(dict.fromkeys(rule_ids))


def _normalize_field_mapping(mapping: dict[str, str] | None) -> dict[str, str] | None:
    if mapping is None:
        return None

    normalized: dict[str, str] = {}
    for sigma_field, wazuh_field in mapping.items():
        sigma_field = _as_non_empty_str(sigma_field, "wazuh.field_mapping keys")
        wazuh_field = _as_non_empty_str(wazuh_field, f"wazuh.field_mapping.{sigma_field}")
        normalized[sigma_field] = wazuh_field
    return normalized


def _normalize_parent_rules(parent_rules: dict[str, list[int]] | None) -> dict[str, list[int]] | None:
    if parent_rules is None:
        return None

    return {
        _as_non_empty_str(str(source), "wazuh.parent_rules keys").lower(): [
            _as_positive_int(rule_id, f"wazuh.parent_rules.{source}")
            for rule_id in rule_ids
        ]
        for source, rule_ids in parent_rules.items()
    }


def env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    return default if value is None else _as_bool(value, field_name=name)


def _reject_unknown_keys(payload: Mapping[str, Any], allowed_keys: frozenset[str], *, namespace: str) -> None:
    unknown = sorted(str(key) for key in payload if key not in allowed_keys)
    if unknown:
        allowed = ", ".join(sorted(allowed_keys))
        raise PipelineConfigError(
            f"unknown {namespace} config key(s): {', '.join(unknown)}. Allowed keys: {allowed}"
        )
