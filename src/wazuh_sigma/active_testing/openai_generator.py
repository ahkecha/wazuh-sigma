"""OpenAI-backed generation of Caldera active-test manifests.

This module only proposes safe Caldera stimuli. It does not deploy Wazuh rules,
modify generated XML, or decide whether a detection passed. The existing active
test runner remains authoritative by executing the generated manifest through
Caldera and verifying Wazuh alerts.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from wazuh_sigma.active_testing.models import ActiveTestError, load_active_tests
from wazuh_sigma.naming import sigma_group_name
from wazuh_sigma.sigma import SigmaRule, parse_sigma_with_pysigma

logger = logging.getLogger("SigmaActiveTest.openai")

DEFAULT_ACTIVE_TEST_MODEL_ENV = "OPENAI_API_KEY"
PROMPT_VERSION = "caldera-active-test-v1"
OUTPUT_SCHEMA_VERSION = "caldera-active-test-output-v1"
MARKER_TEMPLATE = "{{marker}}"
BACKOFF_BASE_SECONDS = 0.5
BACKOFF_MAX_SECONDS = 8.0


class OpenAIActiveTestGenerationError(ActiveTestError):
    """Base error for OpenAI-backed active-test manifest generation failures."""

    retryable = False
    hint = "Review the generation error and retry after correcting configuration or prompt inputs."


class OpenAIActiveTestRateLimitError(OpenAIActiveTestGenerationError):
    """Raised when the OpenAI API rate-limits active-test generation."""

    retryable = True
    hint = "Retry later, lower concurrency, reduce generation volume, or use another model/API key with quota."


class OpenAIActiveTestAuthenticationError(OpenAIActiveTestGenerationError):
    """Raised when the OpenAI API rejects credentials."""

    hint = "Check OPENAI_API_KEY or active_test.openai_api_key_env."


class OpenAIActiveTestConfigurationError(OpenAIActiveTestGenerationError):
    """Raised when the OpenAI API rejects request configuration."""

    hint = "Check active_test.openai_model, model access, schema support, and max output token settings."


class OpenAIActiveTestUnavailableError(OpenAIActiveTestGenerationError):
    """Raised for transient OpenAI transport, timeout, or server-side failures."""

    retryable = True
    hint = "Retry later; if it persists, reduce request volume or check API/service availability."


class OpenAIActiveTestSchemaError(OpenAIActiveTestGenerationError):
    """Raised when the provider output does not match the strict manifest schema."""

    hint = "The provider returned malformed structured output; retry or adjust the generation prompt/schema."


class OpenAIActiveTestRefusalError(OpenAIActiveTestGenerationError):
    """Raised when the provider refuses active-test manifest generation."""

    hint = "Use a safer Sigma test target or hand-write a benign active-test manifest."


class GeneratedCalderaTest(BaseModel):
    """Strict structured output expected from the OpenAI generator."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=120)
    executor: Literal["cmd", "psh", "powershell", "pwsh"]
    platform: Literal["windows"] = "windows"
    command: str = Field(min_length=1, max_length=2000)
    cleanup: list[str] = Field(default_factory=list, max_length=8)
    timeout: int = Field(default=60, ge=1, le=300)
    tactic: str = Field(default="execution", min_length=1, max_length=80)
    technique_id: str = Field(default="T1059", min_length=1, max_length=32)
    technique_name: str = Field(
        default="Command and Scripting Interpreter",
        min_length=1,
        max_length=120,
    )
    expected_marker_field: str = Field(
        default="full_log",
        min_length=1,
        max_length=120,
        description="Human-readable hint only; Wazuh matching still uses the marker query.",
    )
    rationale: str = Field(min_length=1, max_length=500)
    safety_notes: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("command")
    @classmethod
    def _command_must_include_marker(cls, value: str) -> str:
        if MARKER_TEMPLATE not in value:
            raise ValueError(f"command must include {MARKER_TEMPLATE}")
        return value

    @field_validator("cleanup")
    @classmethod
    def _cleanup_commands_must_be_bounded(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item.strip():
                raise ValueError("cleanup commands must be non-empty")
            if len(item) > 1000:
                raise ValueError("cleanup commands must be at most 1000 characters")
        return value


@dataclass(frozen=True)
class ActiveTestGenerationRuntime:
    """Runtime settings for OpenAI-backed active-test manifest generation."""

    sigma_dir: Path
    output_dir: Path
    model: str
    api_key_env: str = DEFAULT_ACTIVE_TEST_MODEL_ENV
    timeout_seconds: int = 30
    max_output_tokens: int = 800
    max_retries: int = 3
    overwrite: bool = False


def generate_active_tests_with_openai(
    runtime: ActiveTestGenerationRuntime,
    *,
    provider: "CalderaTestProvider | None" = None,
) -> dict[str, Any]:
    """Generate strict active-test manifests for every Sigma rule in ``sigma_dir``."""
    if not runtime.model.strip():
        raise ActiveTestError("active_test.openai_model is required when generating active tests")
    if runtime.timeout_seconds <= 0:
        raise ActiveTestError("active_test.openai_timeout_seconds must be positive")
    if runtime.max_output_tokens <= 0:
        raise ActiveTestError("active_test.openai_max_output_tokens must be positive")
    if runtime.max_retries < 0:
        raise ActiveTestError("active_test.openai_max_retries must be non-negative")

    sigma_rules = _load_sigma_rules(runtime.sigma_dir)
    if not sigma_rules:
        raise ActiveTestError(f"no Sigma rules found in {runtime.sigma_dir}")

    runtime.output_dir.mkdir(parents=True, exist_ok=True)
    if provider is None:
        provider = OpenAICalderaTestProvider.from_env(
            api_key_env=runtime.api_key_env,
            max_retries=runtime.max_retries,
        )

    report: dict[str, Any] = {
        "status": "started",
        "prompt_version": PROMPT_VERSION,
        "output_schema_version": OUTPUT_SCHEMA_VERSION,
        "sigma_dir": str(runtime.sigma_dir),
        "output_dir": str(runtime.output_dir),
        "model": runtime.model,
        "total": len(sigma_rules),
        "generated": 0,
        "failed": 0,
        "skipped": 0,
        "results": [],
    }

    for sigma_rule in sigma_rules:
        result = _generate_one(runtime, provider, sigma_rule)
        report["results"].append(result)
        if result["status"] == "generated":
            report["generated"] += 1
        elif result["status"] == "skipped":
            report["skipped"] += 1
        else:
            report["failed"] += 1

    report["status"] = "succeeded" if report["failed"] == 0 else "failed"
    if report["failed"]:
        raise ActiveTestError(f"{report['failed']} active test manifest generation(s) failed")

    # Prove the generated YAML is accepted by the active-test manifest loader.
    loaded = load_active_tests(runtime.output_dir)
    report["validated_manifests"] = len(loaded)
    return report


class CalderaTestProvider(Protocol):
    """Provider protocol kept simple for tests and future non-OpenAI providers."""

    def generate(self, request: Mapping[str, Any], metadata: Mapping[str, Any]) -> GeneratedCalderaTest:
        """Return one strict generated Caldera test."""
        ...


class OpenAICalderaTestProvider(CalderaTestProvider):
    """Structured-output provider backed by the OpenAI Responses API."""

    def __init__(
        self,
        client: Any,
        *,
        max_retries: int = 3,
        sleeper: Any = time.sleep,
    ) -> None:
        if max_retries < 0:
            raise OpenAIActiveTestConfigurationError("active test generation max_retries must be non-negative")
        self._client = client
        self._max_retries = max_retries
        self._sleeper = sleeper

    @classmethod
    def from_env(
        cls,
        *,
        api_key_env: str = DEFAULT_ACTIVE_TEST_MODEL_ENV,
        max_retries: int = 3,
    ) -> "OpenAICalderaTestProvider":
        api_key = os.getenv(api_key_env)
        if not api_key:
            raise OpenAIActiveTestConfigurationError(
                f"active test generation requires {api_key_env}; export it or disable --generate-tests"
            )
        try:
            from openai import OpenAI
        except ImportError as error:  # pragma: no cover - only hit without optional dependency
            raise OpenAIActiveTestConfigurationError("the OpenAI SDK is required for active test generation") from error
        return cls(OpenAI(api_key=api_key, max_retries=0), max_retries=max_retries)

    def generate(self, request: Mapping[str, Any], metadata: Mapping[str, Any]) -> GeneratedCalderaTest:
        attempt = 0
        while True:
            try:
                response = self._invoke(request, metadata)
                break
            except OpenAIActiveTestGenerationError as error:
                if not error.retryable or attempt >= self._max_retries:
                    raise
                attempt += 1
                delay = _backoff_delay(attempt)
                logger.warning(
                    "Transient OpenAI active-test generation error (%s); retry %d/%d after %.2fs",
                    type(error).__name__,
                    attempt,
                    self._max_retries,
                    delay,
                )
                self._sleeper(delay)

        parsed = getattr(response, "output_parsed", None) or _extract_parsed_response(response)
        try:
            if isinstance(parsed, GeneratedCalderaTest):
                return parsed
            if hasattr(parsed, "model_dump"):
                parsed = parsed.model_dump()
            return GeneratedCalderaTest.model_validate(parsed)
        except ValidationError as error:
            raise OpenAIActiveTestSchemaError(
                f"OpenAI active test generation returned invalid schema: {error.error_count()} error(s)"
            ) from error

    def _invoke(self, request: Mapping[str, Any], metadata: Mapping[str, Any]) -> Any:
        import openai

        try:
            return self._client.responses.parse(
                model=str(metadata["model"]),
                instructions=_system_instructions(),
                input=yaml.safe_dump(dict(request), sort_keys=True),
                text_format=GeneratedCalderaTest,
                max_output_tokens=int(metadata["max_output_tokens"]),
                store=False,
                timeout=float(metadata["timeout_seconds"]),
            )
        except openai.RateLimitError as error:
            raise OpenAIActiveTestRateLimitError("OpenAI active test generation was rate-limited") from error
        except openai.AuthenticationError as error:
            raise OpenAIActiveTestAuthenticationError("OpenAI active test generation rejected credentials") from error
        except openai.BadRequestError as error:
            raise OpenAIActiveTestConfigurationError("OpenAI active test generation request was rejected") from error
        except (openai.APITimeoutError, openai.APIConnectionError, openai.InternalServerError) as error:
            raise OpenAIActiveTestUnavailableError(
                f"OpenAI active test generation failed transiently: {type(error).__name__}"
            ) from error
        except openai.APIStatusError as error:
            status = getattr(error, "status_code", None)
            if status is not None and 500 <= status < 600:
                raise OpenAIActiveTestUnavailableError(
                    f"OpenAI active test generation returned server status {status}"
                ) from error
            raise OpenAIActiveTestConfigurationError(
                f"OpenAI active test generation returned unexpected status {status}"
            ) from error
        except openai.OpenAIError as error:
            raise OpenAIActiveTestConfigurationError(
                f"OpenAI active test generation failed: {type(error).__name__}"
            ) from error


def _generate_one(
    runtime: ActiveTestGenerationRuntime,
    provider: CalderaTestProvider,
    sigma_rule: SigmaRule,
) -> dict[str, Any]:
    output_path = runtime.output_dir / f"{_slug(sigma_rule.title)}.yml"
    result: dict[str, Any] = {
        "sigma_title": sigma_rule.title,
        "sigma_id": sigma_rule.raw_rule.get("id"),
        "source_file": sigma_rule.source_file,
        "manifest": str(output_path),
        "status": "started",
    }
    if output_path.exists() and not runtime.overwrite:
        result.update({"status": "skipped", "reason": "manifest already exists"})
        return result

    try:
        generated = provider.generate(
            _provider_request(sigma_rule),
            {
                "model": runtime.model,
                "timeout_seconds": runtime.timeout_seconds,
                "max_output_tokens": runtime.max_output_tokens,
                "max_retries": runtime.max_retries,
                "prompt_version": PROMPT_VERSION,
                "output_schema_version": OUTPUT_SCHEMA_VERSION,
            },
        )
        _reject_unsafe_command(generated)
        manifest = _manifest_for_rule(sigma_rule, generated)
        output_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
        # Re-parse the one generated manifest through the normal active-test model.
        load_active_tests(output_path.parent)
        result.update(
            {
                "status": "generated",
                "executor": generated.executor,
                "technique_id": generated.technique_id,
                "rule_group": manifest["expect"]["rule_group"],
            }
        )
    except ActiveTestError as error:
        result.update(
            {
                "status": "failed",
                "error": str(error),
                "error_type": type(error).__name__,
                "retryable": bool(getattr(error, "retryable", False)),
                "hint": getattr(error, "hint", None),
            }
        )
    return result


def _load_sigma_rules(directory: Path) -> list[SigmaRule]:
    if not directory.is_dir():
        raise ActiveTestError(f"sigma directory does not exist: {directory}")
    rules: list[SigmaRule] = []
    for path in sorted([*directory.rglob("*.yml"), *directory.rglob("*.yaml")]):
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(payload, dict):
            raise ActiveTestError(f"Sigma rule must be a mapping: {path}")
        normalized, _parser = parse_sigma_with_pysigma(payload)
        rules.append(SigmaRule(normalized, str(path)))
    return rules


def _provider_request(sigma_rule: SigmaRule) -> dict[str, Any]:
    """Build a compact rule summary safe to send to OpenAI."""
    return {
        "task": "Generate one safe Caldera ability command to trigger this Sigma rule on Windows.",
        "constraints": {
            "must_include_marker_template": MARKER_TEMPLATE,
            "must_be_safe": True,
            "must_not_download_or_execute_remote_code": True,
            "must_not_disable_security_tools": True,
            "must_not_persist_or_modify_system_configuration": True,
        },
        "sigma": {
            "title": sigma_rule.title,
            "id": sigma_rule.raw_rule.get("id"),
            "description": sigma_rule.description,
            "level": sigma_rule.level,
            "status": sigma_rule.status,
            "logsource": sigma_rule.logsource,
            "detection": sigma_rule.detection,
            "tags": sigma_rule.tags,
        },
        "expected_wazuh_group": sigma_group_name(sigma_rule.title),
    }


def _manifest_for_rule(sigma_rule: SigmaRule, generated: GeneratedCalderaTest) -> dict[str, Any]:
    return {
        "name": generated.name,
        "sigma_id": str(sigma_rule.raw_rule.get("id") or ""),
        "caldera": {
            "executor": generated.executor,
            "platform": generated.platform,
            "command": generated.command,
            "cleanup": generated.cleanup,
            "timeout": generated.timeout,
            "tactic": generated.tactic,
            "technique_id": generated.technique_id,
            "technique_name": generated.technique_name,
        },
        "expect": {
            "rule_group": sigma_group_name(sigma_rule.title),
            "marker": MARKER_TEMPLATE,
        },
        "metadata": {
            "generated_by": "openai",
            "prompt_version": PROMPT_VERSION,
            "output_schema_version": OUTPUT_SCHEMA_VERSION,
            "source_file": sigma_rule.source_file,
            "expected_marker_field": generated.expected_marker_field,
            "rationale": generated.rationale,
            "safety_notes": generated.safety_notes,
        },
    }


def _reject_unsafe_command(generated: GeneratedCalderaTest) -> None:
    command = generated.command.lower()
    blocked = [
        "invoke-webrequest",
        "iwr ",
        "curl ",
        "wget ",
        "bitsadmin",
        "certutil",
        "reg add",
        "schtasks",
        "new-service",
        "set-mppreference",
        "disable",
        "format ",
        "del /f",
        "remove-item",
    ]
    found = [token for token in blocked if token in command]
    if found:
        raise ActiveTestError(f"generated command failed safety policy: {', '.join(found)}")


def _system_instructions() -> str:
    return f"""\
You generate safe Caldera ability manifests for validating Wazuh detections.

Return only the structured schema.

Requirements:
- Generate exactly one Windows-safe command that should trigger the provided Sigma rule.
- The command MUST include the literal marker template {MARKER_TEMPLATE}.
- Prefer harmless echo, whoami, cmd.exe, powershell.exe, process creation, and environment inspection commands.
- Do not download files, execute remote code, disable controls, persist, change registry, create users, delete data, or evade security.
- Cleanup must be empty unless the command creates a clearly harmless temporary file containing the marker.
- Use ATT&CK tactic/technique fields that match the Sigma tags when possible.
- Keep the command suitable for a dev Windows Caldera agent.
"""


def _extract_parsed_response(response: Any) -> Any:
    for item in getattr(response, "output", None) or []:
        for content in getattr(item, "content", None) or []:
            parsed = getattr(content, "parsed", None)
            if parsed is not None:
                return parsed
            if getattr(content, "type", None) == "refusal":
                raise OpenAIActiveTestRefusalError(str(getattr(content, "refusal", "OpenAI refused the request")))
    return None


def _backoff_delay(attempt: int) -> float:
    return min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))


def _slug(value: str) -> str:
    import re

    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "active-test"
