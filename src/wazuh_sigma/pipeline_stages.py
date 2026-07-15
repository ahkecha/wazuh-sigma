"""Runtime stages for the config-driven Sigma-to-Wazuh pipeline."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Callable, TypeVar

from wazuh_sigma.active_testing.alerts import AlertSearchConfig, WazuhIndexerAlertClient
from wazuh_sigma.active_testing.caldera import CalderaAuth, CalderaClient
from wazuh_sigma.active_testing.openai_generator import (
    ActiveTestGenerationRuntime,
    generate_active_tests_with_openai,
)
from wazuh_sigma.active_testing.runner import ActiveTestRuntime, run_active_detection_tests
from wazuh_sigma.backend.wazuh import WazuhBackendConfig
from wazuh_sigma.config import PipelineConfig
from wazuh_sigma.converter.service import SigmaToWazuhConverter
from wazuh_sigma.incremental.integration import build_incremental_service
from wazuh_sigma.reporting import write_json_report
from wazuh_sigma.validator.rule_validator import WazuhRuleValidator, validation_exit_code


DOCKER_SMOKE_TIMEOUT_SECONDS = 120
PIPELINE_STAGE_ERRORS = (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired)
T = TypeVar("T")


class PipelineStageError(RuntimeError):
    """Raised when an expected pipeline stage failure has been recorded."""

    def __init__(self, stage: str, error: Exception):
        self.stage = stage
        self.error = error
        super().__init__(str(error))


def convert_from_config(config: PipelineConfig) -> dict[str, Any]:
    """Convert configured Sigma rules into the configured Wazuh XML artifact.

    When ``config.advisor.enabled`` is false (the default), the advisor package
    is never imported and conversion behaves exactly as before.
    """
    advisor_service = None
    advisor_hook = None
    if config.advisor.enabled:
        # Imported lazily so the optional openai/pydantic deps are only required
        # when the advisor is actually enabled.
        from wazuh_sigma.advisor.runtime import build_advisor_service, make_advisor_hook

        advisor_service = build_advisor_service(config.advisor)
        if advisor_service is not None:
            advisor_hook = make_advisor_hook(advisor_service, config.advisor)

    converter = SigmaToWazuhConverter(
        backend_config=WazuhBackendConfig(
            rule_id_start=config.wazuh.rule_id_start,
            rule_id_end=config.wazuh.rule_id_end,
            field_mapping_version=config.wazuh.field_mapping_version,
            field_mapping=config.wazuh.field_mapping,
            parent_rules=config.wazuh.parent_rules,
        ),
        advisor_hook=advisor_hook,
        incremental_service=build_incremental_service(config),
    )
    rules = converter.convert_directory(str(config.sigma_dir))
    if not rules:
        raise RuntimeError(f"no Sigma rules converted from {config.sigma_dir}")

    if advisor_service is not None:
        from wazuh_sigma.advisor.runtime import build_run_advisor_summary

        converter.advisor_summary = build_run_advisor_summary(advisor_service, config.advisor)

    if not converter.generate_xml_output(rules, str(config.output_file)):
        raise RuntimeError(f"failed to write Wazuh XML to {config.output_file}")

    report = converter.generate_report()
    write_json_report(config.conversion_report, report)
    return report


def validate_output(config: PipelineConfig, *, strict: bool | None = None) -> dict[str, Any]:
    """Validate the configured generated Wazuh XML artifact."""
    strict_mode = config.strict_validation if strict is None else strict
    validator = WazuhRuleValidator(str(config.output_file), strict_mode=strict_mode)
    validator.validate_all()
    failed = sum(item.failed_checks for item in validator.all_results)
    warnings = sum(item.warning_checks for item in validator.all_results)
    result = {
        "failed_checks": failed,
        "warning_checks": warnings,
        "strict": strict_mode,
        "exit_code": validation_exit_code(validator.all_results, strict_mode=strict_mode),
    }
    if result["exit_code"]:
        raise RuntimeError(f"validator failed for {config.output_file}: {result}")
    return result


def docker_native_smoke(timeout_seconds: int = DOCKER_SMOKE_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Run Wazuh's native parser test inside the local Docker Compose manager."""
    commands = [
        ["docker", "compose", "up", "-d", "--force-recreate", "wazuh.manager"],
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "wazuh.manager",
            "sh",
            "-lc",
            (
                "rm -f /var/ossec/etc/rules/sigma_rules.xml "
                "/var/ossec/etc/rules/rules_*.xml && "
                "cp /sigma-rules/*.xml /var/ossec/etc/rules/ && "
                "/var/ossec/bin/wazuh-analysisd -t"
            ),
        ],
    ]
    results = []
    for command in commands:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
        item = {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timeout_seconds": timeout_seconds,
        }
        results.append(item)
        if completed.returncode:
            raise RuntimeError(f"Docker smoke command failed: {item}")
    return {"commands": results}


def _record_smoke_failure(report: dict[str, Any], error: PipelineStageError) -> None:
    """Update a smoke report with structured failure details."""
    report["status"] = "failed"
    report["failed_stage"] = error.stage
    report["error_type"] = type(error.error).__name__
    report["error"] = str(error.error)


def _run_smoke_stage(stage: str, action: Callable[[], T]) -> T:
    """Run one smoke stage and wrap expected operational failures with stage metadata."""
    try:
        return action()
    except PIPELINE_STAGE_ERRORS as error:
        raise PipelineStageError(stage, error) from error


def _smoke_report_config(config: PipelineConfig, *, docker: bool, strict: bool | None) -> dict[str, Any]:
    """Build the stable config snapshot embedded in smoke reports."""
    strict_mode = config.strict_validation if strict is None else strict
    return {
        "sigma_dir": str(config.sigma_dir),
        "build_dir": str(config.build_dir),
        "output_file": str(config.output_file),
        "conversion_report": str(config.conversion_report),
        "smoke_report": str(config.smoke_report),
        "strict_validation": strict_mode,
        "docker": docker,
        "wazuh": {
            "rule_id_start": config.wazuh.rule_id_start,
            "rule_id_end": config.wazuh.rule_id_end,
            "field_mapping_version": config.wazuh.field_mapping_version,
            "parent_rules": config.wazuh.parent_rules,
            "remote_file": config.wazuh.remote_file,
        },
    }


def run_smoke(config: PipelineConfig, docker: bool = False, *, strict: bool | None = None) -> dict[str, Any]:
    """Run conversion, validation, and optional native Docker/Wazuh parser smoke."""
    report = {
        "status": "started",
        "config": _smoke_report_config(config, docker=docker, strict=strict),
        "conversion": None,
        "validator": None,
        "docker": None,
        "error": None,
        "error_type": None,
        "failed_stage": None,
    }
    try:
        report["conversion"] = _run_smoke_stage("conversion", lambda: convert_from_config(config))
        report["validator"] = _run_smoke_stage("validator", lambda: validate_output(config, strict=strict))
        if docker:
            report["docker"] = _run_smoke_stage("docker", docker_native_smoke)
        report["status"] = "succeeded"
    except PipelineStageError as error:
        _record_smoke_failure(report, error)
        write_json_report(config.smoke_report, report)
        raise
    write_json_report(config.smoke_report, report)
    return report


def run_active_tests_from_config(
    config: PipelineConfig,
    *,
    caldera_api_key: str,
    alert_username: str,
    alert_password: str,
    test_dir: Path | None = None,
) -> dict[str, Any]:
    """Run autonomous Caldera-backed active detection tests from config."""
    active = config.active_test
    if not active.alert_indexer_url:
        raise RuntimeError("active_test.alert_indexer_url is required for active-test")

    ca_bundle = str(active.ca_bundle) if active.ca_bundle is not None else None
    caldera = CalderaClient(
        active.caldera_url,
        CalderaAuth(
            header_name=active.caldera_auth_header,
            token=caldera_api_key,
            scheme=active.caldera_auth_scheme,
        ),
        timeout=config.wazuh.timeout,
        verify_tls=not active.insecure,
        ca_bundle=ca_bundle,
    )
    alerts = WazuhIndexerAlertClient(
        AlertSearchConfig(
            base_url=active.alert_indexer_url,
            index=active.alert_index,
            username=alert_username,
            password=alert_password,
            timeout=config.wazuh.timeout,
            verify_tls=not active.insecure,
            ca_bundle=ca_bundle,
        )
    )
    runtime = ActiveTestRuntime(
        test_dir=test_dir or active.test_dir,
        report=active.report,
        agent_platform=active.agent_platform,
        agent_group=active.agent_group,
        operation_timeout_seconds=active.operation_timeout_seconds,
        operation_poll_interval_seconds=active.operation_poll_interval_seconds,
        alert_timeout_seconds=active.alert_timeout_seconds,
        alert_poll_interval_seconds=active.alert_poll_interval_seconds,
    )
    return run_active_detection_tests(runtime=runtime, caldera=caldera, alerts=alerts)


def generate_active_tests_from_config(config: PipelineConfig, *, overwrite: bool = False) -> dict[str, Any]:
    """Generate Caldera active-test manifests from Sigma rules with OpenAI."""
    active = config.active_test
    if not active.openai_model:
        raise RuntimeError("active_test.openai_model is required for OpenAI active-test generation")
    runtime = ActiveTestGenerationRuntime(
        sigma_dir=config.sigma_dir,
        output_dir=active.generated_test_dir,
        model=active.openai_model,
        api_key_env=active.openai_api_key_env,
        timeout_seconds=active.openai_timeout_seconds,
        max_output_tokens=active.openai_max_output_tokens,
        max_retries=active.openai_max_retries,
        overwrite=overwrite,
    )
    return generate_active_tests_with_openai(runtime)
