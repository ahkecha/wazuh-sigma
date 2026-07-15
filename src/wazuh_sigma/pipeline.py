"""Single-command orchestration for conversion, smoke testing, and deployment."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from wazuh_sigma.config import AdvisorConfig, PipelineConfig
from wazuh_sigma.deploy.wazuh_api import (
    WazuhApiError,
    WazuhDeploymentError,
    deploy_rules,
    positive_int,
    validate_deployment_options,
)
from wazuh_sigma.pipeline_doctor import doctor_exit_code, run_doctor
from wazuh_sigma.pipeline_stages import (
    convert_from_config,
    generate_active_tests_from_config,
    run_active_tests_from_config,
    run_smoke,
    validate_output,
)
from wazuh_sigma.reporting import write_json_report


logger = logging.getLogger("SigmaPipeline")


def _shared_parser(*, suppress_defaults: bool = False) -> argparse.ArgumentParser:
    """Build shared options accepted before or after the subcommand."""
    config_default: Any = argparse.SUPPRESS if suppress_defaults else Path("pipeline.yml")
    verbose_default: Any = argparse.SUPPRESS if suppress_defaults else False
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--config",
        type=Path,
        default=config_default,
        help="Pipeline YAML config",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=verbose_default,
        help="Enable debug logging",
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    root_options = _shared_parser()
    subcommand_options = _shared_parser(suppress_defaults=True)
    parser = argparse.ArgumentParser(
        description="Orchestrate the Wazuh Sigma pipeline",
        parents=[root_options],
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", parents=[subcommand_options], help="Inspect local pipeline readiness")
    doctor.add_argument("--require-deploy", action="store_true", help="Fail when deploy-only requirements are missing")
    doctor.add_argument("--report", type=Path, help="Write machine-readable JSON doctor report")

    convert = subparsers.add_parser(
        "convert",
        parents=[subcommand_options],
        help="Convert Sigma rules from config to Wazuh XML",
    )
    _add_advisor_options(convert)
    validate = subparsers.add_parser(
        "validate",
        parents=[subcommand_options],
        help="Validate the configured generated Wazuh XML",
    )
    _add_validation_policy_options(validate)

    smoke = subparsers.add_parser(
        "smoke",
        parents=[subcommand_options],
        help="Convert, validate, and optionally run Docker/Wazuh parser smoke",
    )
    smoke.add_argument("--docker", action="store_true", help="Run native Docker/Wazuh parser validation")
    _add_validation_policy_options(smoke)
    _add_advisor_options(smoke)

    advise = subparsers.add_parser(
        "advise",
        parents=[subcommand_options],
        help="Run the non-authoritative advisor and write a conversion report (report-only)",
    )
    _add_advisor_options(advise)

    generate_active = subparsers.add_parser(
        "generate-active-tests",
        parents=[subcommand_options],
        help="Generate Caldera active-test manifests from Sigma rules with OpenAI",
    )
    generate_active.add_argument("--openai-model", help="Override active_test.openai_model")
    generate_active.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing generated active-test manifests",
    )

    deploy = subparsers.add_parser("deploy", parents=[subcommand_options], help="Deploy generated rules to Wazuh API")
    deploy.add_argument("--username", default=os.getenv("WAZUH_USER"), help="Wazuh API username")
    deploy.add_argument("--password", default=os.getenv("WAZUH_PASSWORD"), help="Wazuh API password")
    restart_group = deploy.add_mutually_exclusive_group()
    restart_group.add_argument("--restart", action="store_true", help="Restart Wazuh after deployment")
    restart_group.add_argument("--no-restart", action="store_true", help="Do not restart Wazuh")
    mode_group = deploy.add_mutually_exclusive_group()
    mode_group.add_argument("--dry-run", action="store_true", help="Authenticate and print plan without mutation")
    mode_group.add_argument("--validate-only", action="store_true", help="Validate manager config without upload")
    deploy.add_argument(
        "--preflight-smoke",
        action="store_true",
        help="Regenerate and validate rules from configured Sigma source before deployment",
    )
    deploy.add_argument("--backup-remote", action="store_true", help="Back up remote file before upload")
    deploy.add_argument("--rollback-on-failure", action="store_true", help="Restore backup on failure")
    deploy.add_argument("--report", type=Path, help="Deployment report path")
    deploy.add_argument("--timeout", type=positive_int, help="Override Wazuh API timeout from config")
    deploy.add_argument("--ca-bundle", help="Override CA bundle path from config")

    active = subparsers.add_parser(
        "active-test",
        parents=[subcommand_options],
        help="Run autonomous Caldera-backed detection tests and verify Wazuh alerts",
    )
    active.add_argument(
        "--preflight-smoke",
        action="store_true",
        help="Regenerate and validate rules before active testing",
    )
    active.add_argument(
        "--deploy",
        action="store_true",
        help="Deploy configured generated rules before active testing",
    )
    active.add_argument("--username", default=os.getenv("WAZUH_USER"), help="Wazuh API username for --deploy")
    active.add_argument("--password", default=os.getenv("WAZUH_PASSWORD"), help="Wazuh API password for --deploy")
    active.add_argument("--restart", action="store_true", help="Restart Wazuh after --deploy")
    active.add_argument("--backup-remote", action="store_true", help="Back up remote file before --deploy upload")
    active.add_argument("--rollback-on-failure", action="store_true", help="Rollback remote rules if --deploy fails")
    active.add_argument("--caldera-api-key", default=None, help="Caldera API key; defaults to active_test env setting")
    active.add_argument("--alert-username", default=None, help="Wazuh indexer username; defaults to active_test env setting")
    active.add_argument("--alert-password", default=None, help="Wazuh indexer password; defaults to active_test env setting")
    active.add_argument(
        "--generate-tests",
        action="store_true",
        help="Generate Caldera manifests from Sigma with OpenAI before running active tests",
    )
    active.add_argument(
        "--generate-only",
        action="store_true",
        help="Generate Caldera manifests and exit without contacting Caldera or Wazuh",
    )
    active.add_argument("--openai-model", help="Override active_test.openai_model for generated tests")
    active.add_argument(
        "--overwrite-generated-tests",
        action="store_true",
        help="Overwrite existing generated active-test manifests",
    )

    return parser


def _add_validation_policy_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--strict", action="store_true", help="Treat validation warnings as failures")
    group.add_argument("--no-strict", action="store_true", help="Do not treat validation warnings as failures")


def _add_advisor_options(parser: argparse.ArgumentParser) -> None:
    """Add advisor flags. The advisor is NON-AUTHORITATIVE; report-only is the safe default."""
    parser.add_argument(
        "--advisor",
        action="store_true",
        help="Enable the non-authoritative OpenAI advisor (report-only unless --advisor-mode changes it)",
    )
    parser.add_argument(
        "--advisor-mode",
        choices=("report-only", "review", "apply"),
        help="Advisor mode. report-only never changes generated XML (default); apply requires explicit opt-in",
    )
    parser.add_argument("--advisor-model", help="Override the primary advisor model")
    parser.add_argument("--advisor-escalation-model", help="Override the escalation advisor model")
    parser.add_argument("--advisor-timeout", type=positive_int, help="Advisor request timeout in seconds")
    parser.add_argument("--advisor-max-retries", type=int, help="Advisor transient-failure retry budget")
    parser.add_argument(
        "--advisor-min-confidence",
        type=float,
        help="Minimum confidence before a recommendation may be applied (review/apply modes)",
    )
    parser.add_argument("--advisor-max-level-delta", type=int, help="Maximum accepted level delta from the default")
    parser.add_argument("--advisor-cache-dir", type=Path, help="Advisor cache directory")
    parser.add_argument("--advisor-no-cache", action="store_true", help="Disable advisor caching")
    parser.add_argument("--advisor-changed-only", action="store_true", help="Reuse cached recommendations for unchanged rules")
    parser.add_argument(
        "--advisor-fail-closed",
        action="store_true",
        help="Fail conversion when the advisor fails instead of falling back to deterministic conversion",
    )


def _advisor_config_from_args(config: PipelineConfig, args: argparse.Namespace) -> "AdvisorConfig":
    """Apply advisor CLI overrides on top of the configured advisor settings."""
    from dataclasses import replace

    advisor = config.advisor
    enabled = advisor.enabled or getattr(args, "advisor", False)
    updates: dict[str, Any] = {"enabled": enabled}
    if getattr(args, "advisor_mode", None) is not None:
        updates["mode"] = args.advisor_mode
    if getattr(args, "advisor_model", None) is not None:
        updates["primary_model"] = args.advisor_model
    if getattr(args, "advisor_escalation_model", None) is not None:
        updates["escalation_model"] = args.advisor_escalation_model
    if getattr(args, "advisor_timeout", None) is not None:
        updates["timeout_seconds"] = args.advisor_timeout
    if getattr(args, "advisor_max_retries", None) is not None:
        updates["max_retries"] = args.advisor_max_retries
    if getattr(args, "advisor_min_confidence", None) is not None:
        updates["minimum_confidence"] = args.advisor_min_confidence
    if getattr(args, "advisor_max_level_delta", None) is not None:
        updates["maximum_level_delta"] = args.advisor_max_level_delta
    if getattr(args, "advisor_cache_dir", None) is not None:
        updates["cache_directory"] = args.advisor_cache_dir
    if getattr(args, "advisor_no_cache", False):
        updates["cache_enabled"] = False
    if getattr(args, "advisor_changed_only", False):
        updates["changed_only"] = True
    if getattr(args, "advisor_fail_closed", False):
        updates["fail_open"] = False
    return replace(advisor, **updates)


def _strict_validation_from_args(config: PipelineConfig, args: argparse.Namespace) -> bool:
    if getattr(args, "strict", False):
        return True
    if getattr(args, "no_strict", False):
        return False
    return config.strict_validation


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    try:
        config = PipelineConfig.from_file(args.config)

        if args.command == "doctor":
            report = run_doctor(config, require_deploy=args.require_deploy)
            if args.report:
                write_json_report(args.report, report)
            print(json.dumps(report, indent=2, sort_keys=True))
            return doctor_exit_code(report)

        if args.command == "convert":
            config = replace(config, advisor=_advisor_config_from_args(config, args))
            convert_from_config(config)
            logger.info("Pipeline conversion completed successfully")
            return 0

        if args.command == "advise":
            advisor = _advisor_config_from_args(config, args)
            advisor = replace(advisor, enabled=True)
            config = replace(config, advisor=advisor)
            convert_from_config(config)
            logger.info("Advisor run completed (mode=%s); see %s", advisor.mode, config.conversion_report)
            return 0

        if args.command == "generate-active-tests":
            if args.openai_model:
                config = replace(
                    config,
                    active_test=replace(config.active_test, openai_model=args.openai_model),
                )
            result = generate_active_tests_from_config(config, overwrite=args.overwrite)
            print(json.dumps(result, indent=2, sort_keys=True))
            logger.info("Generated active test manifests in %s", config.active_test.generated_test_dir)
            return 0

        if args.command == "validate":
            validate_output(config, strict=_strict_validation_from_args(config, args))
            logger.info("Pipeline validation completed successfully")
            return 0

        if args.command == "smoke":
            config = replace(config, advisor=_advisor_config_from_args(config, args))
            run_smoke(config, docker=args.docker, strict=_strict_validation_from_args(config, args))
            logger.info("Pipeline smoke completed successfully")
            return 0

        if args.command == "deploy":
            if not args.username:
                parser.error("--username or WAZUH_USER is required")
            if not args.password:
                parser.error("--password or WAZUH_PASSWORD is required")
            validate_deployment_options(
                dry_run=args.dry_run,
                validate_only=args.validate_only,
                backup_remote=args.backup_remote,
                rollback_on_failure=args.rollback_on_failure,
            )
            if args.preflight_smoke:
                run_smoke(config, docker=False, strict=config.strict_validation)
            report_path = args.report or config.build_dir / "deploy-report.json"
            ca_bundle = args.ca_bundle
            if ca_bundle is None and config.wazuh.ca_bundle is not None:
                ca_bundle = str(config.wazuh.ca_bundle)
            try:
                result = deploy_rules(
                    host=config.wazuh.host,
                    username=args.username,
                    password=args.password,
                    local_file=config.output_file,
                    remote_file=config.wazuh.remote_file,
                    restart=args.restart and not args.no_restart,
                    dry_run=args.dry_run,
                    validate_only=args.validate_only,
                    backup_remote=args.backup_remote,
                    backup_dir=config.wazuh.backup_dir,
                    rollback_on_failure=args.rollback_on_failure,
                    verify_tls=not config.wazuh.insecure,
                    ca_bundle=ca_bundle,
                    timeout=args.timeout or config.wazuh.timeout,
                )
            except WazuhDeploymentError as error:
                write_json_report(report_path, error.report)
                raise
            write_json_report(report_path, result)
            logger.info("Pipeline deployment completed successfully")
            return 0

        if args.command == "active-test":
            should_generate_tests = (
                args.generate_tests
                or args.generate_only
                or config.active_test.generate_with_openai
                or bool(args.openai_model)
            )
            active_test_dir = config.active_test.test_dir
            if args.openai_model:
                config = replace(
                    config,
                    active_test=replace(
                        config.active_test,
                        openai_model=args.openai_model,
                        generate_with_openai=True,
                    ),
                )
            if should_generate_tests:
                generate_active_tests_from_config(
                    config,
                    overwrite=args.overwrite_generated_tests,
                )
                active_test_dir = config.active_test.generated_test_dir
                if args.generate_only:
                    logger.info("Generated active test manifests in %s", active_test_dir)
                    return 0
            if args.preflight_smoke:
                run_smoke(config, docker=False, strict=config.strict_validation)
            if args.deploy:
                if not args.username:
                    parser.error("--username or WAZUH_USER is required when --deploy is used")
                if not args.password:
                    parser.error("--password or WAZUH_PASSWORD is required when --deploy is used")
                validate_deployment_options(
                    backup_remote=args.backup_remote,
                    rollback_on_failure=args.rollback_on_failure,
                )
                deploy_rules(
                    host=config.wazuh.host,
                    username=args.username,
                    password=args.password,
                    local_file=config.output_file,
                    remote_file=config.wazuh.remote_file,
                    restart=args.restart,
                    backup_remote=args.backup_remote,
                    backup_dir=config.wazuh.backup_dir,
                    rollback_on_failure=args.rollback_on_failure,
                    verify_tls=not config.wazuh.insecure,
                    ca_bundle=str(config.wazuh.ca_bundle) if config.wazuh.ca_bundle is not None else None,
                    timeout=config.wazuh.timeout,
                )
            caldera_api_key = args.caldera_api_key or os.getenv(config.active_test.caldera_api_key_env)
            alert_username = args.alert_username or os.getenv(config.active_test.alert_username_env)
            alert_password = args.alert_password or os.getenv(config.active_test.alert_password_env)
            if not caldera_api_key:
                parser.error(f"--caldera-api-key or {config.active_test.caldera_api_key_env} is required")
            if not alert_username:
                parser.error(f"--alert-username or {config.active_test.alert_username_env} is required")
            if not alert_password:
                parser.error(f"--alert-password or {config.active_test.alert_password_env} is required")
            run_active_tests_from_config(
                config,
                caldera_api_key=caldera_api_key,
                alert_username=alert_username,
                alert_password=alert_password,
                test_dir=active_test_dir,
            )
            logger.info("Pipeline active detection tests completed successfully")
            return 0
    except (RuntimeError, WazuhApiError, FileNotFoundError, ValueError) as error:
        logger.error("%s", error)
        return 1

    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
