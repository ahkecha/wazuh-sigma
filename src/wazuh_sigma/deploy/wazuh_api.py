#!/usr/bin/env python3
"""Deploy generated Sigma-derived Wazuh rules through the Wazuh API."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from wazuh_sigma.deploy.client import (
    ApiPayload,
    HttpResponse,
    Transport,
    WazuhApiClient,
    WazuhApiError,
    validate_remote_rule_filename,
    validate_wazuh_host,
)
from wazuh_sigma.deploy.reports import (
    DeploymentReport,
    mark_deployment_failure,
    new_deployment_report,
    verified_rule_count,
)
from wazuh_sigma.reporting import write_bytes_artifact, write_json_report
from wazuh_sigma.validator.rule_validator import WazuhRuleValidator


logger = logging.getLogger("WazuhDeploy")


class WazuhDeploymentError(WazuhApiError):
    """Raised when deployment fails after a machine-readable report exists."""

    def __init__(self, message: str, report: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.report = dict(report)


DEPLOYMENT_STAGE_ERRORS = (WazuhApiError, OSError, ValueError)


def positive_int(value: str) -> int:
    """Parse a positive integer for CLI options."""
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def validate_local_rules_file(local_file: Path) -> ApiPayload:
    """Validate a local Wazuh rules file before any remote deployment action."""
    validator = WazuhRuleValidator(str(local_file))
    validator.validate_all()
    failed_checks = sum(item.failed_checks for item in validator.all_results)
    warning_checks = sum(item.warning_checks for item in validator.all_results)
    rule_count = count_local_rules(local_file) if not failed_checks else None
    report = {
        "file": str(local_file),
        "failed_checks": failed_checks,
        "warning_checks": warning_checks,
        "validated_files": len(validator.all_results),
        "rule_count": rule_count,
    }
    if failed_checks:
        raise WazuhApiError(f"Local rule validation failed for {local_file}: {report}")
    return report


def count_local_rules(local_file: Path) -> int:
    """Count Wazuh ``<rule>`` elements in a validated local rules artifact."""
    root = ET.parse(local_file).getroot()
    return int(root.tag == "rule") + len(root.findall(".//rule"))


def extract_local_rule_ids(local_file: Path) -> set[int]:
    """Return all numeric Wazuh rule IDs in a local rules artifact."""
    root = ET.parse(local_file).getroot()
    rule_elements = [root] if root.tag == "rule" else []
    rule_elements.extend(root.findall(".//rule"))

    rule_ids: set[int] = set()
    for rule in rule_elements:
        raw_rule_id = rule.get("id")
        if raw_rule_id is None:
            continue
        try:
            rule_ids.add(int(raw_rule_id))
        except ValueError:
            continue
    return rule_ids


def check_remote_rule_id_collisions(
    *,
    api: WazuhApiClient,
    local_file: Path,
    remote_file: str,
) -> ApiPayload:
    """Check whether generated rule IDs collide with other loaded Wazuh rule files."""
    local_rule_ids = extract_local_rule_ids(local_file)
    response = api.find_rules_by_ids(local_rule_ids, limit=max(len(local_rule_ids) * 2, 1))
    affected_items = response.get("data", {}).get("affected_items", [])
    if not isinstance(affected_items, list):
        affected_items = []

    collisions = []
    for item in affected_items:
        if not isinstance(item, Mapping):
            continue
        try:
            remote_rule_id = int(item.get("id"))
        except (TypeError, ValueError):
            continue
        if remote_rule_id not in local_rule_ids:
            continue
        filename = item.get("filename")
        if filename == remote_file:
            continue
        collisions.append(
            {
                "rule_id": remote_rule_id,
                "filename": filename,
                "relative_dirname": item.get("relative_dirname"),
                "description": item.get("description"),
            }
        )

    return {
        "checked_rule_ids": len(local_rule_ids),
        "collisions": sorted(collisions, key=lambda collision: collision["rule_id"]),
    }


def validate_deployment_options(
    *,
    dry_run: bool = False,
    validate_only: bool = False,
    backup_remote: bool = False,
    rollback_on_failure: bool = False,
) -> None:
    """Reject ambiguous or unsafe deployment mode combinations."""
    if dry_run and validate_only:
        raise WazuhApiError("dry-run and validate-only modes are mutually exclusive")
    if rollback_on_failure and not backup_remote:
        raise WazuhApiError("rollback-on-failure requires backup-remote")


def rollback_remote_rules(
    *,
    api: WazuhApiClient,
    backup_bytes: bytes,
    remote_file: str,
    report: DeploymentReport,
) -> None:
    """Best-effort rollback of a remote Wazuh rule file after deployment failure."""
    logger.error("Deployment failed; rolling back remote rule file %s", remote_file)
    try:
        api.upload_rule_bytes(backup_bytes, remote_file, overwrite=True)
        report["rolled_back"] = True
    except WazuhApiError as rollback_error:
        report["rollback_error"] = str(rollback_error)
        report["rollback_error_type"] = type(rollback_error).__name__


def deploy_rules(
    *,
    host: str,
    username: str,
    password: str,
    local_file: Path,
    remote_file: str,
    restart: bool = False,
    dry_run: bool = False,
    validate_only: bool = False,
    backup_remote: bool = False,
    backup_dir: Path | None = None,
    rollback_on_failure: bool = False,
    verify_tls: bool = True,
    ca_bundle: str | None = None,
    timeout: int = 30,
    client: WazuhApiClient | None = None,
) -> DeploymentReport:
    """Deploy a generated Wazuh rules XML file and return deployment results."""
    validate_deployment_options(
        dry_run=dry_run,
        validate_only=validate_only,
        backup_remote=backup_remote,
        rollback_on_failure=rollback_on_failure,
    )
    if not local_file.is_file():
        raise WazuhApiError(f"Rule file does not exist: {local_file}")

    host = validate_wazuh_host(host).rstrip("/")
    remote_file = validate_remote_rule_filename(remote_file)
    local_validation = validate_local_rules_file(local_file)

    api = client or WazuhApiClient(
        host,
        username,
        password,
        timeout=timeout,
        verify_tls=verify_tls,
        ca_bundle=ca_bundle,
    )

    report = new_deployment_report(
        host=host,
        remote_file=remote_file,
        local_file=local_file,
        converted=local_validation["rule_count"],
        dry_run=dry_run,
        validate_only=validate_only,
        backup_remote=backup_remote,
        rollback_on_failure=rollback_on_failure,
        restart_requested=restart,
        local_validation=local_validation,
    )

    try:
        report["stage"] = "authenticate"
        logger.info("Authenticating to Wazuh API at %s", host)
        api.authenticate()
    except WazuhApiError as error:
        mark_deployment_failure(report, error)
        raise WazuhDeploymentError(f"Wazuh deployment failed during authentication: {error}", report) from error

    if dry_run:
        logger.info("Dry run enabled; skipping upload, validation, restart, and verification")
        report["status"] = "dry_run"
        report["stage"] = "dry_run"
        return report

    if not validate_only:
        try:
            report["stage"] = "remote_rule_id_collision_check"
            logger.info("Checking remote Wazuh rule ID collisions before upload")
            collision_check = check_remote_rule_id_collisions(
                api=api,
                local_file=local_file,
                remote_file=remote_file,
            )
            report["remote_rule_id_collision_check"] = collision_check
            if collision_check["collisions"]:
                collision_ids = ", ".join(str(item["rule_id"]) for item in collision_check["collisions"][:10])
                raise WazuhApiError(
                    f"Remote rule ID collision detected for generated rule ID(s): {collision_ids}"
                )
        except DEPLOYMENT_STAGE_ERRORS as error:
            mark_deployment_failure(report, error)
            raise WazuhDeploymentError(f"Wazuh deployment failed before upload: {error}", report) from error

    backup_bytes: bytes | None = None
    if backup_remote:
        backup_dir = backup_dir or Path("backups/wazuh")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = backup_dir / f"{Path(remote_file).stem}-{timestamp}{Path(remote_file).suffix or '.xml'}"
        try:
            report["stage"] = "backup_remote"
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_bytes = api.download_rule_file(remote_file)
            write_bytes_artifact(backup_path, backup_bytes)
            report["backup_file"] = str(backup_path)
            logger.info("Backed up remote rule file %s to %s", remote_file, backup_path)
        except (OSError, WazuhApiError) as error:
            report["backup_error"] = str(error)
            logger.warning("Could not back up remote rule file %s: %s", remote_file, error)
            if rollback_on_failure:
                mark_deployment_failure(report, error)
                report["error"] = f"Remote backup failed before upload: {error}"
                raise WazuhDeploymentError("Wazuh deployment failed before upload: remote backup failed", report) from error

    if validate_only:
        try:
            logger.info("Validate-only enabled; validating manager configuration without upload")
            report["stage"] = "manager_validation"
            validation = api.validate_manager_configuration()
            report["manager_validation"] = validation
            report["status"] = "validate_only"
            report["stage"] = "validate_only"
            return report
        except DEPLOYMENT_STAGE_ERRORS as error:
            mark_deployment_failure(report, error)
            raise WazuhDeploymentError(f"Wazuh validate-only failed: {error}", report) from error

    try:
        report["stage"] = "upload"
        logger.info("Uploading %s as Wazuh rule file %s", local_file, remote_file)
        report["upload_response"] = api.upload_rule_file(local_file, remote_file, overwrite=True)
        report["uploaded"] = True

        report["stage"] = "manager_validation"
        logger.info("Validating Wazuh manager configuration")
        validation = api.validate_manager_configuration()
        report["manager_validation"] = validation

        if restart:
            report["stage"] = "restart"
            logger.info("Restarting Wazuh manager")
            report["restart"] = api.restart_manager()

        report["stage"] = "verify"
        logger.info("Verifying deployed Wazuh rule file")
        verification = api.verify_rule_file(remote_file)
        report["verification"] = verification
        report["verified_rules"] = verified_rule_count(verification)
        if restart and report["verified_rules"] == 0:
            raise WazuhApiError(f"Wazuh reported no loaded rules for {remote_file} after restart")
        report["status"] = "succeeded"
        report["stage"] = "completed"
        return report
    except DEPLOYMENT_STAGE_ERRORS as error:
        if rollback_on_failure and backup_bytes is not None:
            rollback_remote_rules(
                api=api,
                backup_bytes=backup_bytes,
                remote_file=remote_file,
                report=report,
            )
        mark_deployment_failure(report, error)
        raise WazuhDeploymentError(f"Wazuh deployment failed: {error}", report) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Deploy generated Wazuh rules through the Wazuh API")
    parser.add_argument("--host", required=True, help="Wazuh API base URL, for example https://wazuh.example.invalid")
    parser.add_argument("--username", default=os.getenv("WAZUH_USER"), help="Wazuh API username, defaults to WAZUH_USER")
    parser.add_argument("--password", default=os.getenv("WAZUH_PASSWORD"), help="Wazuh API password, defaults to WAZUH_PASSWORD")
    parser.add_argument("--file", required=True, type=Path, help="Local generated Wazuh XML file to upload")
    parser.add_argument("--remote-file", default="sigma_rules.xml", help="Remote custom rule filename in Wazuh")
    restart_group = parser.add_mutually_exclusive_group()
    restart_group.add_argument("--restart", action="store_true", help="Restart Wazuh manager after upload and validation")
    restart_group.add_argument("--no-restart", action="store_true", help="Do not restart Wazuh manager, even if config enables it")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--dry-run", action="store_true", help="Authenticate and print a deployment plan without changing Wazuh")
    mode_group.add_argument("--validate-only", action="store_true", help="Validate manager configuration without uploading rules")
    parser.add_argument("--backup-remote", action="store_true", help="Download the current remote rule file before upload")
    parser.add_argument("--backup-dir", type=Path, default=Path("backups/wazuh"), help="Directory for remote rule backups")
    parser.add_argument("--rollback-on-failure", action="store_true", help="Restore the backup if upload/validation/restart fails")
    parser.add_argument("--report", type=Path, help="Write machine-readable JSON deployment report")
    parser.add_argument("--timeout", type=positive_int, default=30, help="HTTP timeout in seconds")
    parser.add_argument("--ca-bundle", help="CA bundle path for validating Wazuh API TLS")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if not args.username:
        parser.error("--username or WAZUH_USER is required")
    if not args.password:
        parser.error("--password or WAZUH_PASSWORD is required")

    try:
        result = deploy_rules(
            host=args.host,
            username=args.username,
            password=args.password,
            local_file=args.file,
            remote_file=args.remote_file,
            restart=args.restart and not args.no_restart,
            dry_run=args.dry_run,
            validate_only=args.validate_only,
            backup_remote=args.backup_remote,
            backup_dir=args.backup_dir,
            rollback_on_failure=args.rollback_on_failure,
            verify_tls=not args.insecure,
            ca_bundle=args.ca_bundle,
            timeout=args.timeout,
        )
    except WazuhApiError as error:
        if args.report and isinstance(error, WazuhDeploymentError):
            write_json_report(args.report, error.report)
        logger.error("%s", error)
        return 1

    if args.report:
        write_json_report(args.report, result)

    logger.info("Wazuh rule deployment completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
