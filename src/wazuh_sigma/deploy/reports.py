"""Machine-readable deployment report helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


DeploymentReport = dict[str, Any]


def verified_rule_count(verification: Mapping[str, Any]) -> int | None:
    """Return the number of Wazuh rules visible for a verification response."""
    data = verification.get("data", {})
    if not isinstance(data, Mapping):
        return None
    total = data.get("total_affected_items")
    if isinstance(total, int) and not isinstance(total, bool) and total >= 0:
        return total
    items = data.get("affected_items", [])
    return len(items) if isinstance(items, list) else None


def new_deployment_report(
    *,
    host: str,
    remote_file: str,
    local_file: Path,
    converted: int | None,
    dry_run: bool,
    validate_only: bool,
    backup_remote: bool,
    rollback_on_failure: bool,
    restart_requested: bool,
    local_validation: Mapping[str, Any],
) -> DeploymentReport:
    """Create the initial machine-readable deployment report."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "started",
        "stage": "initialized",
        "host": host,
        "remote_file": remote_file,
        "local_file": str(local_file),
        "converted": converted,
        "dry_run": dry_run,
        "validate_only": validate_only,
        "backup_remote": backup_remote,
        "rollback_on_failure": rollback_on_failure,
        "restart_requested": restart_requested,
        "local_validation": dict(local_validation),
        "uploaded": False,
        "backup_file": None,
        "manager_validation": None,
        "restart": None,
        "verified_rules": None,
        "rolled_back": False,
        "failed_stage": None,
        "error_type": None,
        "error": None,
    }


def mark_deployment_failure(report: DeploymentReport, error: BaseException) -> None:
    """Stamp standard failure metadata onto a deployment report."""
    report["status"] = "failed"
    report["failed_stage"] = report.get("stage")
    report["error_type"] = type(error).__name__
    report["error"] = str(error)
