"""Environment readiness checks for the config-driven Sigma-to-Wazuh pipeline."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from wazuh_sigma.config import PipelineConfig


CHECK_OK = "ok"
CHECK_WARN = "warn"
CHECK_FAIL = "fail"
DEFAULT_WAZUH_HOST = "https://example:55000"


def run_doctor(config: PipelineConfig, *, require_deploy: bool = False) -> dict[str, Any]:
    """Inspect pipeline readiness and return a machine-readable report."""
    checks = [
        _check_sigma_dir(config.sigma_dir),
        _check_sigma_rules(config.sigma_dir),
        _check_path_parent("output_file_parent", config.output_file),
        _check_path_parent("conversion_report_parent", config.conversion_report),
        _check_path_parent("smoke_report_parent", config.smoke_report),
        _check_path_parent("backup_dir_parent", config.wazuh.backup_dir / ".doctor"),
        _check_ca_bundle(config.wazuh.ca_bundle),
        _check_wazuh_host(config.wazuh.host, require_deploy=require_deploy),
        _check_credentials(require_deploy=require_deploy),
    ]
    summary = {
        "ok": sum(check["status"] == CHECK_OK for check in checks),
        "warn": sum(check["status"] == CHECK_WARN for check in checks),
        "fail": sum(check["status"] == CHECK_FAIL for check in checks),
    }
    return {
        "status": CHECK_FAIL if summary["fail"] else CHECK_WARN if summary["warn"] else CHECK_OK,
        "require_deploy": require_deploy,
        "summary": summary,
        "checks": checks,
    }


def doctor_exit_code(report: dict[str, Any]) -> int:
    """Return the process exit code for a doctor report."""
    return 1 if report["summary"]["fail"] else 0


def _check(name: str, status: str, message: str, **details: Any) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "message": message,
        **details,
    }


def _check_sigma_dir(path: Path) -> dict[str, Any]:
    if path.is_dir():
        return _check("sigma_dir", CHECK_OK, "Sigma directory exists", path=str(path))
    return _check("sigma_dir", CHECK_FAIL, "Sigma directory does not exist", path=str(path))


def _check_sigma_rules(path: Path) -> dict[str, Any]:
    files = list(_sigma_rule_files(path)) if path.is_dir() else []
    if files:
        return _check("sigma_rules", CHECK_OK, "Sigma rule files found", path=str(path), count=len(files))
    return _check("sigma_rules", CHECK_FAIL, "No .yml or .yaml Sigma rule files found", path=str(path), count=0)


def _sigma_rule_files(path: Path) -> Iterable[Path]:
    yield from sorted(item for item in path.rglob("*") if item.suffix.lower() in {".yml", ".yaml"})


def _check_path_parent(name: str, path: Path) -> dict[str, Any]:
    parent = path.parent
    if parent.exists() and parent.is_dir():
        return _check(name, CHECK_OK, "Parent directory exists", path=str(path), parent=str(parent))
    return _check(
        name,
        CHECK_WARN,
        "Parent directory does not exist yet; pipeline artifact writers will create it",
        path=str(path),
        parent=str(parent),
    )


def _check_ca_bundle(path: Path | None) -> dict[str, Any]:
    if path is None:
        return _check("ca_bundle", CHECK_OK, "No custom CA bundle configured")
    if path.is_file():
        return _check("ca_bundle", CHECK_OK, "Configured CA bundle exists", path=str(path))
    return _check("ca_bundle", CHECK_FAIL, "Configured CA bundle does not exist", path=str(path))


def _check_wazuh_host(host: str, *, require_deploy: bool) -> dict[str, Any]:
    if host == DEFAULT_WAZUH_HOST:
        status = CHECK_FAIL if require_deploy else CHECK_WARN
        return _check(
            "wazuh_host",
            status,
            "Wazuh host is still the example placeholder",
            host=host,
            require_deploy=require_deploy,
        )
    return _check("wazuh_host", CHECK_OK, "Wazuh host is configured", host=host)


def _check_credentials(*, require_deploy: bool) -> dict[str, Any]:
    missing = [name for name in ("WAZUH_USER", "WAZUH_PASSWORD") if not os.getenv(name)]
    if not missing:
        return _check("wazuh_credentials", CHECK_OK, "Wazuh credentials are present in the environment")
    status = CHECK_FAIL if require_deploy else CHECK_WARN
    return _check(
        "wazuh_credentials",
        status,
        "Wazuh credentials are missing from the environment",
        missing=missing,
        require_deploy=require_deploy,
    )
