"""Orchestration for autonomous Caldera-to-Wazuh active detection tests."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from wazuh_sigma.active_testing.alerts import WazuhIndexerAlertClient
from wazuh_sigma.active_testing.caldera import CalderaClient
from wazuh_sigma.active_testing.models import ActiveDetectionTest, ActiveTestError, load_active_tests
from wazuh_sigma.reporting import write_json_report


@dataclass(frozen=True)
class ActiveTestRuntime:
    """Runtime settings for active detection tests."""

    test_dir: Path
    report: Path
    agent_platform: str = "windows"
    agent_group: str | None = None
    operation_timeout_seconds: int = 180
    operation_poll_interval_seconds: int = 5
    alert_timeout_seconds: int = 120
    alert_poll_interval_seconds: int = 5


def run_active_detection_tests(
    *,
    runtime: ActiveTestRuntime,
    caldera: CalderaClient,
    alerts: WazuhIndexerAlertClient,
) -> dict[str, Any]:
    """Execute all active detection manifests and write a report."""
    tests = load_active_tests(runtime.test_dir)
    report: dict[str, Any] = {
        "status": "started",
        "test_dir": str(runtime.test_dir),
        "total": len(tests),
        "passed": 0,
        "failed": 0,
        "results": [],
    }

    try:
        caldera.health()
        selected_agent = caldera.find_live_agent(
            platform=runtime.agent_platform,
            group=runtime.agent_group,
        )
        group = runtime.agent_group or str(selected_agent.get("group", ""))
        if not group:
            raise ActiveTestError("selected Caldera agent does not expose a group")
        report["agent"] = _agent_report(selected_agent)

        for test in tests:
            result = _run_one_test(
                test,
                group=group,
                runtime=runtime,
                caldera=caldera,
                alerts=alerts,
            )
            report["results"].append(result)
            if result["status"] == "passed":
                report["passed"] += 1
            else:
                report["failed"] += 1

        report["status"] = "succeeded" if report["failed"] == 0 else "failed"
        write_json_report(runtime.report, report)
        if report["failed"]:
            raise ActiveTestError(f"{report['failed']} active detection test(s) failed")
        return report
    except ActiveTestError as error:
        report["status"] = "failed"
        report["error"] = str(error)
        report["error_type"] = type(error).__name__
        write_json_report(runtime.report, report)
        raise


def _run_one_test(
    test: ActiveDetectionTest,
    *,
    group: str,
    runtime: ActiveTestRuntime,
    caldera: CalderaClient,
    alerts: WazuhIndexerAlertClient,
) -> dict[str, Any]:
    marker = _marker_for_test(test)
    result: dict[str, Any] = {
        "name": test.name,
        "sigma_id": test.sigma_id,
        "manifest": str(test.path),
        "marker": marker,
        "status": "started",
    }
    try:
        prefix = f"wazuh-sigma {test.name}"
        ability = caldera.create_ability(name=f"{prefix} ability", spec=test.caldera, marker=marker)
        ability_id = str(ability.get("ability_id") or ability.get("id") or "")
        if not ability_id:
            raise ActiveTestError(f"Caldera did not return an ability id for {test.name}")

        adversary = caldera.create_adversary(name=f"{prefix} adversary", ability_id=ability_id)
        operation = caldera.create_operation(name=f"{prefix} operation", adversary=adversary, group=group)
        operation_id = str(operation.get("id") or "")
        if not operation_id:
            raise ActiveTestError(f"Caldera did not return an operation id for {test.name}")

        operation_result = caldera.wait_for_operation(
            operation_id,
            timeout=runtime.operation_timeout_seconds,
            poll_interval=runtime.operation_poll_interval_seconds,
        )
        alert_result = alerts.wait_for_alert(
            test.expect,
            marker=marker,
            timeout=runtime.alert_timeout_seconds,
            poll_interval=runtime.alert_poll_interval_seconds,
        )
        result.update(
            {
                "status": "passed",
                "ability_id": ability_id,
                "operation_id": operation_id,
                "operation": _operation_summary(operation_result),
                "alert": alert_result,
            }
        )
    except ActiveTestError as error:
        result.update(
            {
                "status": "failed",
                "error": str(error),
                "error_type": type(error).__name__,
            }
        )
    return result


def _marker_for_test(test: ActiveDetectionTest) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", test.name).strip("-").lower() or "active-test"
    return f"wazuh-sigma-{slug}-{uuid.uuid4().hex[:12]}"


def _agent_report(agent: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "paw": agent.get("paw"),
        "host": agent.get("host"),
        "platform": agent.get("platform"),
        "group": agent.get("group"),
        "status": agent.get("status"),
        "username": agent.get("username"),
    }


def _operation_summary(operation_result: Mapping[str, Any]) -> dict[str, Any]:
    operation = operation_result.get("operation", {})
    links = operation_result.get("links", [])
    return {
        "id": operation.get("id") if isinstance(operation, Mapping) else None,
        "state": operation.get("state") if isinstance(operation, Mapping) else None,
        "link_count": len(links) if isinstance(links, list) else 0,
        "link_statuses": [
            item.get("status")
            for item in links
            if isinstance(item, Mapping)
        ] if isinstance(links, list) else [],
    }
