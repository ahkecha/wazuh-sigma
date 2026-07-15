import argparse
import base64
import json
import os
from pathlib import Path

import pytest

from wazuh_sigma.config import PipelineConfigError, env_flag
from wazuh_sigma.deploy.client import redact_sensitive_text
from wazuh_sigma.deploy.wazuh_api import (
    HttpResponse,
    WazuhApiClient,
    WazuhApiError,
    WazuhDeploymentError,
    build_parser,
    check_remote_rule_id_collisions,
    deploy_rules,
    extract_local_rule_ids,
    main,
    positive_int,
    validate_deployment_options,
    validate_local_rules_file,
    validate_remote_rule_filename,
    validate_wazuh_host,
    verified_rule_count,
)


DEFAULT_INTEGRATION_REMOTE_FILE = "sigma_integration_smoke.xml"
DEFAULT_INTEGRATION_TIMEOUT = 30


def write_valid_rules_file(path: Path, *, rule_id: int = 900000) -> None:
    path.write_text(
        (
            '<group name="sigma_rules,">'
            f'<rule id="{rule_id}" level="5">'
            "<description>deploy smoke</description>"
            "<group>sigma_deploy_smoke</group>"
            "</rule>"
            "</group>"
        ),
        encoding="utf-8",
    )


def integration_env_flag(name: str, default: bool = False) -> bool:
    try:
        return env_flag(name, default=default)
    except PipelineConfigError as error:
        pytest.fail(str(error))


def integration_timeout() -> int:
    value = os.getenv("WAZUH_TIMEOUT")
    if value is None:
        return DEFAULT_INTEGRATION_TIMEOUT
    try:
        return positive_int(value)
    except argparse.ArgumentTypeError as error:
        pytest.fail(f"WAZUH_TIMEOUT {error}")


def integration_ca_bundle() -> str | None:
    value = os.getenv("WAZUH_CA_BUNDLE")
    if value is None or not value.strip():
        return None
    return value


def integration_remote_file() -> str:
    return os.getenv("WAZUH_REMOTE_FILE", DEFAULT_INTEGRATION_REMOTE_FILE)


class FakeTransport:
    def __init__(self):
        self.calls = []

    def __call__(self, method, url, body, headers):
        self.calls.append((method, url, body, dict(headers)))
        if url.endswith("/security/user/authenticate"):
            return HttpResponse(200, json.dumps({"data": {"token": "jwt-token"}, "error": 0}).encode(), {})
        if "/rules/files/" in url and "raw=true" in url:
            return HttpResponse(200, b"<group name=\"old,\" />", {})
        if "/rules/files/" in url:
            return HttpResponse(200, json.dumps({"data": {"message": "uploaded"}, "error": 0}).encode(), {})
        if url.endswith("/manager/configuration/validation"):
            return HttpResponse(200, json.dumps({"data": {"status": "OK"}, "error": 0}).encode(), {})
        if url.endswith("/manager/restart"):
            return HttpResponse(200, json.dumps({"data": {"message": "restarted"}, "error": 0}).encode(), {})
        if "/rules?" in url:
            return HttpResponse(
                200,
                json.dumps({"data": {"affected_items": [{"filename": "sigma_rules.xml"}]}, "error": 0}).encode(),
                {},
            )
        return HttpResponse(404, b"{}", {})


def test_deploy_rules_runs_expected_wazuh_api_sequence(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    transport = FakeTransport()
    client = WazuhApiClient(
        "https://wazuh.example.invalid",
        "alice",
        "secret",
        transport=transport,
    )

    result = deploy_rules(
        host="https://wazuh.example.invalid",
        username="alice",
        password="secret",
        local_file=rules_file,
        remote_file="sigma_rules.xml",
        restart=True,
        client=client,
    )

    methods_and_paths = [(method, url.split(".invalid/")[1]) for method, url, _, _ in transport.calls]
    assert methods_and_paths == [
        ("POST", "security/user/authenticate"),
        ("GET", "rules?rule_ids=900000&limit=2"),
        ("PUT", "rules/files/sigma_rules.xml?overwrite=true"),
        ("GET", "manager/configuration/validation"),
        ("PUT", "manager/restart"),
        ("GET", "rules?filename=sigma_rules.xml&limit=1"),
    ]
    assert result["restart"] is not None
    assert result["uploaded"] is True
    assert result["converted"] == 1
    assert result["verified_rules"] == 1
    assert result["backup_remote"] is False
    assert result["rollback_on_failure"] is False
    assert result["restart_requested"] is True
    assert result["status"] == "succeeded"
    assert result["stage"] == "completed"

    auth_header = transport.calls[0][3]["Authorization"]
    assert auth_header == "Basic " + base64.b64encode(b"alice:secret").decode("ascii")

    upload_body = transport.calls[2][2]
    upload_headers = transport.calls[2][3]
    assert upload_body == rules_file.read_bytes()
    assert upload_headers["Authorization"] == "Bearer jwt-token"
    assert upload_headers["Content-Type"] == "application/xml"


def test_verified_rule_count_prefers_wazuh_total_affected_items():
    assert (
        verified_rule_count(
            {
                "data": {
                    "total_affected_items": 42,
                    "affected_items": [{"filename": "sigma_rules.xml"}],
                }
            }
        )
        == 42
    )


def test_verified_rule_count_falls_back_to_affected_items_length():
    assert verified_rule_count({"data": {"affected_items": [{"id": 1}, {"id": 2}]}}) == 2


def test_verified_rule_count_returns_none_for_unexpected_shape():
    assert verified_rule_count({"data": {"affected_items": "not-a-list"}}) is None
    assert verified_rule_count({"data": "not-a-mapping"}) is None


def test_extract_local_rule_ids_reads_single_and_grouped_rules(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    rules_file.write_text(
        (
            '<group name="sigma_rules,">'
            '<rule id="900000" level="5"><description>one</description></rule>'
            '<rule id="900001" level="5"><description>two</description></rule>'
            "</group>"
        ),
        encoding="utf-8",
    )

    assert extract_local_rule_ids(rules_file) == {900000, 900001}


def test_remote_rule_id_collision_check_allows_same_managed_file(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file, rule_id=900225)

    def transport(method, url, body, headers):
        if "/rules?" in url:
            return HttpResponse(
                200,
                json.dumps(
                    {
                        "data": {
                            "affected_items": [{"id": 900225, "filename": "sigma_rules.xml"}],
                            "total_affected_items": 1,
                        },
                        "error": 0,
                    }
                ).encode(),
                {},
            )
        return HttpResponse(404, b"{}", {})

    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)
    client.token = "jwt-token"

    result = check_remote_rule_id_collisions(api=client, local_file=rules_file, remote_file="sigma_rules.xml")

    assert result == {"checked_rule_ids": 1, "collisions": []}


def test_deploy_rules_rejects_remote_rule_id_collision_before_upload(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file, rule_id=900225)

    def transport(method, url, body, headers):
        if url.endswith("/security/user/authenticate"):
            return HttpResponse(200, json.dumps({"data": {"token": "jwt-token"}, "error": 0}).encode(), {})
        if "rule_ids=900225" in url:
            return HttpResponse(
                200,
                json.dumps(
                    {
                        "data": {
                            "affected_items": [
                                {
                                    "id": 900225,
                                    "filename": "900-global_exclusion_rules.xml",
                                    "relative_dirname": "etc/rules",
                                    "description": "Existing managed exclusion",
                                }
                            ],
                            "total_affected_items": 1,
                        },
                        "error": 0,
                    }
                ).encode(),
                {},
            )
        return HttpResponse(404, b"{}", {})

    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhDeploymentError, match="before upload") as error_info:
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            client=client,
        )

    report = error_info.value.report
    assert report["status"] == "failed"
    assert report["stage"] == "remote_rule_id_collision_check"
    assert report["failed_stage"] == "remote_rule_id_collision_check"
    assert report["uploaded"] is False
    assert report["remote_rule_id_collision_check"]["collisions"] == [
        {
            "rule_id": 900225,
            "filename": "900-global_exclusion_rules.xml",
            "relative_dirname": "etc/rules",
            "description": "Existing managed exclusion",
        }
    ]


def test_deploy_rules_uses_wazuh_total_for_verified_rule_count(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)

    def transport(method, url, body, headers):
        if url.endswith("/security/user/authenticate"):
            return HttpResponse(200, json.dumps({"data": {"token": "jwt-token"}, "error": 0}).encode(), {})
        if "/rules/files/" in url:
            return HttpResponse(200, json.dumps({"data": {"message": "uploaded"}, "error": 0}).encode(), {})
        if url.endswith("/manager/configuration/validation"):
            return HttpResponse(200, json.dumps({"data": {"status": "OK"}, "error": 0}).encode(), {})
        if "/rules?" in url:
            return HttpResponse(
                200,
                json.dumps(
                    {
                        "data": {
                            "total_affected_items": 42,
                            "affected_items": [{"filename": "sigma_rules.xml"}],
                        },
                        "error": 0,
                    }
                ).encode(),
                {},
            )
        return HttpResponse(404, b"{}", {})

    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    result = deploy_rules(
        host="https://wazuh.example.invalid",
        username="alice",
        password="secret",
        local_file=rules_file,
        remote_file="sigma_rules.xml",
        client=client,
    )

    assert result["status"] == "succeeded"
    assert result["verified_rules"] == 42


def test_deploy_rules_fails_after_restart_when_no_rules_are_visible(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)

    def transport(method, url, body, headers):
        if url.endswith("/security/user/authenticate"):
            return HttpResponse(200, json.dumps({"data": {"token": "jwt-token"}, "error": 0}).encode(), {})
        if "raw=true" in url:
            return HttpResponse(200, b"<group name=\"old,\" />", {})
        if "/rules/files/" in url:
            return HttpResponse(200, json.dumps({"data": {"message": "uploaded"}, "error": 0}).encode(), {})
        if url.endswith("/manager/configuration/validation"):
            return HttpResponse(200, json.dumps({"data": {"status": "OK"}, "error": 0}).encode(), {})
        if url.endswith("/manager/restart"):
            return HttpResponse(200, json.dumps({"data": {"message": "restarted"}, "error": 0}).encode(), {})
        if "/rules?" in url:
            return HttpResponse(
                200,
                json.dumps({"data": {"total_affected_items": 0, "affected_items": []}, "error": 0}).encode(),
                {},
            )
        return HttpResponse(404, b"{}", {})

    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhDeploymentError) as error_info:
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            restart=True,
            backup_remote=True,
            rollback_on_failure=True,
            backup_dir=tmp_path / "backups",
            client=client,
        )

    assert error_info.value.report["status"] == "failed"
    assert error_info.value.report["stage"] == "verify"
    assert error_info.value.report["failed_stage"] == "verify"
    assert error_info.value.report["error_type"] == "WazuhApiError"
    assert error_info.value.report["uploaded"] is True
    assert error_info.value.report["rolled_back"] is True
    assert error_info.value.report["verified_rules"] == 0
    assert "no loaded rules" in error_info.value.report["error"]


def test_deploy_rules_can_skip_restart(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    result = deploy_rules(
        host="https://wazuh.example.invalid",
        username="alice",
        password="secret",
        local_file=rules_file,
        remote_file="sigma_rules.xml",
        restart=False,
        client=client,
    )

    assert result["restart"] is None
    assert not any(url.endswith("/manager/restart") for _, url, _, _ in transport.calls)


def test_deploy_rules_dry_run_authenticates_but_does_not_mutate(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    result = deploy_rules(
        host="https://wazuh.example.invalid",
        username="alice",
        password="secret",
        local_file=rules_file,
        remote_file="sigma_rules.xml",
        dry_run=True,
        client=client,
    )

    assert result["dry_run"] is True
    assert result["validate_only"] is False
    assert result["backup_remote"] is False
    assert result["rollback_on_failure"] is False
    assert result["restart_requested"] is False
    assert result["local_validation"]["failed_checks"] == 0
    assert result["uploaded"] is False
    assert result["status"] == "dry_run"
    assert result["stage"] == "dry_run"
    assert [(method, url.split(".invalid/")[1]) for method, url, _, _ in transport.calls] == [
        ("POST", "security/user/authenticate")
    ]


def test_deploy_rules_dry_run_requires_local_rules_file(tmp_path):
    missing_file = tmp_path / "missing.xml"
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhApiError, match="Rule file does not exist"):
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=missing_file,
            remote_file="sigma_rules.xml",
            dry_run=True,
            client=client,
        )

    assert transport.calls == []


def test_deploy_rules_validate_only_requires_local_rules_file(tmp_path):
    missing_file = tmp_path / "missing.xml"
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhApiError, match="Rule file does not exist"):
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=missing_file,
            remote_file="sigma_rules.xml",
            validate_only=True,
            client=client,
        )

    assert transport.calls == []


def test_deploy_rules_validate_only_reports_status(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    result = deploy_rules(
        host="https://wazuh.example.invalid",
        username="alice",
        password="secret",
        local_file=rules_file,
        remote_file="sigma_rules.xml",
        validate_only=True,
        client=client,
    )

    assert result["status"] == "validate_only"
    assert result["stage"] == "validate_only"
    assert result["manager_validation"] == {"data": {"status": "OK"}, "error": 0}
    assert result["uploaded"] is False
    assert [(method, url.split(".invalid/")[1]) for method, url, _, _ in transport.calls] == [
        ("POST", "security/user/authenticate"),
        ("GET", "manager/configuration/validation"),
    ]


def test_deploy_rules_validate_only_reports_manager_validation_failure(monkeypatch, tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    def fail_validation():
        raise WazuhApiError("manager validation failed")

    monkeypatch.setattr(client, "validate_manager_configuration", fail_validation)

    with pytest.raises(WazuhDeploymentError, match="validate-only failed") as error_info:
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            validate_only=True,
            client=client,
        )

    assert error_info.value.report["status"] == "failed"
    assert error_info.value.report["stage"] == "manager_validation"
    assert error_info.value.report["failed_stage"] == "manager_validation"
    assert error_info.value.report["error_type"] == "WazuhApiError"
    assert error_info.value.report["error"] == "manager validation failed"
    assert error_info.value.report["uploaded"] is False


def test_deploy_rules_backs_up_remote_file_before_upload(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    backup_dir = tmp_path / "backups"
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    result = deploy_rules(
        host="https://wazuh.example.invalid",
        username="alice",
        password="secret",
        local_file=rules_file,
        remote_file="sigma_rules.xml",
        backup_remote=True,
        backup_dir=backup_dir,
        client=client,
    )

    assert result["backup_file"]
    assert result["backup_remote"] is True
    assert result["rollback_on_failure"] is False
    assert result["restart_requested"] is False
    assert Path(result["backup_file"]).read_bytes() == b"<group name=\"old,\" />"
    methods_and_paths = [(method, url.split(".invalid/")[1]) for method, url, _, _ in transport.calls]
    assert methods_and_paths[1] == ("GET", "rules?rule_ids=900000&limit=2")
    assert methods_and_paths[2] == ("GET", "rules/files/sigma_rules.xml?raw=true")
    assert methods_and_paths[3] == ("PUT", "rules/files/sigma_rules.xml?overwrite=true")


def test_deploy_rules_writes_remote_backup_atomically(monkeypatch, tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    backup_dir = tmp_path / "backups"
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)
    calls = {}

    def fake_write_bytes_artifact(path, content):
        calls["path"] = path
        calls["content"] = content
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    monkeypatch.setattr("wazuh_sigma.deploy.wazuh_api.write_bytes_artifact", fake_write_bytes_artifact)

    result = deploy_rules(
        host="https://wazuh.example.invalid",
        username="alice",
        password="secret",
        local_file=rules_file,
        remote_file="sigma_rules.xml",
        backup_remote=True,
        backup_dir=backup_dir,
        client=client,
    )

    assert calls["content"] == b"<group name=\"old,\" />"
    assert calls["path"] == Path(result["backup_file"])
    assert calls["path"].parent == backup_dir


def test_deploy_rules_stops_before_upload_when_required_backup_fails(monkeypatch, tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    def fail_backup_write(path, content):
        raise OSError("backup disk full")

    monkeypatch.setattr("wazuh_sigma.deploy.wazuh_api.write_bytes_artifact", fail_backup_write)

    with pytest.raises(WazuhDeploymentError) as error_info:
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            backup_remote=True,
            rollback_on_failure=True,
            client=client,
        )

    assert error_info.value.report["status"] == "failed"
    assert error_info.value.report["stage"] == "backup_remote"
    assert error_info.value.report["failed_stage"] == "backup_remote"
    assert error_info.value.report["error_type"] == "OSError"
    assert error_info.value.report["uploaded"] is False
    assert error_info.value.report["backup_remote"] is True
    assert error_info.value.report["rollback_on_failure"] is True
    assert error_info.value.report["restart_requested"] is False
    assert error_info.value.report["backup_error"] == "backup disk full"
    assert "backup failed before upload" in error_info.value.report["error"]
    assert not any(method == "PUT" and "/rules/files/" in url for method, url, _, _ in transport.calls)


def test_deploy_rules_can_continue_without_optional_backup(monkeypatch, tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    def fail_backup_write(path, content):
        raise OSError("backup disk full")

    monkeypatch.setattr("wazuh_sigma.deploy.wazuh_api.write_bytes_artifact", fail_backup_write)

    result = deploy_rules(
        host="https://wazuh.example.invalid",
        username="alice",
        password="secret",
        local_file=rules_file,
        remote_file="sigma_rules.xml",
        backup_remote=True,
        rollback_on_failure=False,
        client=client,
    )

    assert result["status"] == "succeeded"
    assert result["uploaded"] is True
    assert result["backup_file"] is None
    assert result["backup_error"] == "backup disk full"


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"dry_run": True, "validate_only": True}, "mutually exclusive"),
        ({"rollback_on_failure": True, "backup_remote": False}, "requires backup-remote"),
    ],
)
def test_validate_deployment_options_rejects_unsafe_combinations(options, message):
    with pytest.raises(WazuhApiError, match=message):
        validate_deployment_options(**options)


def test_deploy_rules_rejects_rollback_without_backup_before_authentication(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhApiError, match="requires backup-remote"):
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            rollback_on_failure=True,
            client=client,
        )

    assert transport.calls == []


def test_deploy_rules_rolls_back_on_failure_after_backup(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    calls = []

    def transport(method, url, body, headers):
        calls.append((method, url, body, dict(headers)))
        if url.endswith("/security/user/authenticate"):
            return HttpResponse(200, json.dumps({"data": {"token": "jwt-token"}, "error": 0}).encode(), {})
        if "raw=true" in url:
            return HttpResponse(200, b"<group name=\"old,\" />", {})
        if "/rules?" in url:
            return HttpResponse(
                200,
                json.dumps({"data": {"affected_items": [], "total_affected_items": 0}, "error": 0}).encode(),
                {},
            )
        if url.endswith("/manager/configuration/validation"):
            return HttpResponse(500, b"{}", {})
        if "/rules/files/" in url:
            return HttpResponse(200, json.dumps({"data": {"message": "uploaded"}, "error": 0}).encode(), {})
        return HttpResponse(404, b"{}", {})

    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhDeploymentError) as error_info:
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            backup_remote=True,
            backup_dir=tmp_path / "backups",
            rollback_on_failure=True,
            client=client,
        )

    assert error_info.value.report["uploaded"] is True
    assert error_info.value.report["rolled_back"] is True
    assert error_info.value.report["status"] == "failed"
    assert error_info.value.report["stage"] == "manager_validation"
    assert error_info.value.report["failed_stage"] == "manager_validation"
    assert error_info.value.report["error_type"] == "WazuhApiError"
    assert "HTTP 500" in error_info.value.report["error"]
    upload_calls = [call for call in calls if "/rules/files/" in call[1] and "overwrite=true" in call[1]]
    assert len(upload_calls) == 2


def test_deploy_rules_reports_failed_rollback(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)

    def transport(method, url, body, headers):
        if url.endswith("/security/user/authenticate"):
            return HttpResponse(200, json.dumps({"data": {"token": "jwt-token"}, "error": 0}).encode(), {})
        if "raw=true" in url:
            return HttpResponse(200, b"<group name=\"old,\" />", {})
        if "/rules?" in url:
            return HttpResponse(
                200,
                json.dumps({"data": {"affected_items": [], "total_affected_items": 0}, "error": 0}).encode(),
                {},
            )
        if url.endswith("/manager/configuration/validation"):
            return HttpResponse(500, b"{}", {})
        if "/rules/files/" in url and body == b"<group name=\"old,\" />":
            return HttpResponse(500, b"{}", {})
        if "/rules/files/" in url:
            return HttpResponse(200, json.dumps({"data": {"message": "uploaded"}, "error": 0}).encode(), {})
        return HttpResponse(404, b"{}", {})

    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhDeploymentError) as error_info:
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            backup_remote=True,
            backup_dir=tmp_path / "backups",
            rollback_on_failure=True,
            client=client,
        )

    assert error_info.value.report["uploaded"] is True
    assert error_info.value.report["rolled_back"] is False
    assert "rollback_error" in error_info.value.report
    assert error_info.value.report["rollback_error_type"] == "WazuhApiError"
    assert error_info.value.report["failed_stage"] == "manager_validation"
    assert error_info.value.report["error_type"] == "WazuhApiError"


def test_deploy_rules_does_not_hide_programming_errors(monkeypatch, tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    def fail_with_programming_error():
        raise TypeError("validation method contract changed")

    monkeypatch.setattr(client, "validate_manager_configuration", fail_with_programming_error)

    with pytest.raises(TypeError, match="validation method contract changed"):
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            backup_remote=True,
            backup_dir=tmp_path / "backups",
            rollback_on_failure=True,
            client=client,
        )

    upload_calls = [
        call
        for call in transport.calls
        if call[0] == "PUT" and "/rules/files/" in call[1] and "overwrite=true" in call[1]
    ]
    assert len(upload_calls) == 1


def test_authentication_requires_token():
    def transport(method, url, body, headers):
        return HttpResponse(200, json.dumps({"data": {}, "error": 0}).encode(), {})

    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhApiError, match="token"):
        client.authenticate()


def test_deploy_rules_reports_authentication_failure(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)

    def transport(method, url, body, headers):
        return HttpResponse(200, json.dumps({"data": {}, "error": 0}).encode(), {})

    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhDeploymentError, match="authentication") as error_info:
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            client=client,
        )

    assert error_info.value.report["status"] == "failed"
    assert error_info.value.report["stage"] == "authenticate"
    assert error_info.value.report["failed_stage"] == "authenticate"
    assert error_info.value.report["error_type"] == "WazuhApiError"
    assert error_info.value.report["uploaded"] is False
    assert "token" in error_info.value.report["error"]


def test_json_api_responses_must_be_objects():
    def transport(method, url, body, headers):
        return HttpResponse(200, b"[]", {})

    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhApiError, match="non-object JSON"):
        client.authenticate()


def test_api_error_payloads_redact_sensitive_values():
    def transport(method, url, body, headers):
        return HttpResponse(
            200,
            json.dumps(
                {
                    "error": 1000,
                    "detail": "token=jwt-secret password=super-secret Authorization: Bearer bearer-secret",
                }
            ).encode(),
            {},
        )

    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhApiError) as error_info:
        client.authenticate()

    message = str(error_info.value)
    assert "jwt-secret" not in message
    assert "super-secret" not in message
    assert "bearer-secret" not in message
    assert "<redacted>" in message


def test_diagnostic_text_redaction_handles_common_secret_shapes():
    redacted = redact_sensitive_text(
        'Authorization: Basic abc123 token="jwt-secret" password=super-secret api_key=key-secret'
    )

    assert "abc123" not in redacted
    assert "jwt-secret" not in redacted
    assert "super-secret" not in redacted
    assert "key-secret" not in redacted
    assert redacted.count("<redacted>") == 4


@pytest.mark.parametrize("value", ["1", "30"])
def test_positive_int_accepts_positive_values(value):
    assert positive_int(value) == int(value)


@pytest.mark.parametrize("value", ["0", "-1", "nope"])
def test_positive_int_rejects_non_positive_values(value):
    with pytest.raises(argparse.ArgumentTypeError, match="positive integer"):
        positive_int(value)


@pytest.mark.parametrize(
    "flags",
    [
        ["--dry-run", "--validate-only"],
        ["--restart", "--no-restart"],
    ],
)
def test_deploy_parser_rejects_mutually_exclusive_flags(flags):
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--host",
                "https://wazuh.example.invalid",
                "--username",
                "alice",
                "--password",
                "secret",
                "--file",
                "sigma_rules.xml",
                *flags,
            ]
        )


def test_integration_timeout_defaults_when_env_is_absent(monkeypatch):
    monkeypatch.delenv("WAZUH_TIMEOUT", raising=False)

    assert integration_timeout() == DEFAULT_INTEGRATION_TIMEOUT


def test_integration_timeout_uses_positive_env_value(monkeypatch):
    monkeypatch.setenv("WAZUH_TIMEOUT", "45")

    assert integration_timeout() == 45


def test_integration_timeout_fails_on_invalid_env_value(monkeypatch):
    monkeypatch.setenv("WAZUH_TIMEOUT", "0")

    with pytest.raises(pytest.fail.Exception, match="WAZUH_TIMEOUT"):
        integration_timeout()


def test_integration_env_flag_reuses_config_boolean_contract(monkeypatch):
    monkeypatch.setenv("WAZUH_RESTART", "yes")

    assert integration_env_flag("WAZUH_RESTART") is True


def test_integration_env_flag_fails_on_ambiguous_boolean(monkeypatch):
    monkeypatch.setenv("WAZUH_RESTART", "maybe")

    with pytest.raises(pytest.fail.Exception, match="WAZUH_RESTART"):
        integration_env_flag("WAZUH_RESTART")


def test_integration_ca_bundle_ignores_blank_env_value(monkeypatch):
    monkeypatch.setenv("WAZUH_CA_BUNDLE", " ")

    assert integration_ca_bundle() is None


def test_integration_remote_file_defaults_to_dedicated_smoke_file(monkeypatch):
    monkeypatch.delenv("WAZUH_REMOTE_FILE", raising=False)

    assert integration_remote_file() == DEFAULT_INTEGRATION_REMOTE_FILE


def test_client_rejects_non_positive_timeout():
    with pytest.raises(WazuhApiError, match="timeout"):
        WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", timeout=0)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("sigma_rules.xml", "sigma_rules.xml"),
        (" sigma_rules.xml ", "sigma_rules.xml"),
        ("SIGMA_RULES.XML", "SIGMA_RULES.XML"),
    ],
)
def test_remote_rule_filename_validation_accepts_single_xml_filename(value, expected):
    assert validate_remote_rule_filename(value) == expected


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("", "must not be empty"),
        ("nested/sigma_rules.xml", "path separators"),
        ("nested\\sigma_rules.xml", "path separators"),
        ("../sigma_rules.xml", "filename, not a path"),
        ("sigma_rules.txt", ".xml"),
    ],
)
def test_remote_rule_filename_validation_rejects_unsafe_values(value, message):
    with pytest.raises(WazuhApiError, match=message):
        validate_remote_rule_filename(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://wazuh.example.invalid", "https://wazuh.example.invalid/"),
        ("https://wazuh.example.invalid/", "https://wazuh.example.invalid/"),
    ],
)
def test_wazuh_host_validation_normalizes_http_urls(value, expected):
    assert validate_wazuh_host(value) == expected


@pytest.mark.parametrize("value", ["wazuh.example.com:55000", "ftp://wazuh.example.com", ""])
def test_wazuh_host_validation_rejects_non_http_urls(value):
    with pytest.raises(WazuhApiError, match="http"):
        validate_wazuh_host(value)


def test_deploy_rejects_unsafe_remote_filename_before_authentication(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhApiError, match="path separators"):
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="nested/sigma_rules.xml",
            client=client,
        )

    assert transport.calls == []


def test_deploy_rejects_non_positive_timeout_before_authentication(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)

    with pytest.raises(WazuhApiError, match="timeout"):
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            timeout=0,
        )


def test_local_validation_rejects_invalid_rules_before_authentication(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    rules_file.write_text('<group name="sigma_rules,"><rule id="900000" level="5" /></group>', encoding="utf-8")
    transport = FakeTransport()
    client = WazuhApiClient("https://wazuh.example.invalid", "alice", "secret", transport=transport)

    with pytest.raises(WazuhApiError, match="Local rule validation failed"):
        deploy_rules(
            host="https://wazuh.example.invalid",
            username="alice",
            password="secret",
            local_file=rules_file,
            remote_file="sigma_rules.xml",
            client=client,
        )

    assert transport.calls == []


def test_local_validation_report_is_machine_readable(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)

    report = validate_local_rules_file(rules_file)

    assert report == {
        "file": str(rules_file),
        "failed_checks": 0,
        "warning_checks": 0,
        "validated_files": 1,
        "rule_count": 1,
    }


def test_cli_uses_environment_credentials(monkeypatch, tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    monkeypatch.setenv("WAZUH_USER", "alice")
    monkeypatch.setenv("WAZUH_PASSWORD", "secret")

    calls = {}

    def fake_deploy_rules(**kwargs):
        calls.update(kwargs)
        return {"uploaded": {}, "validation": {}, "restart": None, "verification": {}}

    monkeypatch.setattr("wazuh_sigma.deploy.wazuh_api.deploy_rules", fake_deploy_rules)

    exit_code = main(
        [
            "--host",
            "https://wazuh.example.invalid",
            "--file",
            str(rules_file),
            "--remote-file",
            "sigma_rules.xml",
            "--restart",
            "--insecure",
        ]
    )

    assert exit_code == 0
    assert calls["username"] == "alice"
    assert calls["password"] == "secret"
    assert calls["restart"] is True
    assert calls["verify_tls"] is False
    assert calls["backup_remote"] is False
    assert calls["rollback_on_failure"] is False


def test_cli_rejects_non_positive_timeout(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)

    with pytest.raises(SystemExit) as exit_info:
        main(
            [
                "--host",
                "https://wazuh.example.invalid",
                "--username",
                "alice",
                "--password",
                "secret",
                "--file",
                str(rules_file),
                "--timeout",
                "0",
            ]
        )

    assert exit_info.value.code == 2


def test_cli_writes_failure_report_from_deployment_error(monkeypatch, tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    write_valid_rules_file(rules_file)
    report_file = tmp_path / "deploy-report.json"
    monkeypatch.setenv("WAZUH_USER", "alice")
    monkeypatch.setenv("WAZUH_PASSWORD", "secret")

    def fake_deploy_rules(**kwargs):
        raise WazuhDeploymentError(
            "deployment failed",
            {
                "uploaded": True,
                "rolled_back": True,
                "error": "manager validation failed",
            },
        )

    monkeypatch.setattr("wazuh_sigma.deploy.wazuh_api.deploy_rules", fake_deploy_rules)

    exit_code = main(
        [
            "--host",
            "https://wazuh.example.invalid",
            "--file",
            str(rules_file),
            "--remote-file",
            "sigma_rules.xml",
            "--report",
            str(report_file),
        ]
    )

    assert exit_code == 1
    assert json.loads(report_file.read_text(encoding="utf-8")) == {
        "error": "manager validation failed",
        "rolled_back": True,
        "uploaded": True,
    }


@pytest.mark.integration
@pytest.mark.skipif(
    not (os.getenv("WAZUH_HOST") and os.getenv("WAZUH_USER") and os.getenv("WAZUH_PASSWORD")),
    reason="WAZUH_HOST, WAZUH_USER, and WAZUH_PASSWORD are required",
)
def test_real_wazuh_api_deployment_smoke(tmp_path):
    rules_file = tmp_path / "sigma_rules.xml"
    rules_file.write_text(
        "<group name=\"sigma_rules,\"><rule id=\"949990\" level=\"3\"><description>integration smoke</description><group>sigma_integration_smoke</group></rule></group>",
        encoding="utf-8",
    )

    result = deploy_rules(
        host=os.environ["WAZUH_HOST"],
        username=os.environ["WAZUH_USER"],
        password=os.environ["WAZUH_PASSWORD"],
        local_file=rules_file,
        remote_file=integration_remote_file(),
        restart=integration_env_flag("WAZUH_RESTART"),
        backup_remote=False,
        verify_tls=not integration_env_flag("WAZUH_INSECURE"),
        ca_bundle=integration_ca_bundle(),
        timeout=integration_timeout(),
    )

    assert result["status"] == "succeeded"
    assert result["uploaded"] is True
    assert result["manager_validation"] is not None
    assert result["verification"] is not None
    if integration_env_flag("WAZUH_RESTART"):
        assert result["verified_rules"] and result["verified_rules"] >= 1
