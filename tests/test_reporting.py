import json
from pathlib import Path

import pytest

from wazuh_sigma.reporting import write_bytes_artifact, write_json_report, write_text_artifact


def test_write_text_artifact_creates_parent_and_writes_content(tmp_path):
    artifact_path = tmp_path / "build" / "sigma_rules.xml"

    write_text_artifact(artifact_path, "<group />")

    assert artifact_path.read_text(encoding="utf-8") == "<group />"


def test_write_bytes_artifact_creates_parent_and_writes_content(tmp_path):
    artifact_path = tmp_path / "backups" / "sigma_rules.xml"

    write_bytes_artifact(artifact_path, b"<group />")

    assert artifact_path.read_bytes() == b"<group />"


def test_write_json_report_creates_parent_and_stable_json(tmp_path):
    report_path = tmp_path / "nested" / "report.json"

    write_json_report(report_path, {"z": 1, "a": {"nested": True}})

    assert json.loads(report_path.read_text(encoding="utf-8")) == {
        "a": {"nested": True},
        "z": 1,
    }
    assert report_path.read_text(encoding="utf-8").endswith("\n")


def test_write_json_report_keeps_existing_file_when_serialization_fails(tmp_path):
    report_path = tmp_path / "report.json"
    report_path.write_text('{"status": "previous"}\n', encoding="utf-8")

    with pytest.raises(TypeError):
        write_json_report(report_path, {"bad": object()})

    assert report_path.read_text(encoding="utf-8") == '{"status": "previous"}\n'
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_write_text_artifact_cleans_temp_file_when_content_type_is_invalid(tmp_path):
    artifact_path = tmp_path / "sigma_rules.xml"

    with pytest.raises(TypeError):
        write_text_artifact(artifact_path, object())  # type: ignore[arg-type]

    assert not artifact_path.exists()
    assert list(tmp_path.glob(".sigma_rules.xml.*.tmp")) == []


def test_write_bytes_artifact_cleans_temp_file_when_content_type_is_invalid(tmp_path):
    artifact_path = tmp_path / "sigma_rules.xml"

    with pytest.raises(TypeError):
        write_bytes_artifact(artifact_path, object())  # type: ignore[arg-type]

    assert not artifact_path.exists()
    assert list(tmp_path.glob(".sigma_rules.xml.*.tmp")) == []


def test_write_text_artifact_keeps_existing_file_when_replace_fails(monkeypatch, tmp_path):
    artifact_path = tmp_path / "sigma_rules.xml"
    artifact_path.write_text("<previous />", encoding="utf-8")

    def fail_replace(self, target):
        raise OSError("replace failed")

    monkeypatch.setattr("pathlib.Path.replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        write_text_artifact(artifact_path, "<new />")

    assert artifact_path.read_text(encoding="utf-8") == "<previous />"
    assert list(tmp_path.glob(".sigma_rules.xml.*.tmp")) == []


def test_write_text_artifact_retries_transient_permission_error(monkeypatch, tmp_path):
    artifact_path = tmp_path / "sigma_rules.xml"
    artifact_path.write_text("<previous />", encoding="utf-8")
    original_replace = Path.replace
    calls = {"count": 0}

    def transient_replace(self, target):
        calls["count"] += 1
        if calls["count"] == 1:
            raise PermissionError("temporarily locked")
        return original_replace(self, target)

    monkeypatch.setattr("pathlib.Path.replace", transient_replace)
    monkeypatch.setattr("wazuh_sigma.reporting.time.sleep", lambda seconds: None)

    write_text_artifact(artifact_path, "<new />")

    assert 2 <= calls["count"] <= 3
    assert artifact_path.read_text(encoding="utf-8") == "<new />"
    assert list(tmp_path.glob(".sigma_rules.xml.*.tmp")) == []


def test_write_bytes_artifact_keeps_existing_file_when_replace_fails(monkeypatch, tmp_path):
    artifact_path = tmp_path / "sigma_rules.xml"
    artifact_path.write_bytes(b"<previous />")

    def fail_replace(self, target):
        raise OSError("replace failed")

    monkeypatch.setattr("pathlib.Path.replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        write_bytes_artifact(artifact_path, b"<new />")

    assert artifact_path.read_bytes() == b"<previous />"
    assert list(tmp_path.glob(".sigma_rules.xml.*.tmp")) == []
