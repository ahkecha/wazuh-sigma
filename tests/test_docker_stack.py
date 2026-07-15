"""Static contract tests for the Wazuh Docker test environment."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_compose_mounts_generated_rules_read_only():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    manager = compose["services"]["wazuh.manager"]

    assert any(volume == "./build/sigmahq:/sigma-rules:ro" for volume in manager["volumes"])
    assert "cp /sigma-rules/*.xml /var/ossec/etc/rules/" in manager["command"][0]


def test_stack_contains_only_the_manager():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))

    assert set(compose["services"]) == {"wazuh.manager"}


def test_api_binds_to_loopback_by_default():
    compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "127.0.0.1:${WAZUH_API_PORT:-55000}:55000" in compose_text
