import json
from pathlib import Path
from types import SimpleNamespace

import yaml

import pytest

from wazuh_sigma.backend import DEFAULT_FIELD_MAPPING_VERSION, DEFAULT_RULE_ID_END, DEFAULT_RULE_ID_START
from wazuh_sigma.config import PipelineConfig, PipelineConfigError, env_flag
from wazuh_sigma.deploy.wazuh_api import WazuhDeploymentError
from wazuh_sigma.pipeline import build_parser, main
from wazuh_sigma.pipeline_stages import DOCKER_SMOKE_TIMEOUT_SECONDS, docker_native_smoke


ROOT = Path(__file__).resolve().parents[1]


def test_gitlab_ci_uses_canonical_generated_rules_path():
    """CI should validate the same generated XML path documented by pipeline.yml."""
    ci_text = (ROOT / "ci" / ".gitlab-ci.yml").read_text(encoding="utf-8")
    config = yaml.safe_load((ROOT / "ci" / "pipeline.yml").read_text(encoding="utf-8"))

    assert config["output_file"] == "build/sigmahq/sigma_rules.xml"
    assert "build/sigmahq/sigma_rules.xml" in ci_text
    assert "build/sigma_rules.xml" not in ci_text


def test_github_actions_runs_fast_non_deployment_pipeline():
    """GitHub CI should run fast validation gates without deploying to Wazuh."""
    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    workflow_text = workflow.read_text(encoding="utf-8")
    config = yaml.safe_load((ROOT / "ci" / "pipeline.yml").read_text(encoding="utf-8"))

    assert workflow.exists()
    assert config["output_file"] == "build/sigmahq/sigma_rules.xml"
    assert "python -m compileall -q src tests" in workflow_text
    assert "python -m pytest" in workflow_text
    assert "python -m wazuh_sigma.pipeline --config ci/pipeline.yml smoke" in workflow_text
    assert "build/sigmahq/sigma_rules.xml" in workflow_text
    assert "sigma-deploy-wazuh" not in workflow_text
    assert "WAZUH_PASSWORD" not in workflow_text


def test_default_pipeline_config_uses_checked_in_sigma_rules():
    """The advertised default smoke command should work in a clean checkout."""
    config = PipelineConfig.from_file(ROOT / "pipeline.yml")

    assert config.sigma_dir == ROOT / "examples/sigma"
    assert config.sigma_dir.is_dir()


def test_pipeline_config_loads_rule_id_ownership(tmp_path):
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        """
sigma_dir: examples/sigma
build_dir: build
output_file: build/sigmahq/sigma_rules.xml
wazuh:
  host: https://wazuh.example.invalid
  insecure: true
  timeout: 45
  ca_bundle: certs/dev-ca.pem
  rule_id_start: 900000
  rule_id_end: 949999
  field_mapping_version: dev-windows-v2
  field_mapping:
    EventID: win.system.event_id
    Image: custom.image
  parent_rules:
    product:
      windows: 60000
    service:
      sysmon: 60004
      security:
        - 60103
        - 60104
    security_event_id:
      4720: 60109
    default: 60000
  remote_file: sigma_rules.xml
  backup_dir: backups/wazuh
strict_validation: true
""".lstrip(),
        encoding="utf-8",
    )

    config = PipelineConfig.from_file(config_file)

    assert config.sigma_dir == tmp_path / "examples/sigma"
    assert config.build_dir == tmp_path / "build"
    assert config.output_file == tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    assert config.wazuh.host == "https://wazuh.example.invalid"
    assert config.wazuh.insecure is True
    assert config.wazuh.timeout == 45
    assert config.wazuh.ca_bundle == tmp_path / "certs" / "dev-ca.pem"
    assert config.wazuh.rule_id_start == 900000
    assert config.wazuh.rule_id_end == 949999
    assert config.wazuh.field_mapping_version == "dev-windows-v2"
    assert config.wazuh.field_mapping == {
        "EventID": "win.system.event_id",
        "Image": "custom.image",
    }
    assert config.wazuh.parent_rules == {
        "product:windows": [60000],
        "service:sysmon": [60004],
        "service:security": [60103, 60104],
        "security_event_id:4720": [60109],
        "default": [60000],
    }
    assert config.wazuh.backup_dir == tmp_path / "backups" / "wazuh"
    assert config.strict_validation is True


def test_pipeline_config_from_mapping_keeps_relative_paths_relative():
    config = PipelineConfig.from_mapping(
        {
            "sigma_dir": "examples/sigma",
            "build_dir": "build",
            "output_file": "build/sigmahq/sigma_rules.xml",
            "wazuh": {
                "ca_bundle": "certs/dev-ca.pem",
                "backup_dir": "backups/wazuh",
            },
        }
    )

    assert config.sigma_dir == Path("examples/sigma")
    assert config.build_dir == Path("build")
    assert config.output_file == Path("build/sigmahq/sigma_rules.xml")
    assert config.wazuh.ca_bundle == Path("certs/dev-ca.pem")
    assert config.wazuh.backup_dir == Path("backups/wazuh")


def test_pipeline_config_normalizes_wazuh_contract_values():
    config = PipelineConfig.from_mapping(
        {
            "wazuh": {
                "host": " https://wazuh.example.invalid/ ",
                "remote_file": " sigma_rules.xml ",
            }
        }
    )

    assert config.wazuh.host == "https://wazuh.example.invalid"
    assert config.wazuh.remote_file == "sigma_rules.xml"


def test_pipeline_config_defaults_match_backend_contract():
    config = PipelineConfig.from_mapping({})

    assert config.wazuh.rule_id_start == DEFAULT_RULE_ID_START
    assert config.wazuh.rule_id_end == DEFAULT_RULE_ID_END
    assert config.wazuh.field_mapping_version == DEFAULT_FIELD_MAPPING_VERSION
    assert config.wazuh.parent_rules["product:windows"] == [60000]
    assert config.wazuh.parent_rules["service:sysmon"] == [60004]
    assert config.wazuh.parent_rules["security_event_id:4720"] == [60109]
    assert config.wazuh.parent_rules["category:process_creation"] == [61603]
    assert config.wazuh.parent_rules["category:registry_event"] == [61614, 61615, 61616]
    assert config.incremental_cache.enabled is False
    assert config.incremental_cache.manifest.name == "manifest.json"


def test_pipeline_config_loads_incremental_cache_contract(tmp_path):
    config = PipelineConfig.from_mapping(
        {
            "incremental_cache": {
                "enabled": "true",
                "directory": "cache",
                "manifest": "cache/state.json",
                "strict": "yes",
            }
        },
        base_dir=tmp_path,
    )

    assert config.incremental_cache.enabled is True
    assert config.incremental_cache.directory == tmp_path / "cache"
    assert config.incremental_cache.manifest == tmp_path / "cache" / "state.json"
    assert config.incremental_cache.strict is True


def test_pipeline_config_loads_active_test_contract(tmp_path):
    config = PipelineConfig.from_mapping(
        {
            "active_test": {
                "enabled": True,
                "test_dir": "active-tests",
                "generated_test_dir": "build/generated-active-tests",
                "report": "build/active-test-report.json",
                "generate_with_openai": True,
                "openai_model": "test-model",
                "openai_api_key_env": "OPENAI_KEY",
                "openai_timeout_seconds": 45,
                "openai_max_output_tokens": 900,
                "openai_max_retries": 4,
                "caldera_url": "http://127.0.0.1:8888",
                "caldera_api_key_env": "CALDERA_KEY",
                "caldera_auth_header": "KEY",
                "caldera_auth_scheme": "",
                "agent_platform": "WINDOWS",
                "agent_group": "dev-windows",
                "operation_timeout_seconds": 240,
                "operation_poll_interval_seconds": 3,
                "alert_indexer_url": "https://indexer.example.invalid:9200",
                "alert_index": "wazuh-alerts-*",
                "alert_username_env": "INDEXER_USER",
                "alert_password_env": "INDEXER_PASSWORD",
                "alert_timeout_seconds": 180,
                "alert_poll_interval_seconds": 4,
                "insecure": True,
                "ca_bundle": "certs/dev-ca.pem",
            }
        },
        base_dir=tmp_path,
    )

    assert config.active_test.enabled is True
    assert config.active_test.test_dir == tmp_path / "active-tests"
    assert config.active_test.generated_test_dir == tmp_path / "build" / "generated-active-tests"
    assert config.active_test.report == tmp_path / "build" / "active-test-report.json"
    assert config.active_test.generate_with_openai is True
    assert config.active_test.openai_model == "test-model"
    assert config.active_test.openai_api_key_env == "OPENAI_KEY"
    assert config.active_test.openai_timeout_seconds == 45
    assert config.active_test.openai_max_output_tokens == 900
    assert config.active_test.openai_max_retries == 4
    assert config.active_test.caldera_url == "http://127.0.0.1:8888"
    assert config.active_test.caldera_api_key_env == "CALDERA_KEY"
    assert config.active_test.agent_platform == "windows"
    assert config.active_test.agent_group == "dev-windows"
    assert config.active_test.alert_indexer_url == "https://indexer.example.invalid:9200"
    assert config.active_test.ca_bundle == tmp_path / "certs" / "dev-ca.pem"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"wazuh": {"host": "wazuh.example.com:55000"}}, "http"),
        ({"wazuh": {"insecure": "maybe"}}, "wazuh.insecure"),
        ({"wazuh": {"timeout": 0}}, "wazuh.timeout"),
        ({"wazuh": {"ca_bundle": True}}, "wazuh.ca_bundle"),
        ({"wazuh": {"rule_id_start": "nine"}}, "wazuh.rule_id_start"),
        ({"wazuh": {"rule_id_start": 950000, "rule_id_end": 900000}}, "rule_id_start"),
        ({"wazuh": {"rule_id_end": 10_000_000}}, "9999999"),
        ({"wazuh": {"field_mapping_version": True}}, "field_mapping_version"),
        ({"wazuh": {"field_mapping_version": "  "}}, "field_mapping_version"),
        ({"wazuh": {"field_mapping": []}}, "field_mapping"),
        ({"wazuh": {"field_mapping": {" ": "win.eventdata.image"}}}, "keys"),
        ({"wazuh": {"field_mapping": {"Image": " "}}}, "field_mapping.Image"),
        ({"wazuh": {"field_mapping": {"Image": True}}}, "field_mapping.Image"),
        ({"wazuh": {"parent_rules": []}}, "parent_rules"),
        ({"wazuh": {"parent_rules": {"service": []}}}, "service"),
        ({"wazuh": {"parent_rules": {"service": {"sysmon": 0}}}}, "positive"),
        ({"wazuh": {"parent_rules": {"service": {"sysmon": "nope"}}}}, "integer"),
        ({"wazuh": {"parent_rules": {"default": []}}}, "at least one"),
        ({"wazuh": {"remote_file": "../local_rules.xml"}}, "filename"),
        ({"wazuh": {"remote_file": "nested/sigma_rules.xml"}}, "path separators"),
        ({"wazuh": {"remote_file": "nested\\sigma_rules.xml"}}, "path separators"),
        ({"wazuh": {"remote_file": "sigma_rules.txt"}}, ".xml"),
        ({"strict_validation": "sometimes"}, "strict_validation"),
        ({"incremental_cache": []}, "incremental_cache config must be a mapping"),
        ({"incremental_cache": {"enabled": "sometimes"}}, "incremental_cache.enabled"),
        ({"incremental_cache": {"directory": True}}, "pipeline path values"),
        ({"incremental_cache": {"manifest": True}}, "pipeline path values"),
        ({"incremental_cache": {"manifest": "manifest.txt"}}, ".json"),
        ({"incremental_cache": {"directory": "cache.json", "manifest": "cache.json"}}, "must be different"),
        ({"incremental_cache": {"strict": "sometimes"}}, "incremental_cache.strict"),
        ({"active_test": []}, "active_test config must be a mapping"),
        ({"active_test": {"enabled": "sometimes"}}, "active_test.enabled"),
        ({"active_test": {"test_dir": True}}, "pipeline path values"),
        ({"active_test": {"generated_test_dir": True}}, "pipeline path values"),
        ({"active_test": {"report": True}}, "pipeline path values"),
        ({"active_test": {"generate_with_openai": "sometimes"}}, "active_test.generate_with_openai"),
        ({"active_test": {"generate_with_openai": True}}, "openai_model"),
        ({"active_test": {"openai_model": " "}}, "openai_model"),
        ({"active_test": {"openai_api_key_env": " "}}, "openai_api_key_env"),
        ({"active_test": {"openai_timeout_seconds": 0}}, "openai_timeout_seconds"),
        ({"active_test": {"openai_max_output_tokens": 0}}, "openai_max_output_tokens"),
        ({"active_test": {"openai_max_retries": -1}}, "openai_max_retries"),
        ({"active_test": {"caldera_url": "caldera.local:8888"}}, "http"),
        ({"active_test": {"caldera_auth_header": " "}}, "caldera_auth_header"),
        ({"active_test": {"operation_timeout_seconds": 0}}, "operation_timeout_seconds"),
        ({"active_test": {"operation_poll_interval_seconds": 0}}, "operation_poll_interval_seconds"),
        ({"active_test": {"alert_indexer_url": "indexer.local:9200"}}, "http"),
        ({"active_test": {"alert_index": " "}}, "alert_index"),
        ({"active_test": {"alert_timeout_seconds": 0}}, "alert_timeout_seconds"),
        ({"active_test": {"alert_poll_interval_seconds": 0}}, "alert_poll_interval_seconds"),
        ({"active_test": {"insecure": "sometimes"}}, "active_test.insecure"),
        ({"active_test": {"ca_bundle": True}}, "active_test.ca_bundle"),
    ],
)
def test_pipeline_config_rejects_invalid_production_values(payload, message):
    with pytest.raises(PipelineConfigError, match=message):
        PipelineConfig.from_mapping(payload)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"sigma_directory": "examples/sigma"}, "unknown pipeline config key"),
        ({"wazuh": {"remote_filename": "sigma_rules.xml"}}, "unknown wazuh config key"),
        ({"incremental_cache": {"cache_dir": "build/cache"}}, "unknown incremental_cache config key"),
        ({"active_test": {"caldera": {}}}, "unknown active_test config key"),
    ],
)
def test_pipeline_config_rejects_unknown_keys(payload, message):
    with pytest.raises(PipelineConfigError, match=message):
        PipelineConfig.from_mapping(payload)


def test_sigma_pipeline_returns_nonzero_when_config_is_missing(tmp_path):
    assert main(["doctor", "--config", str(tmp_path / "missing.yml")]) == 1


def test_sigma_pipeline_active_test_uses_configured_secret_env(monkeypatch, tmp_path):
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
active_test:
  test_dir: {(tmp_path / "active-tests").as_posix()}
  report: {(tmp_path / "build" / "active-test-report.json").as_posix()}
  caldera_url: http://127.0.0.1:8888
  caldera_api_key_env: CALDERA_KEY
  alert_indexer_url: https://indexer.example.invalid:9200
  alert_username_env: INDEXER_USER
  alert_password_env: INDEXER_PASSWORD
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("CALDERA_KEY", "caldera-secret")
    monkeypatch.setenv("INDEXER_USER", "indexer-user")
    monkeypatch.setenv("INDEXER_PASSWORD", "indexer-password")
    seen = {}

    def fake_run_active_tests_from_config(
        config,
        *,
        caldera_api_key,
        alert_username,
        alert_password,
        test_dir=None,
    ):
        seen["config"] = config
        seen["caldera_api_key"] = caldera_api_key
        seen["alert_username"] = alert_username
        seen["alert_password"] = alert_password
        seen["test_dir"] = test_dir
        return {"status": "succeeded"}

    monkeypatch.setattr(
        "wazuh_sigma.pipeline.run_active_tests_from_config",
        fake_run_active_tests_from_config,
    )

    assert main(["active-test", "--config", str(config_file)]) == 0

    assert seen["caldera_api_key"] == "caldera-secret"
    assert seen["alert_username"] == "indexer-user"
    assert seen["alert_password"] == "indexer-password"
    assert seen["test_dir"] == seen["config"].active_test.test_dir
    assert seen["config"].active_test.alert_indexer_url == "https://indexer.example.invalid:9200"


def test_sigma_pipeline_generate_active_tests_uses_openai_stage(monkeypatch, tmp_path):
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: {(tmp_path / "sigma").as_posix()}
active_test:
  generated_test_dir: {(tmp_path / "generated").as_posix()}
  openai_model: configured-model
""".lstrip(),
        encoding="utf-8",
    )
    seen = {}

    def fake_generate_active_tests_from_config(config, *, overwrite=False):
        seen["model"] = config.active_test.openai_model
        seen["generated_test_dir"] = config.active_test.generated_test_dir
        seen["overwrite"] = overwrite
        return {"status": "succeeded", "generated": 1}

    monkeypatch.setattr(
        "wazuh_sigma.pipeline.generate_active_tests_from_config",
        fake_generate_active_tests_from_config,
    )

    assert main(["generate-active-tests", "--config", str(config_file), "--openai-model", "cli-model", "--overwrite"]) == 0

    assert seen == {
        "model": "cli-model",
        "generated_test_dir": tmp_path / "generated",
        "overwrite": True,
    }


def test_sigma_pipeline_active_test_can_generate_then_run(monkeypatch, tmp_path):
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: {(tmp_path / "sigma").as_posix()}
active_test:
  generated_test_dir: {(tmp_path / "generated").as_posix()}
  caldera_url: http://127.0.0.1:8888
  caldera_api_key_env: CALDERA_KEY
  alert_indexer_url: https://indexer.example.invalid:9200
  alert_username_env: INDEXER_USER
  alert_password_env: INDEXER_PASSWORD
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("CALDERA_KEY", "caldera-secret")
    monkeypatch.setenv("INDEXER_USER", "indexer-user")
    monkeypatch.setenv("INDEXER_PASSWORD", "indexer-password")
    seen = {}

    def fake_generate_active_tests_from_config(config, *, overwrite=False):
        seen["generated_model"] = config.active_test.openai_model
        seen["overwrite"] = overwrite
        return {"status": "succeeded", "generated": 1}

    def fake_run_active_tests_from_config(
        config,
        *,
        caldera_api_key,
        alert_username,
        alert_password,
        test_dir=None,
    ):
        seen["test_dir"] = test_dir
        seen["caldera_api_key"] = caldera_api_key
        return {"status": "succeeded"}

    monkeypatch.setattr(
        "wazuh_sigma.pipeline.generate_active_tests_from_config",
        fake_generate_active_tests_from_config,
    )
    monkeypatch.setattr(
        "wazuh_sigma.pipeline.run_active_tests_from_config",
        fake_run_active_tests_from_config,
    )

    assert main(
        [
            "active-test",
            "--config",
            str(config_file),
            "--generate-tests",
            "--openai-model",
            "cli-model",
            "--overwrite-generated-tests",
        ]
    ) == 0

    assert seen["generated_model"] == "cli-model"
    assert seen["overwrite"] is True
    assert seen["test_dir"] == tmp_path / "generated"
    assert seen["caldera_api_key"] == "caldera-secret"


def test_sigma_pipeline_active_test_requires_caldera_secret(monkeypatch, tmp_path):
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        """
active_test:
  caldera_url: http://127.0.0.1:8888
  alert_indexer_url: https://indexer.example.invalid:9200
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_USER", "indexer-user")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "indexer-password")

    with pytest.raises(SystemExit):
        main(["active-test", "--config", str(config_file)])


def test_env_flag_rejects_ambiguous_boolean(monkeypatch):
    monkeypatch.setenv("WAZUH_INSECURE", "sometimes")

    with pytest.raises(PipelineConfigError, match="WAZUH_INSECURE"):
        env_flag("WAZUH_INSECURE")


def test_sigma_pipeline_doctor_reports_local_readiness(monkeypatch, tmp_path, capsys):
    sigma_dir = tmp_path / "rules" / "sigma"
    sigma_dir.mkdir(parents=True)
    (sigma_dir / "rule.yml").write_text(
        """
title: Doctor Smoke
logsource:
  service: sysmon
detection:
  selection:
    Image: doctor.exe
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    report_file = build_dir / "doctor-report.json"
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: {sigma_dir.as_posix()}
build_dir: {build_dir.as_posix()}
output_file: {(build_dir / "sigmahq" / "sigma_rules.xml").as_posix()}
conversion_report: {(build_dir / "conversion-report.json").as_posix()}
smoke_report: {(build_dir / "smoke-report.json").as_posix()}
wazuh:
  host: https://example:55000
  remote_file: sigma_rules.xml
  backup_dir: {(tmp_path / "backups" / "wazuh").as_posix()}
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.delenv("WAZUH_USER", raising=False)
    monkeypatch.delenv("WAZUH_PASSWORD", raising=False)

    assert main(["doctor", "--config", str(config_file), "--report", str(report_file)]) == 0

    output = json.loads(capsys.readouterr().out)
    written = json.loads(report_file.read_text(encoding="utf-8"))
    assert output == written
    assert output["status"] == "warn"
    assert output["summary"]["fail"] == 0
    assert output["summary"]["warn"] >= 1
    checks = {check["name"]: check for check in output["checks"]}
    assert checks["sigma_dir"]["status"] == "ok"
    assert checks["sigma_rules"]["count"] == 1
    assert checks["wazuh_host"]["status"] == "warn"
    assert checks["wazuh_credentials"]["status"] == "warn"


def test_sigma_pipeline_doctor_require_deploy_fails_for_missing_deploy_readiness(monkeypatch, tmp_path):
    sigma_dir = tmp_path / "rules" / "sigma"
    sigma_dir.mkdir(parents=True)
    (sigma_dir / "rule.yml").write_text(
        """
title: Doctor Deploy
logsource:
  service: sysmon
detection:
  selection:
    Image: doctor.exe
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: {sigma_dir.as_posix()}
wazuh:
  host: https://example:55000
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.delenv("WAZUH_USER", raising=False)
    monkeypatch.delenv("WAZUH_PASSWORD", raising=False)

    assert main(["doctor", "--config", str(config_file), "--require-deploy"]) == 1


def test_sigma_pipeline_smoke_uses_config(tmp_path):
    sigma_dir = tmp_path / "rules" / "sigma"
    sigma_dir.mkdir(parents=True)
    (sigma_dir / "rule.yml").write_text(
        """
title: Pipeline Smoke
logsource:
  service: sysmon
detection:
  selection:
    Image: smoke.exe
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )
    config_file = tmp_path / "pipeline.yml"
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    conversion_report = tmp_path / "build" / "conversion-report.json"
    smoke_report = tmp_path / "build" / "smoke-report.json"
    config_file.write_text(
        f"""
sigma_dir: {sigma_dir.as_posix()}
build_dir: {(tmp_path / "build").as_posix()}
output_file: {output.as_posix()}
conversion_report: {conversion_report.as_posix()}
smoke_report: {smoke_report.as_posix()}
wazuh:
  rule_id_start: 900000
  rule_id_end: 900010
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )

    assert main(["--config", str(config_file), "smoke"]) == 0
    assert output.exists()
    assert conversion_report.exists()
    data = json.loads(smoke_report.read_text(encoding="utf-8"))
    assert data["status"] == "succeeded"
    assert data["error"] is None
    assert data["error_type"] is None
    assert data["failed_stage"] is None
    # Verify core config structure and values
    assert data["config"]["sigma_dir"] == str(sigma_dir)
    assert data["config"]["build_dir"] == str(tmp_path / "build")
    assert data["config"]["output_file"] == str(output)
    assert data["config"]["conversion_report"] == str(conversion_report)
    assert data["config"]["smoke_report"] == str(smoke_report)
    assert data["config"]["strict_validation"] is False
    assert data["config"]["docker"] is False

    # Verify Wazuh config includes parent rules (added in parent rule anchoring feature)
    assert data["config"]["wazuh"]["rule_id_start"] == 900000
    assert data["config"]["wazuh"]["rule_id_end"] == 900010
    assert data["config"]["wazuh"]["field_mapping_version"] == "wazuh-windows-eventdata-v1"
    assert data["config"]["wazuh"]["remote_file"] == "sigma_rules.xml"
    assert "parent_rules" in data["config"]["wazuh"]
    assert data["config"]["wazuh"]["parent_rules"]["product:windows"] == [60000]
    assert data["conversion"]["total_converted"] == 1
    assert data["validator"]["failed_checks"] == 0


def test_sigma_pipeline_accepts_config_before_or_after_command():
    parser = build_parser()

    before = parser.parse_args(["--config", "ci/pipeline.yml", "smoke"])
    after = parser.parse_args(["smoke", "--config", "ci/pipeline.yml"])

    assert before.config == Path("ci/pipeline.yml")
    assert after.config == Path("ci/pipeline.yml")


def test_sigma_pipeline_accepts_strict_validation_overrides():
    parser = build_parser()

    strict = parser.parse_args(["validate", "--strict"])
    no_strict = parser.parse_args(["smoke", "--no-strict"])

    assert strict.strict is True
    assert strict.no_strict is False
    assert no_strict.strict is False
    assert no_strict.no_strict is True


@pytest.mark.parametrize(
    "flags",
    [
        ["--dry-run", "--validate-only"],
        ["--restart", "--no-restart"],
    ],
)
def test_sigma_pipeline_deploy_parser_rejects_mutually_exclusive_flags(flags):
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["deploy", *flags])


def test_sigma_pipeline_strict_validation_fails_on_warnings(tmp_path):
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    output.parent.mkdir(parents=True)
    output.write_text(
        (
            '<group name="sigma_rules,">'
            '<rule id="900000" level="5">'
            '<description>warning-only rule</description>'
            f'<regex>{"a" * 2000}</regex>'
            '</rule>'
            '</group>'
        ),
        encoding="utf-8",
    )
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
output_file: {output.as_posix()}
strict_validation: true
wazuh:
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )

    assert main(["validate", "--config", str(config_file)]) == 1
    assert main(["validate", "--config", str(config_file), "--no-strict"]) == 0


def test_sigma_pipeline_smoke_writes_failure_report(monkeypatch, tmp_path):
    sigma_dir = tmp_path / "rules" / "sigma"
    sigma_dir.mkdir(parents=True)
    (sigma_dir / "rule.yml").write_text(
        """
title: Smoke Failure Report
logsource:
  service: sysmon
detection:
  selection:
    Image: failure.exe
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )
    smoke_report = tmp_path / "build" / "smoke-report.json"
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: {sigma_dir.as_posix()}
output_file: {(tmp_path / "build" / "sigmahq" / "sigma_rules.xml").as_posix()}
conversion_report: {(tmp_path / "build" / "conversion-report.json").as_posix()}
smoke_report: {smoke_report.as_posix()}
wazuh:
  rule_id_start: 900000
  rule_id_end: 900010
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )

    def fail_validation(*args, **kwargs):
        raise RuntimeError("validator exploded")

    monkeypatch.setattr("wazuh_sigma.pipeline_stages.validate_output", fail_validation)

    assert main(["smoke", "--config", str(config_file)]) == 1
    report = json.loads(smoke_report.read_text(encoding="utf-8"))
    assert report["status"] == "failed"
    assert report["conversion"]["total_converted"] == 1
    assert report["validator"] is None
    assert report["docker"] is None
    assert report["error"] == "validator exploded"
    assert report["error_type"] == "RuntimeError"
    assert report["failed_stage"] == "validator"
    assert report["config"]["output_file"] == str(tmp_path / "build" / "sigmahq" / "sigma_rules.xml")
    assert report["config"]["wazuh"]["rule_id_start"] == 900000
    assert report["config"]["wazuh"]["rule_id_end"] == 900010
    assert report["config"]["wazuh"]["remote_file"] == "sigma_rules.xml"


def test_sigma_pipeline_smoke_reports_conversion_stage_failures(tmp_path):
    smoke_report = tmp_path / "build" / "smoke-report.json"
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: {(tmp_path / "missing-sigma").as_posix()}
output_file: {(tmp_path / "build" / "sigmahq" / "sigma_rules.xml").as_posix()}
conversion_report: {(tmp_path / "build" / "conversion-report.json").as_posix()}
smoke_report: {smoke_report.as_posix()}
wazuh:
  rule_id_start: 900000
  rule_id_end: 900010
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )

    assert main(["smoke", "--config", str(config_file)]) == 1
    report = json.loads(smoke_report.read_text(encoding="utf-8"))
    assert report["status"] == "failed"
    assert report["conversion"] is None
    assert report["validator"] is None
    assert report["docker"] is None
    assert report["error_type"] == "RuntimeError"
    assert report["failed_stage"] == "conversion"
    assert "no Sigma rules converted" in report["error"]


def test_sigma_pipeline_smoke_does_not_hide_programming_errors(monkeypatch, tmp_path):
    sigma_dir = tmp_path / "rules" / "sigma"
    sigma_dir.mkdir(parents=True)
    (sigma_dir / "rule.yml").write_text(
        """
title: Smoke Programming Error
logsource:
  service: sysmon
detection:
  selection:
    Image: bug.exe
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )
    smoke_report = tmp_path / "build" / "smoke-report.json"
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: {sigma_dir.as_posix()}
output_file: {(tmp_path / "build" / "sigmahq" / "sigma_rules.xml").as_posix()}
conversion_report: {(tmp_path / "build" / "conversion-report.json").as_posix()}
smoke_report: {smoke_report.as_posix()}
wazuh:
  rule_id_start: 900000
  rule_id_end: 900010
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )

    def fail_with_programming_error(*args, **kwargs):
        raise TypeError("validator contract changed")

    monkeypatch.setattr("wazuh_sigma.pipeline_stages.validate_output", fail_with_programming_error)

    with pytest.raises(TypeError, match="validator contract changed"):
        main(["smoke", "--config", str(config_file)])

    assert not smoke_report.exists()


def test_sigma_pipeline_convert_and_validate_are_independent_stages(tmp_path):
    sigma_dir = tmp_path / "rules" / "sigma"
    sigma_dir.mkdir(parents=True)
    (sigma_dir / "rule.yml").write_text(
        """
title: Pipeline Stage Commands
logsource:
  service: sysmon
detection:
  selection:
    Image: staged.exe
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )
    config_file = tmp_path / "pipeline.yml"
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    conversion_report = tmp_path / "build" / "conversion-report.json"
    config_file.write_text(
        f"""
sigma_dir: {sigma_dir.as_posix()}
build_dir: {(tmp_path / "build").as_posix()}
output_file: {output.as_posix()}
conversion_report: {conversion_report.as_posix()}
wazuh:
  rule_id_start: 900000
  rule_id_end: 900010
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )

    assert main(["convert", "--config", str(config_file)]) == 0
    assert output.exists()
    assert conversion_report.exists()

    assert main(["validate", "--config", str(config_file)]) == 0


def test_sigma_pipeline_convert_uses_configured_field_mapping(tmp_path):
    sigma_dir = tmp_path / "rules" / "sigma"
    sigma_dir.mkdir(parents=True)
    (sigma_dir / "rule.yml").write_text(
        """
title: Pipeline Custom Field Mapping
logsource:
  service: sysmon
detection:
  selection:
    EventID: 1
    Image: mapped.exe
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )
    config_file = tmp_path / "pipeline.yml"
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    conversion_report = tmp_path / "build" / "conversion-report.json"
    config_file.write_text(
        f"""
sigma_dir: {sigma_dir.as_posix()}
build_dir: {(tmp_path / "build").as_posix()}
output_file: {output.as_posix()}
conversion_report: {conversion_report.as_posix()}
wazuh:
  rule_id_start: 900000
  rule_id_end: 900010
  field_mapping_version: dev-custom-v1
  field_mapping:
    Image: custom.process.image
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )

    assert main(["convert", "--config", str(config_file)]) == 0

    xml = output.read_text(encoding="utf-8")
    report = json.loads(conversion_report.read_text(encoding="utf-8"))
    assert 'name="custom.process.image"' in xml
    assert 'name="win.system.eventID"' in xml
    assert 'name="win.eventdata.image"' not in xml
    assert report["field_mapping_version"] == "dev-custom-v1"


def test_sigma_pipeline_convert_uses_incremental_cache_when_enabled(tmp_path):
    sigma_dir = tmp_path / "rules" / "sigma"
    sigma_dir.mkdir(parents=True)
    first_rule = sigma_dir / "first.yml"
    first_rule.write_text(
        """
id: 11111111-1111-1111-1111-111111111111
title: Incremental First
logsource:
  service: sysmon
detection:
  selection:
    Image: first.exe
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    conversion_report = tmp_path / "build" / "conversion-report.json"
    cache_dir = tmp_path / "build" / "conversion-cache"
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: {sigma_dir.as_posix()}
build_dir: {(tmp_path / "build").as_posix()}
output_file: {output.as_posix()}
conversion_report: {conversion_report.as_posix()}
wazuh:
  rule_id_start: 900000
  rule_id_end: 900010
  remote_file: sigma_rules.xml
incremental_cache:
  enabled: true
  directory: {cache_dir.as_posix()}
  manifest: {(cache_dir / "manifest.json").as_posix()}
""".lstrip(),
        encoding="utf-8",
    )

    assert main(["convert", "--config", str(config_file)]) == 0
    first_report = json.loads(conversion_report.read_text(encoding="utf-8"))
    assert first_report["converted_rules"][0]["wazuh_id"] == "900000"
    assert first_report["converted_rules"][0]["conversion_cache"]["status"] == "miss"
    assert first_report["incremental_conversion"]["active_rules"] == 1

    second_rule = sigma_dir / "second.yml"
    second_rule.write_text(
        """
id: 22222222-2222-2222-2222-222222222222
title: Incremental Second
logsource:
  service: sysmon
detection:
  selection:
    Image: second.exe
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )

    assert main(["convert", "--config", str(config_file)]) == 0
    second_report = json.loads(conversion_report.read_text(encoding="utf-8"))
    cache_by_title = {
        rule["sigma_title"]: rule["conversion_cache"]["status"]
        for rule in second_report["converted_rules"]
    }
    ids_by_title = {rule["sigma_title"]: rule["wazuh_id"] for rule in second_report["converted_rules"]}

    assert cache_by_title == {
        "Incremental First": "hit",
        "Incremental Second": "miss",
    }
    assert ids_by_title == {
        "Incremental First": "900000",
        "Incremental Second": "900001",
    }
    assert second_report["incremental_conversion"]["active_rules"] == 2
    assert second_report["incremental_conversion"]["cache_hits"] == 1
    assert second_report["incremental_conversion"]["cache_misses"] == 1

    first_rule.write_text(
        """
id: "11111111-1111-1111-1111-111111111111"
title: Incremental First
logsource: {service: sysmon}
detection:
  condition: selection
  selection:
    Image: first.exe
""".lstrip(),
        encoding="utf-8",
    )

    assert main(["convert", "--config", str(config_file)]) == 0
    formatting_report = json.loads(conversion_report.read_text(encoding="utf-8"))
    formatting_cache_by_title = {
        rule["sigma_title"]: rule["conversion_cache"]["status"]
        for rule in formatting_report["converted_rules"]
    }
    assert formatting_cache_by_title == {
        "Incremental First": "hit",
        "Incremental Second": "hit",
    }
    assert formatting_report["incremental_conversion"]["cache_hits"] == 2
    assert formatting_report["incremental_conversion"]["cache_misses"] == 0


def test_sigma_pipeline_deploy_passes_configured_transport_options(monkeypatch, tmp_path):
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    output.parent.mkdir(parents=True)
    output.write_text(
        '<group name="sigma_rules,"><rule id="900000" level="5"><description>x</description></rule></group>',
        encoding="utf-8",
    )
    ca_bundle = tmp_path / "certs" / "dev-ca.pem"
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: examples/sigma
build_dir: {(tmp_path / "build").as_posix()}
output_file: {output.as_posix()}
wazuh:
  host: https://wazuh.example.invalid
  insecure: false
  timeout: 45
  ca_bundle: {ca_bundle.as_posix()}
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )
    calls = {}

    def fake_deploy_rules(**kwargs):
        calls.update(kwargs)
        return {"uploaded": True}

    monkeypatch.setattr("wazuh_sigma.pipeline.deploy_rules", fake_deploy_rules)

    assert main(["deploy", "--config", str(config_file), "--username", "alice", "--password", "secret"]) == 0

    assert calls["timeout"] == 45
    assert calls["ca_bundle"] == str(ca_bundle)
    assert calls["verify_tls"] is True


def test_sigma_pipeline_deploy_cli_overrides_configured_transport_options(monkeypatch, tmp_path):
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    output.parent.mkdir(parents=True)
    output.write_text(
        '<group name="sigma_rules,"><rule id="900000" level="5"><description>x</description></rule></group>',
        encoding="utf-8",
    )
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: examples/sigma
build_dir: {(tmp_path / "build").as_posix()}
output_file: {output.as_posix()}
wazuh:
  host: https://wazuh.example.invalid
  timeout: 45
  ca_bundle: certs/config-ca.pem
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )
    calls = {}

    def fake_deploy_rules(**kwargs):
        calls.update(kwargs)
        return {"uploaded": True}

    monkeypatch.setattr("wazuh_sigma.pipeline.deploy_rules", fake_deploy_rules)

    assert (
        main(
            [
                "deploy",
                "--config",
                str(config_file),
                "--username",
                "alice",
                "--password",
                "secret",
                "--timeout",
                "9",
                "--ca-bundle",
                "certs/cli-ca.pem",
            ]
        )
        == 0
    )

    assert calls["timeout"] == 9
    assert calls["ca_bundle"] == "certs/cli-ca.pem"


def test_sigma_pipeline_deploy_can_run_preflight_smoke(monkeypatch, tmp_path):
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    output.parent.mkdir(parents=True)
    output.write_text(
        '<group name="sigma_rules,"><rule id="900000" level="5"><description>x</description></rule></group>',
        encoding="utf-8",
    )
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: examples/sigma
build_dir: {(tmp_path / "build").as_posix()}
output_file: {output.as_posix()}
strict_validation: true
wazuh:
  host: https://wazuh.example.invalid
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )
    calls = []

    def fake_run_smoke(config, *, docker, strict):
        calls.append(("smoke", docker, strict, config.output_file))
        return {"status": "succeeded"}

    def fake_deploy_rules(**kwargs):
        calls.append(("deploy", kwargs["local_file"]))
        return {"uploaded": True}

    monkeypatch.setattr("wazuh_sigma.pipeline.run_smoke", fake_run_smoke)
    monkeypatch.setattr("wazuh_sigma.pipeline.deploy_rules", fake_deploy_rules)

    assert (
        main(
            [
                "deploy",
                "--config",
                str(config_file),
                "--username",
                "alice",
                "--password",
                "secret",
                "--preflight-smoke",
            ]
        )
        == 0
    )

    assert calls == [
        ("smoke", False, True, output),
        ("deploy", output),
    ]


def test_sigma_pipeline_deploy_preflight_smoke_failure_prevents_deploy(monkeypatch, tmp_path):
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: {(tmp_path / "rules" / "sigma").as_posix()}
build_dir: {(tmp_path / "build").as_posix()}
output_file: {output.as_posix()}
wazuh:
  host: https://wazuh.example.invalid
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )

    def fake_run_smoke(config, *, docker, strict):
        raise RuntimeError("preflight failed")

    def fake_deploy_rules(**kwargs):
        raise AssertionError("deploy should not be called after preflight failure")

    monkeypatch.setattr("wazuh_sigma.pipeline.run_smoke", fake_run_smoke)
    monkeypatch.setattr("wazuh_sigma.pipeline.deploy_rules", fake_deploy_rules)

    assert (
        main(
            [
                "deploy",
                "--config",
                str(config_file),
                "--username",
                "alice",
                "--password",
                "secret",
                "--preflight-smoke",
            ]
        )
        == 1
    )


def test_sigma_pipeline_deploy_rejects_rollback_without_backup_before_preflight(monkeypatch, tmp_path):
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: {(tmp_path / "rules" / "sigma").as_posix()}
build_dir: {(tmp_path / "build").as_posix()}
output_file: {output.as_posix()}
wazuh:
  host: https://wazuh.example.invalid
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )

    def fake_run_smoke(*args, **kwargs):
        raise AssertionError("preflight should not run when deploy options are invalid")

    def fake_deploy_rules(**kwargs):
        raise AssertionError("deploy should not run when deploy options are invalid")

    monkeypatch.setattr("wazuh_sigma.pipeline.run_smoke", fake_run_smoke)
    monkeypatch.setattr("wazuh_sigma.pipeline.deploy_rules", fake_deploy_rules)

    assert (
        main(
            [
                "deploy",
                "--config",
                str(config_file),
                "--username",
                "alice",
                "--password",
                "secret",
                "--preflight-smoke",
                "--rollback-on-failure",
            ]
        )
        == 1
    )


def test_sigma_pipeline_deploy_writes_failure_report(monkeypatch, tmp_path):
    output = tmp_path / "build" / "sigmahq" / "sigma_rules.xml"
    output.parent.mkdir(parents=True)
    output.write_text(
        '<group name="sigma_rules,"><rule id="900000" level="5"><description>x</description></rule></group>',
        encoding="utf-8",
    )
    report = tmp_path / "build" / "deploy-report.json"
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        f"""
sigma_dir: examples/sigma
build_dir: {(tmp_path / "build").as_posix()}
output_file: {output.as_posix()}
wazuh:
  host: https://wazuh.example.invalid
  remote_file: sigma_rules.xml
""".lstrip(),
        encoding="utf-8",
    )

    def fake_deploy_rules(**kwargs):
        raise WazuhDeploymentError("deployment failed", {"uploaded": True, "rolled_back": True})

    monkeypatch.setattr("wazuh_sigma.pipeline.deploy_rules", fake_deploy_rules)

    assert (
        main(
            [
                "deploy",
                "--config",
                str(config_file),
                "--username",
                "alice",
                "--password",
                "secret",
                "--report",
                str(report),
            ]
        )
        == 1
    )
    assert json.loads(report.read_text(encoding="utf-8")) == {"rolled_back": True, "uploaded": True}


def test_docker_native_smoke_uses_bounded_subprocess_timeout(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("wazuh_sigma.pipeline_stages.subprocess.run", fake_run)

    report = docker_native_smoke()

    assert len(calls) == 2
    assert all(kwargs["timeout"] == DOCKER_SMOKE_TIMEOUT_SECONDS for _, kwargs in calls)
    assert all(item["timeout_seconds"] == DOCKER_SMOKE_TIMEOUT_SECONDS for item in report["commands"])
