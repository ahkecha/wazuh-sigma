"""End-to-end advisor integration tests.

Proves the advisor is optional and non-authoritative: disabled conversion is
byte-identical to the pre-advisor pipeline (ignoring the timestamp comment),
report-only mode never changes levels, provider failure respects fail-open, and
the conversion report carries traceable, secret-free advisor metadata.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from tests.advisor_helpers import FakeProvider, make_output, make_rule
from wazuh_sigma.advisor import runtime
from wazuh_sigma.advisor.cache import AdvisorCache
from wazuh_sigma.advisor.errors import AdvisorUnavailableError
from wazuh_sigma.advisor.policy import PolicyConfig
from wazuh_sigma.advisor.runtime import make_advisor_hook
from wazuh_sigma.advisor.service import AdvisorService, AdvisorServiceConfig
from wazuh_sigma.config import AdvisorConfig, PipelineConfig
from wazuh_sigma.converter.service import SigmaToWazuhConverter
from wazuh_sigma.pipeline_stages import convert_from_config

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "sigma"


def _write_safe_examples(tmp_path: Path) -> Path:
    rules_dir = tmp_path / "safe_sigma"
    rules_dir.mkdir(exist_ok=True)
    (rules_dir / "process.yml").write_text(
        """
title: Safe Advisor Process Example
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith: '\\cmd.exe'
  selection_cli:
    CommandLine|contains: whoami
  condition: selection_img and selection_cli
level: medium
tags:
  - attack.execution
""",
        encoding="utf-8",
    )
    (rules_dir / "network.yml").write_text(
        """
title: Safe Advisor Network Example
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationPort:
      - 4444
      - 5555
  condition: selection
level: high
tags:
  - attack.command-and-control
""",
        encoding="utf-8",
    )
    return rules_dir


def _render(converter: SigmaToWazuhConverter, rules) -> str:
    xml = converter.backend.render_ruleset(rules)
    # Drop the timestamp comment so comparisons are deterministic.
    return "\n".join(line for line in xml.splitlines() if "Sigma to Wazuh Conversion" not in line)


def _hook_service(advisor_config: AdvisorConfig, provider) -> AdvisorService:
    cache = AdvisorCache(advisor_config.cache_directory, enabled=advisor_config.cache_enabled)
    service_config = AdvisorServiceConfig(
        provider_name=advisor_config.provider,
        primary_model=advisor_config.primary_model,
        escalation_model=advisor_config.escalation_model,
        fail_open=advisor_config.fail_open,
        escalation_enabled=advisor_config.escalation_enabled,
        policy=PolicyConfig(
            mode=advisor_config.mode,
            minimum_confidence=advisor_config.minimum_confidence,
            maximum_level_delta=advisor_config.maximum_level_delta,
        ),
    )
    return AdvisorService(provider, cache, service_config)


def test_disabled_advisor_matches_no_advisor(tmp_path):
    examples = _write_safe_examples(tmp_path)
    plain = SigmaToWazuhConverter()
    plain_rules = plain.convert_directory(str(examples))
    plain_xml = _render(plain, plain_rules)
    assert "advisor" not in plain.generate_report()

    # Advisor "enabled" but hook is None (disabled path) must be identical.
    disabled = SigmaToWazuhConverter(advisor_hook=None)
    disabled_rules = disabled.convert_directory(str(examples))
    assert _render(disabled, disabled_rules) == plain_xml


def test_report_only_does_not_change_xml(tmp_path):
    examples = _write_safe_examples(tmp_path)
    plain = SigmaToWazuhConverter()
    plain_xml = _render(plain, plain.convert_directory(str(examples)))

    advisor_config = AdvisorConfig(
        enabled=True,
        primary_model="test-model",
        mode="report-only",
        cache_directory=tmp_path / "cache",
    )
    # Model always recommends a wildly different level; report-only must ignore it.
    provider = FakeProvider(*[make_output(recommended_level=1, confidence=0.99) for _ in range(10)])
    service = _hook_service(advisor_config, provider)
    hook = make_advisor_hook(service, advisor_config)

    advised = SigmaToWazuhConverter(advisor_hook=hook)
    advised_xml = _render(advised, advised.convert_directory(str(examples)))
    assert advised_xml == plain_xml


def test_report_only_records_advisor_metadata(tmp_path):
    examples = _write_safe_examples(tmp_path)
    advisor_config = AdvisorConfig(
        enabled=True,
        primary_model="test-model",
        mode="report-only",
        cache_directory=tmp_path / "cache",
    )
    provider = FakeProvider(*[make_output(recommended_level=9, confidence=0.9) for _ in range(10)])
    service = _hook_service(advisor_config, provider)
    hook = make_advisor_hook(service, advisor_config)

    converter = SigmaToWazuhConverter(advisor_hook=hook)
    rules = converter.convert_directory(str(examples))
    assert rules
    converter.advisor_summary = runtime.build_run_advisor_summary(service, advisor_config)
    report = converter.generate_report()

    assert report["advisor"]["mode"] == "report-only"
    for rule in report["converted_rules"]:
        advisor = rule["advisor"]
        assert advisor["status"] in {"success", "cache_hit"}
        assert advisor["accepted"] is False
        assert advisor["effective_level"] == advisor["default_level"]
        assert advisor["recommended_level"] == 9


def test_fail_open_conversion_succeeds_on_provider_failure(tmp_path):
    examples = _write_safe_examples(tmp_path)
    advisor_config = AdvisorConfig(
        enabled=True,
        primary_model="test-model",
        mode="report-only",
        fail_open=True,
        cache_directory=tmp_path / "cache",
    )
    provider = FakeProvider(*[AdvisorUnavailableError("down") for _ in range(10)])
    service = _hook_service(advisor_config, provider)
    hook = make_advisor_hook(service, advisor_config)

    converter = SigmaToWazuhConverter(advisor_hook=hook)
    rules = converter.convert_directory(str(examples))
    assert rules  # conversion still produced rules
    report = converter.generate_report()
    for rule in report["converted_rules"]:
        assert rule["advisor"]["status"] == "failed_open"


def test_report_contains_no_secrets(tmp_path):
    examples = _write_safe_examples(tmp_path)
    advisor_config = AdvisorConfig(
        enabled=True,
        primary_model="test-model",
        mode="report-only",
        cache_directory=tmp_path / "cache",
    )
    provider = FakeProvider(*[make_output() for _ in range(10)])
    service = _hook_service(advisor_config, provider)
    hook = make_advisor_hook(service, advisor_config)
    converter = SigmaToWazuhConverter(advisor_hook=hook)
    converter.convert_directory(str(examples))
    converter.advisor_summary = runtime.build_run_advisor_summary(service, advisor_config)
    serialized = json.dumps(converter.generate_report())
    for forbidden in ("OPENAI_API_KEY", "Authorization", "Bearer ", "sk-"):
        assert forbidden not in serialized


def test_convert_from_config_wires_advisor(tmp_path, monkeypatch):
    """The pipeline stage builds and uses the advisor when enabled in config."""

    def inject_fake_service(config, provider=None, telemetry=None):
        fake = FakeProvider(*[make_output(recommended_level=9, confidence=0.9) for _ in range(10)])
        return _hook_service(config, fake)

    monkeypatch.setattr(
        "wazuh_sigma.advisor.runtime.build_advisor_service",
        inject_fake_service,
    )

    base = PipelineConfig.from_file(str(Path(__file__).resolve().parents[1] / "pipeline.yml"))
    advisor = AdvisorConfig(
        enabled=True,
        primary_model="test-model",
        mode="report-only",
        cache_directory=tmp_path / "cache",
    )
    config = replace(
        base,
        sigma_dir=_write_safe_examples(tmp_path),
        output_file=tmp_path / "rules.xml",
        conversion_report=tmp_path / "report.json",
        advisor=advisor,
    )
    report = convert_from_config(config)
    assert report["advisor"]["mode"] == "report-only"
    assert all(r["advisor"]["accepted"] is False for r in report["converted_rules"])
