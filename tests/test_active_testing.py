import json

import httpx
import openai
import pytest

from wazuh_sigma.active_testing.alerts import (
    AlertSearchConfig,
    WazuhIndexerAlertClient,
    build_alert_query,
)
from wazuh_sigma.active_testing.caldera import CalderaAuth, CalderaClient, substitute_marker
from wazuh_sigma.active_testing.models import ExpectedAlertSpec, load_active_tests
from wazuh_sigma.active_testing.openai_generator import (
    ActiveTestGenerationRuntime,
    GeneratedCalderaTest,
    OpenAIActiveTestRateLimitError,
    OpenAICalderaTestProvider,
    _generate_one,
    _load_sigma_rules,
    generate_active_tests_with_openai,
)
from wazuh_sigma.deploy.client import HttpResponse


def test_load_active_test_manifest(tmp_path):
    manifest = tmp_path / "cmd.yml"
    manifest.write_text(
        """
name: command shell detection
sigma_id: 036d9a52-7a13-11ec-a8a3-0242ac120002
caldera:
  executor: cmd
  platform: windows
  command: cmd.exe /c echo {{marker}} && whoami
  cleanup:
    - cmd.exe /c echo cleanup {{marker}}
  timeout: 30
expect:
  rule_group: sigma_windows_command_line_execution_via_cmd_exe
  marker: "{{marker}}"
""".lstrip(),
        encoding="utf-8",
    )

    tests = load_active_tests(tmp_path)

    assert len(tests) == 1
    assert tests[0].name == "command shell detection"
    assert tests[0].caldera.executor == "cmd"
    assert tests[0].expect.rule_group == "sigma_windows_command_line_execution_via_cmd_exe"


def test_caldera_client_uses_documented_v2_endpoints():
    calls = []

    def transport(method, url, body, headers):
        calls.append((method, url, body, headers))
        if url.endswith("/api/v2/health"):
            return HttpResponse(200, b'{"ok": true}', {})
        if url.endswith("/api/v2/agents"):
            return HttpResponse(200, b'[{"paw":"abc","platform":"windows","group":"red","status":"alive"}]', {})
        return HttpResponse(404, b"{}", {})

    client = CalderaClient(
        "http://127.0.0.1:8888",
        CalderaAuth(header_name="KEY", token="secret"),
        transport=transport,
    )

    assert client.health() == {"ok": True}
    agent = client.find_live_agent(platform="windows")

    assert agent["paw"] == "abc"
    assert calls[0][0] == "GET"
    assert calls[0][1] == "http://127.0.0.1:8888/api/v2/health"
    assert calls[0][3]["KEY"] == "secret"


def test_caldera_create_ability_substitutes_marker():
    captured = {}

    def transport(method, url, body, headers):
        captured["method"] = method
        captured["url"] = url
        captured["payload"] = json.loads(body.decode("utf-8"))
        return HttpResponse(200, json.dumps(captured["payload"]).encode("utf-8"), {})

    client = CalderaClient(
        "http://127.0.0.1:8888",
        CalderaAuth(token="secret"),
        transport=transport,
    )
    spec = load_active_tests_from_inline(tmp_path=None)[0].caldera

    ability = client.create_ability(name="active", spec=spec, marker="marker-123")

    assert captured["method"] == "POST"
    assert captured["url"] == "http://127.0.0.1:8888/api/v2/abilities"
    assert captured["payload"]["executors"][0]["command"] == "cmd.exe /c echo marker-123"
    assert ability["ability_id"]


def test_alert_query_includes_rule_group_rule_id_and_marker():
    query = build_alert_query(
        ExpectedAlertSpec(rule_id="900000", rule_group="sigma_test", marker="abc"),
        marker="fallback",
    )

    filters = query["query"]["bool"]["filter"]
    assert {"term": {"rule.id": "900000"}} in filters
    assert {"term": {"rule.groups": "sigma_test"}} in filters
    assert any(item.get("query_string", {}).get("query") == '"abc"' for item in filters)


def test_alert_client_returns_first_matching_hit():
    def transport(method, url, body, headers):
        payload = {
            "hits": {
                "hits": [
                    {"_id": "alert-1", "_source": {"rule": {"id": "900000"}}},
                ]
            }
        }
        return HttpResponse(200, json.dumps(payload).encode("utf-8"), {})

    client = WazuhIndexerAlertClient(
        AlertSearchConfig(
            base_url="https://indexer.example.invalid:9200",
            username="admin",
            password="secret",
            verify_tls=False,
        ),
        transport=transport,
    )

    result = client.wait_for_alert(
        ExpectedAlertSpec(rule_id="900000"),
        marker="marker",
        timeout=1,
        poll_interval=1,
    )

    assert result["matched"] is True
    assert result["first_hit"]["_id"] == "alert-1"


def test_substitute_marker():
    assert substitute_marker("echo {{marker}}", "abc") == "echo abc"


def test_openai_generator_writes_valid_active_test_manifest(tmp_path):
    sigma_dir = tmp_path / "sigma"
    sigma_dir.mkdir()
    (sigma_dir / "cmd.yml").write_text(
        """
title: Generated Cmd Test
id: 036d9a52-7a13-11ec-a8a3-0242ac120002
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\cmd.exe'
    CommandLine|contains: whoami
  condition: selection
level: medium
""".lstrip(),
        encoding="utf-8",
    )

    class FakeCalderaTestProvider:
        def __init__(self):
            self.requests = []

        def generate(self, request, metadata):
            self.requests.append((request, metadata))
            return GeneratedCalderaTest(
                name="generated cmd test",
                executor="cmd",
                command="cmd.exe /c echo {{marker}} && whoami",
                rationale="Runs a harmless cmd command matching the Sigma selection.",
            )

    provider = FakeCalderaTestProvider()
    output_dir = tmp_path / "generated-active-tests"

    report = generate_active_tests_with_openai(
        ActiveTestGenerationRuntime(
            sigma_dir=sigma_dir,
            output_dir=output_dir,
            model="test-model",
            overwrite=True,
        ),
        provider=provider,
    )

    generated = load_active_tests(output_dir)
    assert report["status"] == "succeeded"
    assert report["generated"] == 1
    assert report["validated_manifests"] == 1
    assert generated[0].caldera.command == "cmd.exe /c echo {{marker}} && whoami"
    assert generated[0].expect.marker == "{{marker}}"
    assert generated[0].expect.rule_group == "sigma_generated_cmd_test"
    assert provider.requests[0][0]["expected_wazuh_group"] == "sigma_generated_cmd_test"


def test_openai_generator_rejects_manifest_without_marker(tmp_path):
    sigma_dir = tmp_path / "sigma"
    sigma_dir.mkdir()
    (sigma_dir / "cmd.yml").write_text(
        """
title: Missing Marker Test
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: whoami
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="marker"):
        GeneratedCalderaTest(
            name="bad",
            executor="cmd",
            command="cmd.exe /c whoami",
            rationale="Missing marker.",
        )


def test_openai_generator_retries_rate_limit_then_succeeds():
    class FakeResponse:
        output_parsed = GeneratedCalderaTest(
            name="retry success",
            executor="cmd",
            command="cmd.exe /c echo {{marker}}",
            rationale="Harmless retry test.",
        )

    class FakeResponses:
        def __init__(self):
            self.calls = 0

        def parse(self, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                raise openai.RateLimitError("slow down", response=_http_response(429), body=None)
            return FakeResponse()

    class FakeClient:
        def __init__(self):
            self.responses = FakeResponses()

    client = FakeClient()
    provider = OpenAICalderaTestProvider(client, max_retries=1, sleeper=lambda _seconds: None)

    generated = provider.generate(
        {"sigma": {"title": "Retry"}},
        {"model": "test-model", "timeout_seconds": 30, "max_output_tokens": 800},
    )

    assert generated.name == "retry success"
    assert client.responses.calls == 2


def test_openai_generator_reports_retryable_rate_limit_failure(tmp_path):
    sigma_dir = tmp_path / "sigma"
    sigma_dir.mkdir()
    (sigma_dir / "cmd.yml").write_text(
        """
title: Rate Limited Rule
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: whoami
  condition: selection
""".lstrip(),
        encoding="utf-8",
    )

    class RateLimitedProvider:
        def generate(self, request, metadata):
            raise OpenAIActiveTestRateLimitError("OpenAI active test generation was rate-limited")

    runtime = ActiveTestGenerationRuntime(
        sigma_dir=sigma_dir,
        output_dir=tmp_path / "generated",
        model="test-model",
        overwrite=True,
    )
    runtime.output_dir.mkdir()

    result = _generate_one(runtime, RateLimitedProvider(), _load_sigma_rules(sigma_dir)[0])

    assert result["status"] == "failed"
    assert result["error_type"] == "OpenAIActiveTestRateLimitError"
    assert result["retryable"] is True
    assert "quota" in result["hint"]


def _http_response(status: int) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        request=httpx.Request("POST", "https://api.openai.test/v1"),
    )


def load_active_tests_from_inline(tmp_path):
    from wazuh_sigma.active_testing.models import ActiveDetectionTest, CalderaAbilitySpec, ExpectedAlertSpec

    return [
        ActiveDetectionTest(
            name="inline",
            sigma_id=None,
            caldera=CalderaAbilitySpec(executor="cmd", platform="windows", command="cmd.exe /c echo {{marker}}"),
            expect=ExpectedAlertSpec(marker="{{marker}}"),
            path=tmp_path,
        )
    ]
