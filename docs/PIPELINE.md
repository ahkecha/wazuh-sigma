# Pipeline

For the complete component architecture and trust model, see
[ARCHITECTURE.md](ARCHITECTURE.md). This page focuses on executable stages and
operational gates.

The primary GitHub-hosted pipeline is `.github/workflows/ci.yml`. It runs on pushes
to `main` and pull requests across Python 3.10, 3.11, and 3.12. The root
`.gitlab-ci.yml` also includes `ci/.gitlab-ci.yml` for GitLab-compatible runners.

The CI gates are:

1. Install the editable package with test dependencies.
2. Byte-compile source and tests.
3. Run the maintained pytest suite configured in `pyproject.toml`.
4. Convert every YAML file below `examples/sigma`, write one Wazuh XML ruleset,
   and validate it through `sigma-pipeline smoke --config ci/pipeline.yml`.

Generated rule artifacts are retained where the CI provider supports artifacts so conversion
reports can be inspected after failures.
Conversion report timestamps and generated XML conversion comments are emitted
as timezone-aware UTC ISO-8601 values.
Smoke reports are self-describing JSON artifacts: each report records the Sigma
input directory, generated XML path, report paths, strict validation policy,
Docker smoke selection, owned Wazuh rule ID range, field mapping version, and
remote Wazuh filename that were tested.

## Local equivalent

```bash
python -m pip install -e ".[test]"
python -m compileall -q src tests
python -m pytest
python -m wazuh_sigma.converter.cli -d examples/sigma -o build/sigmahq/sigma_rules.xml -r build/conversion-report.json
python -m wazuh_sigma.validator.cli -r build/sigmahq/sigma_rules.xml -o json
```

Equivalent installed commands:

```bash
sigma-pipeline doctor --config pipeline.yml
sigma-pipeline convert --config pipeline.yml
sigma-pipeline validate --config pipeline.yml
sigma-pipeline smoke --config pipeline.yml
sigma-pipeline active-test --config pipeline.yml --preflight-smoke --deploy --restart
sigma-convert -d rules/sigma -o build/sigmahq/sigma_rules.xml
sigma-validate --rules build/sigmahq/sigma_rules.xml
sigma-validate --rules build/sigmahq/chunks
sigma-deploy-wazuh \
  --host https://wazuh.example.invalid \
  --username "$WAZUH_USER" \
  --password "$WAZUH_PASSWORD" \
  --file build/sigmahq/sigma_rules.xml \
  --remote-file sigma_rules.xml \
  --restart
```

`sigma-pipeline` accepts `--config` before or after the subcommand, so both
`sigma-pipeline --config pipeline.yml smoke` and `sigma-pipeline smoke --config pipeline.yml`
are valid. Use `convert` and `validate` as independent gates when debugging a failure, and
`smoke` when you want a single command that regenerates and validates the artifact.

Conversion writes both the canonical `output_file` and balanced XML chunks under
`<output_file parent>/chunks/` by default. The full file remains useful for
single-file deployment flows; the chunk files are the default review/native
parser artifact for large Windows corpora.

`active-test` is the opt-in dev-environment gate for autonomous detection
validation. It assumes Wazuh rules can be deployed to a dev manager, a Windows
Caldera agent is connected, and Wazuh alerts are searchable from the Wazuh
indexer. It does not run in normal CI by default, and it requires explicit
stimulus manifests because the pipeline cannot safely infer how to trigger every
Sigma rule by itself.

An optional, non-authoritative advisory stage may run between deterministic
validation and Wazuh XML generation when explicitly enabled (`advise`,
`--advisor`, or `advisor.enabled: true`). It defaults to report-only mode and
never changes generated XML or bypasses any downstream validation gate. See
[ADVISOR.md](ADVISOR.md).
Use `doctor` before smoke/deploy when you want a JSON readiness report. It checks
configured paths, Sigma rule discovery, deploy credential presence, Wazuh host
placeholder usage, CA bundle presence, and backup path readiness. Add
`--require-deploy` when missing deploy credentials or an example Wazuh host should
fail the command instead of producing warnings.
Set `strict_validation: true` in `pipeline.yml` to make validation warnings fail
`validate` and `smoke`. Use `--strict` or `--no-strict` when a single run needs
to override the configured policy.
For deployment, `pipeline.yml` owns the Wazuh API defaults:

```yaml
wazuh:
  host: https://wazuh.example.invalid
  insecure: false
  timeout: 30
  ca_bundle: /path/to/ca.pem
  field_mapping_version: wazuh-windows-eventdata-v1
  parent_rules:
    product:
      windows: 60000
    service:
      security: 60001
      system: 60002
      application: 60003
      sysmon: 60004
      windefend: 60005
      windows-defender: 60005
      powershell: 60000
      wmi: 60018
    default: 60000
  remote_file: sigma_rules.xml
```

The deploy subcommand still accepts `--timeout` and `--ca-bundle` for one-off
overrides, while credentials should come from `--username`/`--password` or
`WAZUH_USER`/`WAZUH_PASSWORD`.
Use `sigma-pipeline deploy --preflight-smoke` when deployment should prove the
configured Sigma source still converts and validates before any Wazuh API
mutation. The preflight smoke gate runs without Docker and fails before
authentication, upload, restart, or rollback work begins.
Deployment modes are intentionally fail-closed: `--dry-run` cannot be combined
with `--validate-only`, `--restart` cannot be combined with `--no-restart`, and
`--rollback-on-failure` requires `--backup-remote`.

`pipeline.yml` is fail-closed: unknown top-level keys and unknown `wazuh:` keys
raise a configuration error so misspelled options do not silently change nothing.
When `pipeline.yml` is loaded from disk, relative paths such as `sigma_dir`,
`output_file`, reports, `wazuh.ca_bundle`, and `wazuh.backup_dir` are resolved
relative to the config file's directory. This keeps CI and local runs stable even
when shared config lives outside the repository root.

Field mapping is an explicit backend contract. The default mapping targets common
Windows event data fields, and production deployments can version additive
overrides in `pipeline.yml`:

```yaml
wazuh:
  field_mapping_version: corp-windows-eventdata-v2
  field_mapping:
    Image: win.eventdata.image
    CommandLine: win.eventdata.commandLine
    User: win.eventdata.user
    DestinationIp: win.eventdata.destinationIp
```

Custom mappings are merged over the defaults, validated at startup, and the selected
`field_mapping_version` is written to the conversion report so deployments can be
audited after the fact.

Parent rules are also an explicit backend contract. Generated Sigma rules include
an `<if_sid>` anchor resolved from Sigma `logsource.product`, `logsource.service`,
or `logsource.category`. The checked-in defaults target Wazuh 4.x Windows
EventChannel base rules:

- `60000`: decoded Windows EventChannel events;
- `60001`: Security channel;
- `60002`: System channel;
- `60003`: Application channel;
- `60004`: Sysmon channel;
- `60005`: Windows Defender channel;
- `60018`: WMI Activity provider.

Override `wazuh.parent_rules` when the target Wazuh manager has a different
ruleset version or custom base rules. The selected parent-rule map is written to
the conversion and smoke reports.

Incremental conversion caching is available through `pipeline.yml`:

```yaml
incremental_cache:
  enabled: true
  directory: build/conversion-cache
  manifest: build/conversion-cache/manifest.json
```

When enabled, `sigma-pipeline convert` reuses cached Wazuh XML for unchanged rules,
preserves previously allocated Wazuh IDs, and writes per-rule `conversion_cache`
metadata plus aggregate `incremental_conversion` counters to the conversion report.

Autonomous active detection testing is configured separately:

```yaml
active_test:
  test_dir: tests/active
  generated_test_dir: build/active-tests
  report: build/active-test-report.json
  generate_with_openai: false
  openai_model:                # required only for generated manifests
  openai_api_key_env: OPENAI_API_KEY
  openai_timeout_seconds: 30
  openai_max_output_tokens: 800
  openai_max_retries: 3
  caldera_url: http://127.0.0.1:8888
  caldera_api_key_env: CALDERA_API_KEY
  caldera_auth_header: KEY
  agent_platform: windows
  agent_group: dev-windows          # optional; auto-selects a live Windows agent when empty
  alert_indexer_url: https://indexer.example.invalid:9200
  alert_index: wazuh-alerts-*
  alert_username_env: WAZUH_INDEXER_USER
  alert_password_env: WAZUH_INDEXER_PASSWORD
  insecure: true                    # dev/self-signed only
```

Active test manifests live under `active_test.test_dir`. Each manifest maps one
rule to a safe Caldera command and the required Wazuh evidence:

```yaml
name: command shell detection
sigma_id: 036d9a52-7a13-11ec-a8a3-0242ac120002
caldera:
  executor: cmd
  platform: windows
  command: cmd.exe /c echo {{marker}} && whoami
  timeout: 30
expect:
  rule_group: sigma_windows_command_line_execution_via_cmd_exe
  marker: "{{marker}}"
```

At runtime the pipeline generates a unique marker, creates a temporary Caldera
ability/adversary/operation through the documented `/api/v2` endpoints, waits
for the operation links to finish, then polls the Wazuh indexer for the expected
marker plus optional `rule.id` / `rule.groups` evidence. This keeps active
tests deterministic and autonomous, but still requires one safe stimulus
manifest per rule family.

When you want OpenAI to draft the Caldera stimulus manifests, generate them into
`active_test.generated_test_dir` first:

```bash
export OPENAI_API_KEY='...'
sigma-pipeline generate-active-tests --config pipeline.yml --openai-model <model> --overwrite
```

Or generate and immediately run them against the dev Caldera/Wazuh environment:

```bash
sigma-pipeline active-test --config pipeline.yml --generate-tests --openai-model <model>
```

The generated manifest contract is intentionally narrow: OpenAI returns a
strict schema for one Windows Caldera command, the command must include
`{{marker}}`, and a safety policy rejects obvious download, persistence,
registry, deletion, and security-disabling commands. The pipeline still validates
the generated YAML with the normal active-test manifest loader before Caldera
can execute it.

OpenAI rate limits, timeouts, and transient API failures are retried with bounded
backoff up to `active_test.openai_max_retries`. If generation still fails, the
per-rule result includes `error_type`, `retryable`, and a human-readable `hint`.

The Wazuh backend preserves common Sigma string modifiers in generated pcre2
patterns: `contains`, `startswith`, `endswith`, and raw `re` are translated into
the emitted field pattern while the Wazuh field name stays mapped and versioned.
Unsupported string modifiers, including `all`, fail conversion so rules do not
deploy with silently weakened matching semantics.

For measured conversion coverage against the SigmaHQ Windows corpus, the
rationale for these rejections, and known fidelity gaps (including case
sensitivity), see [CONVERSION_COVERAGE.md](CONVERSION_COVERAGE.md).

The backend also exposes a provider-agnostic `level_override` boundary for future
policy-controlled severity decisions. The override is optional, must be an
integer from 0 to 15, and is not used by the default deterministic conversion
path.

For a local Docker smoke test against the standalone Wazuh manager:

```bash
sigma-pipeline smoke --config pipeline.yml --docker
```

## Adding rules

Place `.yml` or `.yaml` files anywhere below the input directory. Directory conversion is recursive and deterministic. A rule must have `title`, `logsource`, and `detection` with a standard Sigma `condition`. Source tags should stay in normal dotted Sigma form, such as `attack.t1059`; `sigma_{NAME}` Wazuh groups are derived during conversion. Conversion failures produce a non-zero exit code and are listed in the JSON report.

## Wazuh API deployment contract

`sigma-deploy-wazuh` performs the deployment sequence against the Wazuh API:

1. Validate the local generated XML with the project Wazuh rule validator.
2. Authenticate with `POST /security/user/authenticate`.
3. Upload the generated XML with `PUT /rules/files/{remote-file}?overwrite=true`.
4. Validate manager configuration with `GET /manager/configuration/validation`.
5. Restart the manager with `PUT /manager/restart` when `--restart` is set.
6. Verify the file is queryable through `GET /rules?filename={remote-file}`.

The command manages only the dedicated file passed in `--remote-file`; it does not edit
`local_rules.xml` or merge with hand-written rules.
The remote file must be a single `.xml` filename such as `sigma_rules.xml`, not a
path. The Wazuh host must be an `http://` or `https://` API URL.
If a deployment fails after upload begins, the deployer preserves the partial
machine-readable report so rollback status and the failing stage are inspectable.

For operations details, see [RUNBOOK.md](RUNBOOK.md).
