# Operations runbook

For a system-level explanation of how conversion, deployment, Caldera active
testing, and alert verification fit together, read
[ARCHITECTURE.md](ARCHITECTURE.md) first.

## Add a Sigma rule

1. Add a standard Sigma `.yml` or `.yaml` file below the configured `sigma_dir`.
   The checked-in development config uses `examples/sigma` so a clean clone can run
   immediately. For your managed rule repository, set `sigma_dir: rules/sigma` in
   `pipeline.yml` and add rules there.
2. Keep tags in normal dotted Sigma form, for example `attack.t1059`.
3. Include a Sigma detection `condition`.
4. Regenerate and validate the managed Wazuh XML:

```bash
sigma-pipeline convert --config pipeline.yml
sigma-pipeline validate --config pipeline.yml
```

Or run both stages as a single smoke gate:

```bash
sigma-pipeline smoke --config pipeline.yml
```

## Test locally

Fast smoke test without Docker:

```bash
sigma-pipeline smoke --config pipeline.yml
```

Native Wazuh parser smoke test with the standalone Docker manager:

```bash
sigma-pipeline smoke --config pipeline.yml --docker
```

The Docker smoke test recreates the standalone manager, copies generated XML into
`/var/ossec/etc/rules`, and runs:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

## Deploy to dev Wazuh

Set credentials outside the shell history:

```bash
export WAZUH_USER='...'
export WAZUH_PASSWORD='...'
```

Check local and deploy readiness first:

```bash
sigma-pipeline doctor --config pipeline.yml --require-deploy --report build/doctor-report.json
```

Then deploy with safety controls:

```bash
sigma-pipeline deploy \
  --config pipeline.yml \
  --preflight-smoke \
  --backup-remote \
  --rollback-on-failure \
  --restart
```

`--preflight-smoke` regenerates the managed XML from the configured Sigma source
and validates it before Wazuh authentication. Deployment also validates the local
generated XML immediately before authenticating to Wazuh. If either local gate
fails, no upload, restart, or remote mutation is attempted.
`--dry-run` and `--validate-only` are mutually exclusive modes, and
`--rollback-on-failure` requires `--backup-remote` so rollback is never requested
without a saved restore point.
When `--restart` is used, deployment also requires the uploaded file to expose at
least one loaded rule through the Wazuh rules API. A zero-rule verification result
fails the deployment and triggers rollback when rollback was enabled.

For self-signed dev certificates, set `wazuh.insecure: true` in `pipeline.yml`.

## Run the real Wazuh API integration smoke

The integration profile is skipped unless credentials are present. It uploads a
dedicated smoke rules file, validates manager configuration, and verifies the
remote file through the Wazuh rules API:

```bash
export WAZUH_HOST='https://wazuh.example.invalid'
export WAZUH_USER='...'
export WAZUH_PASSWORD='...'
export WAZUH_INSECURE='true'              # optional for self-signed dev APIs
export WAZUH_TIMEOUT='30'                 # optional, seconds
export WAZUH_CA_BUNDLE='/path/to/ca.pem'  # optional, preferred over insecure
export WAZUH_REMOTE_FILE='sigma_integration_smoke.xml'
export WAZUH_RESTART='false'              # set true only when restart is allowed

pytest -m integration tests/test_wazuh_deploy.py
```

When `WAZUH_RESTART=true`, the smoke test also asserts that Wazuh reports at
least one loaded rule for the uploaded file after restart.

## Run autonomous Caldera-backed detection tests

Use this when you want to prove a generated rule actually fires in the dev
environment. This is intentionally separate from normal CI because it mutates a
dev Caldera server and executes commands on a connected Windows agent.

One manifest is required per rule or rule family. A Sigma rule describes what to
detect; the active-test manifest describes the safe action that should produce
matching telemetry.

Configure `active_test:` in `pipeline.yml`:

```yaml
active_test:
  test_dir: tests/active
  generated_test_dir: build/active-tests
  report: build/active-test-report.json
  generate_with_openai: false
  openai_model:
  openai_api_key_env: OPENAI_API_KEY
  openai_max_retries: 3
  caldera_url: http://127.0.0.1:8888
  caldera_api_key_env: CALDERA_API_KEY
  caldera_auth_header: KEY
  agent_platform: windows
  agent_group: dev-windows
  alert_indexer_url: https://indexer.example.invalid:9200
  alert_index: wazuh-alerts-*
  alert_username_env: WAZUH_INDEXER_USER
  alert_password_env: WAZUH_INDEXER_PASSWORD
  insecure: true
```

Store secrets in the environment:

```bash
export CALDERA_API_KEY='...'
export WAZUH_INDEXER_USER='...'
export WAZUH_INDEXER_PASSWORD='...'
export WAZUH_USER='...'       # only needed with --deploy
export WAZUH_PASSWORD='...'   # only needed with --deploy
export OPENAI_API_KEY='...'   # only needed for generated active tests
```

Add one manifest per rule or rule family under `tests/active`:

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

Run the full dev gate:

```bash
sigma-pipeline active-test \
  --config pipeline.yml \
  --preflight-smoke \
  --deploy \
  --backup-remote \
  --rollback-on-failure \
  --restart
```

The pipeline creates a unique marker per test, creates a temporary Caldera
ability/adversary/operation with the documented `/api/v2` endpoints, waits for
operation links to complete, and polls the Wazuh indexer for the expected
marker plus optional `rule.id` / `rule.groups` evidence. Results are written to
`build/active-test-report.json`.

To generate the active-test manifests with OpenAI before the dev gate:

```bash
sigma-pipeline generate-active-tests \
  --config pipeline.yml \
  --openai-model <model> \
  --overwrite
```

Review the generated YAML under `build/active-tests`, then run it:

```bash
sigma-pipeline active-test \
  --config pipeline.yml \
  --generate-tests \
  --openai-model <model>
```

Generated tests are still fail-closed: the command must include `{{marker}}`,
must pass the local safety policy, and must parse through the normal active-test
manifest loader before Caldera is contacted.

If OpenAI returns rate limits or transient API failures, the generator retries
with bounded backoff. Persistent failures are reported per rule with
`error_type`, `retryable`, and `hint` so you can distinguish quota issues from
schema/safety failures.

## Roll back

When `--backup-remote` is enabled, backups are written below:

```text
backups/wazuh/
```

If `--rollback-on-failure` is set, the deployer re-uploads the backup when upload,
validation, restart, or verification fails.
When rollback is requested, failure to create the remote backup stops deployment
before upload so the managed file is never replaced without a rollback point.
Without `--rollback-on-failure`, backup failures are reported but deployment may
continue because the backup is advisory.
When deployment fails after a report has been initialized, `build/deploy-report.json`
is still written and includes fields such as `uploaded`, `rolled_back`, `error`, and
`rollback_error` when rollback itself fails.
Every report also records the requested safety plan with `dry_run`,
`validate_only`, `backup_remote`, `rollback_on_failure`, and
`restart_requested`.
Validate-only manager validation failures use the same report contract with
`failed_stage: manager_validation`, so automation can detect parser/config errors
before any upload occurs.
The `status` field is the automation-friendly deployment outcome:
`dry_run`, `validate_only`, `succeeded`, or `failed`.

Manual rollback is also possible:

```bash
sigma-deploy-wazuh \
  --host "$WAZUH_HOST" \
  --username "$WAZUH_USER" \
  --password "$WAZUH_PASSWORD" \
  --file backups/wazuh/sigma_rules-YYYYMMDDTHHMMSSZ.xml \
  --remote-file sigma_rules.xml \
  --restart
```

## Debug Wazuh parser errors

Open the smoke report:

```text
build/sigma-smoke-report.json
```

The Docker section includes the exact `wazuh-analysisd -t` stderr. Typical causes:

- XML declaration in a custom rule file.
- Unsupported Wazuh rule child elements.
- Invalid field `type`.
- Unescaped Windows paths or regex metacharacters.
- Static Wazuh fields emitted as dynamic `<field name="...">` elements.

## Generated files

```text
build/sigmahq/sigma_rules.xml       generated Wazuh rule file
build/sigmahq/chunks/               default balanced XML chunks plus manifest.json
build/conversion-report.json        conversion report
build/sigma-smoke-report.json       smoke/native parser report
build/deploy-report.json            deployment report, including local_validation
backups/wazuh/                      remote rule backups
```

## Rule ID ownership

The default owned range is:

```text
900000-949999
```

Configure it in `pipeline.yml`:

```yaml
wazuh:
  rule_id_start: 900000
  rule_id_end: 949999
```

Generation fails if the backend exhausts the owned range.
