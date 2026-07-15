# Architecture

This project is a deterministic Sigma-to-Wazuh delivery pipeline with an
optional autonomous validation loop against a dev Wazuh + Caldera environment.
The goal is not only to generate XML, but to prove that a generated rule can be
loaded by Wazuh and, when a safe stimulus exists, can fire on real telemetry.

## System overview

```text
Sigma YAML
  |
  v
pySigma parsing and normalization
  |
  v
Wazuh backend
  |-- field mapping
  |-- deterministic rule IDs
  |-- sigma_{NAME} groups
  |-- optional incremental conversion cache
  v
Generated Wazuh XML
  |
  +--> local XML validator
  |
  +--> optional native Wazuh parser validation
  |
  +--> Wazuh API deployer
           |
           +--> backup remote file
           +--> upload managed rule file
           +--> manager validation
           +--> optional restart
           +--> rule visibility verification
                    |
                    v
             optional active detection test
                    |
                    +--> Caldera creates ability/adversary/operation
                    +--> Windows agent executes safe command
                    +--> Wazuh receives event telemetry
                    +--> Wazuh indexer is queried for alert evidence
```

## Main boundaries

### Sigma parsing

Location: `src/wazuh_sigma/sigma.py` and `src/wazuh_sigma/converter/`

Sigma files stay valid Sigma YAML. Parsing and normalization are handled by
pySigma first. The converter records rejected or unsupported rules in the
conversion report instead of silently weakening detection logic.

### Wazuh backend

Location: `src/wazuh_sigma/backend/`

The backend is the boundary between normalized Sigma rules and Wazuh XML. It is
responsible for:

- deterministic Wazuh XML generation;
- `sigma_{NAME}` group naming;
- Wazuh rule ID allocation inside the owned range;
- versioned Sigma-field to Wazuh-field mapping;
- optional severity override boundaries used by policy-controlled advisor work.

It should not own CLI parsing, deployment, report writing, or Caldera execution.

### Incremental conversion

Location: `src/wazuh_sigma/incremental/`

Incremental conversion is opt-in. It keeps a manifest of rule identities and
allocated Wazuh IDs, computes deterministic fingerprints, and reuses cached XML
fragments for unchanged rules. The manifest is the source of truth for stable
rule IDs; generated cache artifacts are not source files.

### Validation

Location: `src/wazuh_sigma/validator/`

Validation checks generated Wazuh XML structure, IDs, required fields, groups,
decoders, regex patterns, and strict/warning policy. Validation is local and
does not require a running Wazuh manager.

Native Wazuh parser validation is separate and optional. The Docker smoke path
uses a standalone Wazuh manager and `wazuh-analysisd -t`.

### Wazuh API deployment

Location: `src/wazuh_sigma/deploy/`

Deployment manages one dedicated remote rule file, for example
`sigma_rules.xml`. It never edits arbitrary remote paths and does not merge with
hand-written `local_rules.xml`.

The safe deployment sequence is:

1. Validate the local generated XML.
2. Authenticate to the Wazuh manager API.
3. Optionally back up the current remote managed file.
4. Upload the generated XML as the managed remote file.
5. Ask Wazuh to validate manager configuration.
6. Optionally restart the manager.
7. Verify the uploaded file exposes loaded rules.
8. Roll back from the backup when requested and a later stage fails.

### Caldera-backed active detection testing

Location: `src/wazuh_sigma/active_testing/`

Active testing is the dev-environment proof layer. It is intentionally outside
normal CI because it creates Caldera objects and executes commands on a
connected agent.

The active-test stage does the following:

1. Optionally generates active test manifests from Sigma rules with OpenAI into
   `active_test.generated_test_dir`.
2. Loads active test manifests from `active_test.test_dir` or the generated
   directory selected by the CLI.
3. Authenticates to Caldera with a configured header and environment-provided
   secret.
4. Selects a live Windows Caldera agent, optionally constrained by group.
5. Creates a temporary Caldera ability for the manifest command.
6. Creates a temporary adversary containing that ability.
7. Starts an autonomous operation against the selected agent group.
8. Waits for operation links to finish.
9. Queries the Wazuh indexer for expected alert evidence.
10. Writes `build/active-test-report.json`.

Active tests can be hand-written or generated. The OpenAI generator is a bounded
proposal layer: it receives a compact Sigma summary and returns one strict
Windows Caldera command schema. Generated commands must include `{{marker}}` and
pass a local safety denylist before they are written. It cannot change Wazuh XML,
rule IDs, deployment settings, or pass/fail results.

Example manifest:

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

At runtime `{{marker}}` is replaced with a unique value. The Wazuh alert query
requires that marker plus any configured `rule.id`, `rule.groups`, or custom
query evidence.

## Configuration ownership

`pipeline.yml` owns environment-specific paths and defaults:

- `sigma_dir`: source Sigma directory;
- `output_file`: generated Wazuh XML artifact;
- `wazuh`: manager API, rule ID range, field mapping, parent-rule anchors,
  remote file, backup path;
- `incremental_cache`: optional conversion cache and manifest;
- `advisor`: optional OpenAI advisor settings;
- `active_test`: Caldera and Wazuh indexer active validation settings.

Secrets do not belong in `pipeline.yml`. They come from environment variables:

- `WAZUH_USER` / `WAZUH_PASSWORD` for Wazuh manager deployment;
- `CALDERA_API_KEY` for Caldera active testing;
- `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` for alert verification;
- `OPENAI_API_KEY` for optional advisor work and generated active-test manifests.

## CLI entry points

Installed commands:

- `sigma-convert`: convert Sigma YAML to Wazuh XML;
- `sigma-validate`: validate generated Wazuh XML;
- `sigma-deploy-wazuh`: deploy one managed rule file through the Wazuh API;
- `sigma-pipeline`: config-driven orchestration.

Primary `sigma-pipeline` stages:

- `doctor`: readiness report;
- `convert`: Sigma to Wazuh XML;
- `validate`: generated XML validation;
- `smoke`: convert plus validate, optionally with Docker/Wazuh parser smoke;
- `deploy`: safe Wazuh API deployment;
- `active-test`: optional Caldera execution plus Wazuh alert verification;
- `advise`: optional non-authoritative OpenAI advisor run.

## Trust model

- pySigma and deterministic backend code are authoritative for conversion.
- The optional OpenAI advisor is advisory only and cannot bypass validation.
- Incremental cache cannot bypass final XML validation.
- Wazuh manager validation is required before trusting a deployment.
- Active detection tests trust Caldera only as a stimulus runner; pass/fail is
  based on Wazuh alert evidence.
- Reports are machine-readable and designed for later automation.

## Generated artifacts

Typical generated files:

```text
build/sigmahq/sigma_rules.xml       generated managed Wazuh rules
build/conversion-report.json        conversion report
build/sigma-smoke-report.json       conversion/validation smoke report
build/deploy-report.json            Wazuh API deployment report
build/active-test-report.json       Caldera/Wazuh active validation report
build/conversion-cache/             optional incremental conversion cache
build/advisor-cache/                optional OpenAI advisor cache
backups/wazuh/                      optional remote Wazuh rule backups
```
