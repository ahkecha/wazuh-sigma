# Project structure

## Maintained paths

- `src/wazuh_sigma/converter/`: Sigma file loading, pySigma normalization, conversion reporting, and the conversion CLI. `service.py` owns conversion orchestration and `cli.py` owns `sigma-convert`.
- `src/wazuh_sigma/backend/`: backend-specific conversion boundaries, including the Wazuh XML backend.
- `src/wazuh_sigma/ruleset_chunks.py`: default generated-rules chunk writer. Conversion still writes the canonical XML file, then writes balanced chunk XML files and a manifest next to it for large Windows corpora.
- `src/wazuh_sigma/deploy/`: Wazuh API deployment package. `client.py` owns HTTP transport and API calls, `reports.py` owns machine-readable report helpers, and `wazuh_api.py` owns deployment safety flow, rollback, and the CLI-compatible public API.
- `src/wazuh_sigma/active_testing/`: autonomous dev-environment validation package. `models.py` loads safe test manifests, `caldera.py` owns Caldera `/api/v2` communication, `alerts.py` owns Wazuh indexer alert polling, and `runner.py` coordinates ability/adversary/operation execution plus alert verification. This package is opt-in and never runs in default CI.
- `src/wazuh_sigma/validator/`: Wazuh XML validation package. `rule_validator.py` owns the library orchestrator, `cli.py` owns `sigma-validate`, and focused modules own discovery, structure, pattern, reference, reporting, models, and catalog concerns.
- `src/wazuh_sigma/advisor/`: optional, non-authoritative OpenAI advisor (installed via the `advisor` extra). `models.py` owns the strict Pydantic contracts, `features.py` deterministic feature extraction, `sanitizer.py` redaction, `prompts.py` the versioned prompt contract, `policy.py` the authoritative decision engine, `cache.py` content-addressed caching, `service.py` orchestration, `telemetry.py` usage accounting, `errors.py` the typed exception hierarchy, `providers/` the provider protocol and OpenAI implementation, and `runtime.py` the config-to-service wiring plus report serialization. The deterministic core never imports this package; integration points import it lazily only when the advisor is enabled.
- `src/wazuh_sigma/incremental/`: optional conversion cache package. It owns rule identity, deterministic conversion fingerprints, cached Wazuh XML fragments, manifest persistence, stable Wazuh ID reuse, and deletion/tombstone accounting.
- `src/wazuh_sigma/windows/`: Windows event analysis and fixture generation package. `analysis.py` owns event parsing, grouping, and deduplication. `fixture_generation.py` owns fixture creation and field mapping documentation. `optimization.py` owns analysis reports on field mapping coverage and confidence. `cli.py` owns the `sigma-windows-analysis` command dispatch.
- `src/wazuh_sigma/config.py`, `src/wazuh_sigma/pipeline.py`, and `src/wazuh_sigma/pipeline_stages.py`: config loading, top-level pipeline CLI dispatch, and executable pipeline stages.
- `src/wazuh_sigma/naming.py`: the single canonical implementation of `sigma_{NAME}` naming.
- `examples/sigma/`: source detections used by the real end-to-end test and CI build.
- `docs/ARCHITECTURE.md`: end-to-end component map, trust model, runtime flow, generated artifacts, and Caldera active-test design.
- `docs/ADVISOR_ROADMAP.md`: future OpenAI advisor roadmap. It is intentionally documentation-only until implemented behind explicit opt-in configuration.
- `docs/CONVERSION_COVERAGE.md`: measured conversion coverage against the SigmaHQ Windows corpus, the fail-closed rejection rationale, and known fidelity gaps (unsupported modifiers, case sensitivity).
- `tests/test_real_pipeline.py`: production-path conversion contract.
- `tests/test_sigma_converter.py`: converter unit and edge-case coverage.
- `tests/test_active_testing.py`: Caldera client, active-test manifest, and Wazuh alert-query coverage using fake transports.
- `tests/unit/test_rule_validator_comprehensive.py`: validator coverage.
- `.github/workflows/ci.yml`: GitHub Actions install/test/smoke workflow.
- `ci/.gitlab-ci.yml`: GitLab CI equivalent; `.gitlab-ci.yml` is only its root include.

## Generated paths

`build/`, `output/`, reports, caches, coverage data, `*.egg-info`, and `graphify-out/` are generated artifacts and are not part of the runtime architecture.

## Dependency direction

The converter, backend, validator, deployer, active tester, advisor, and incremental cache are independent package submodules connected by `pipeline_stages.py`. Shared naming behavior lives at package root. Tests may import production modules; production modules never import tests, scripts, or examples. Active testing depends on generated/deployed rules and external dev services; conversion and validation do not depend on Caldera.
