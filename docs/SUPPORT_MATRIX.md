# Support matrix

This project is not production-ready until the native validation and detection-correctness gates in `docs/CONVERSION_COVERAGE.md` pass.

## Tested components

| Component | Current state |
| --- | --- |
| Python | CI targets 3.10, 3.11, 3.12 |
| Wazuh manager | Development environment observed on Wazuh 4.14.x |
| Wazuh rule API | Direct API deployment tested against a synthetic lab endpoint |
| Sigma source | In-repository SigmaHQ clone under `sigma/rules/windows` |
| Rule ID range | `900000`-`949999` |
| Default output | Full XML plus balanced chunk files |
| Chunk files | `sigma_rules_001.xml` ... `sigma_rules_004.xml` for current corpus |

## Supported conversion scope

Current support is limited to Sigma constructs that the backend can represent faithfully in Wazuh XML.

Supported today:

- pySigma parsing and normalization;
- Wazuh XML generation with deterministic rule IDs;
- balanced chunk generation;
- fail-closed unsupported field rejection;
- fail-closed unsupported modifier rejection;
- Event ID-specific parent SID overrides, including Security 4720 -> Wazuh `60109`;
- duplicate generated ID checks;
- remote Wazuh rule ID collision checks before normal deploy flows.

Not yet production-proven:

- native `wazuh-analysisd -t` acceptance for every generated chunk;
- `wazuh-logtest` or equivalent event-to-generated-rule assertions;
- negative event tests for overmatching;
- provider + channel + Event ID parent SID catalogue beyond targeted known fixes;
- complete fixture provenance for every verified mapping;
- restored/justified handling of the removed Windows mappings.

## Unsupported or partially supported Sigma semantics

These constructs require explicit backend support or explicit rejection:

- `all`;
- `windash`;
- `cidr`;
- `base64offset`;
- `wide`;
- `exists`;
- field references;
- nested conditions;
- `1 of` / `all of`;
- filters and negation.

The backend may support common string matching forms, but production correctness still requires event-to-rule tests because Wazuh PCRE behavior and decoder output determine operational behavior.

## Required production gates

Before production:

1. Run full Windows corpus conversion and compare to baseline.
2. Reconcile all removed mappings with fixture and Sigma usage evidence.
3. Run native Wazuh parser validation with `wazuh-analysisd -t`.
4. Run event-to-rule and negative tests with `wazuh-logtest` or equivalent.
5. Verify deployed rules load after manager restart.
6. Verify alert-index evidence for active tests.
7. Enforce these gates in CI or an equivalent release workflow.

## Current readiness

| Area | State |
| --- | --- |
| Architecture | Strong |
| Converter implementation | Functional |
| Mapping evidence | Incomplete; removed mappings require reconciliation |
| Full-corpus regression | Current evidence generated; below baseline |
| Native Wazuh parsing | Not proven |
| Detection correctness | Not proven |
| Deployment safety | Improved, but restart/validation permissions are required |
| CI evidence | Improved with corpus evidence generation |
| Production ready | No |
