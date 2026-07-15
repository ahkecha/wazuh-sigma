# Architecture review

Date: 2026-07-13

Perspective: external maintainer joining the project before a public v1.0 release.

## Verdict

The architecture is directionally strong. The project now has recognizable production boundaries:

- Sigma loading and pySigma normalization are isolated in `converter` / `sigma`.
- Wazuh XML generation is isolated in `backend`.
- Field mapping is isolated in `fields`.
- Wazuh decoded-event evidence is isolated in `fixtures`.
- Validation is isolated in `validator`.
- Deployment is isolated in `deploy`.
- Caldera active testing is isolated in `active_testing`.
- OpenAI advisor behavior is isolated and opt-in under `advisor`.
- Incremental cache is isolated under `incremental`.
- `pipeline_stages.py` composes the packages.

The main weakness is that several packages are cohesive at the package level but still have large orchestration modules internally.

## Dependency flow

Current dependency flow is mostly one-directional:

```text
CLI / pipeline
  -> config
  -> converter
      -> sigma
      -> backend
          -> fields
          -> naming
      -> incremental
      -> advisor (lazy, optional)
  -> validator
  -> deploy
  -> active_testing
```

Good:

- The deterministic conversion path does not import Caldera.
- The deterministic conversion path does not import OpenAI unless advisor is explicitly enabled.
- The backend does not deploy, call APIs, or run active tests.
- The field registry is not hidden in CLI code.

Needs tightening:

- `scripts/normalize_wazuh_rules.py` behaves like production logic but lives outside the package.
- `pipeline.py` knows too much about every command.
- Deployment safety phases are in one large function.

## Package cohesion

### `wazuh_sigma.converter`

Purpose is clear: load Sigma, normalize with pySigma, orchestrate backend conversion, and write conversion reports.

Status: Good.

Recommended improvement: keep only `service.py`, `cli.py`, and presentation helpers. The obsolete compatibility facade has been removed.

### `wazuh_sigma.backend`

Purpose is clear: own the Sigma-normalized-rule to Wazuh XML boundary.

Status: Good boundary, medium internal complexity.

Concern: `wazuh.py` still contains configuration, ID generation, field mapper glue, XML rendering, detection traversal, parent rules, and backend wrapper.

Recommended split:

- `ids.py`
- `parents.py`
- `field_mapper.py`
- `xml_emitter.py`
- `detection_renderer.py`
- `backend.py`

Do this incrementally and preserve behavior.

### `wazuh_sigma.fields`

Purpose is clear: typed/context-aware field mapping.

Status: Good architecture.

Concern: `FieldMappingRegistry.resolve` mixes lookup, resolution modes, and diagnostics.

Recommendation: separate resolution policy from mapping lookup.

### `wazuh_sigma.fixtures`

Purpose is clear: decoded Wazuh fixture loading and verification.

Status: Good package introduction.

Concern: verifier functions are long and duplicate result construction.

Recommendation: extract result factories and keep exact-path verification as the primary API.

### `wazuh_sigma.validator`

Purpose is clear: local Wazuh XML validation.

Status: Good package, medium internal complexity.

Concern: `WazuhRuleValidator` remains a broad orchestrator.

Recommendation: move to pass-based validation internally.

### `wazuh_sigma.deploy`

Purpose is clear: Wazuh API deployment with safety controls.

Status: Production direction is good.

Concern: `deploy_rules` is too broad and has a long argument list.

Recommendation: introduce `DeploymentOptions` and phase-specific private functions.

### `wazuh_sigma.active_testing`

Purpose is clear: optional dev-environment validation with Caldera and Wazuh alert evidence.

Status: Good trust boundary.

Concern: OpenAI-generated active tests must remain advisory. This is documented and should stay enforced.

### `wazuh_sigma.advisor`

Purpose is clear: optional non-authoritative OpenAI advisor.

Status: Good safety model.

Concern: policy and service functions have long parameter surfaces.

Recommendation: use typed request objects.

### `wazuh_sigma.incremental`

Purpose is clear: stable IDs and cache reuse.

Status: Good feature boundary.

Concern: `process_rule` owns too many substeps.

Recommendation: split identity, fingerprint, allocation, cache lookup, and cache write phases.

## Over-engineering

Potentially over-engineered areas:

- Advisor package is very complete compared with current default-disabled usage.
- Fixture provenance model is stricter than the current small fixture corpus can fully exploit.
- Legacy/warn/strict mapping modes increase surface area. Strict mode should remain the only production default.

These are acceptable if kept isolated and documented as optional.

## Under-engineering

Under-engineered areas:

- No package-owned normalizer module despite tested normalizer behavior.
- Deployment options are not typed as one object.
- Pipeline CLI dispatch has not been decomposed.
- No explicit public API policy defining which classes are supported for external import.

## Boundary leaks

- `scripts/normalize_wazuh_rules.py` is imported by tests, so script code is acting as library code.
- Backend classes are imported heavily by tests. This is fine internally, but public API expectations should be documented.
- Field mapping has legacy fallback paths in backend and registry; this should be clearly marked non-production.

## API clarity

Obvious APIs:

- `sigma-pipeline smoke`
- `sigma-pipeline deploy`
- `sigma-convert`
- `sigma-validate`
- `sigma-deploy-wazuh`
- `SigmaToWazuhConverter`
- `WazuhBackend`
- `FieldMappingRegistry`

Less obvious APIs:

- `deploy_rules` due to long argument list.
- `evaluate_policy` due to long policy parameter list.
- `IncrementalConverterService` constructor due to many options.

## Architecture recommendations

Before v1.0:

1. Move normalizer logic into `src/wazuh_sigma`.
2. Split deployment into typed plan + phases.
3. Split `pipeline.py` command dispatch.
4. Define a public API policy in docs.

Before public release:

1. Split backend internals.
2. Split validator orchestrator into validation passes.
3. Rename/gate legacy field mapping mode.
4. Add docs for supported corpus vs. intentionally rejected corpus.

Before enterprise adoption:

1. Add native Wazuh validation in isolated CI/manual workflow.
2. Add authenticated dev-environment integration tests for Wazuh and Caldera.
3. Add release artifacts and versioned compatibility matrix.
