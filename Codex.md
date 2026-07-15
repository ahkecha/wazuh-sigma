# Codex — Engineering Rules for Wazuh Sigma Pipeline

This document defines mandatory engineering standards for contributors and coding agents working on this repository.

The project converts untrusted Sigma YAML detections into Wazuh XML rules, validates the generated output, and may deploy managed rule files to Wazuh. Correctness, determinism, traceability, and safe failure behavior take priority over implementation speed.

The words **MUST**, **MUST NOT**, **SHOULD**, and **SHOULD NOT** are normative.

---

## 1. Core engineering principles

All changes MUST preserve these principles:

1. **Deterministic core**  
   Parsing, normalization, field mapping, rule-ID assignment, XML generation, validation, and deployment decisions must remain deterministic.

2. **Clear boundaries**  
   Parsing, semantic enrichment, policy, backend generation, validation, reporting, and deployment must be separate concerns.

3. **Fail safely**  
   Invalid inputs, unavailable optional services, malformed model responses, deployment failures, and parser errors must not produce partially trusted artifacts.

4. **No hidden behavior**  
   Network calls, filesystem writes, environment-variable use, retries, fallbacks, and mutations must be explicit and testable.

5. **Untrusted input by default**  
   Sigma YAML, generated reports, model output, API responses, and remote Wazuh state must all be treated as untrusted until validated.

6. **Evidence before claims**  
   A rule is not production-compatible because Python tests pass. Native `wazuh-analysisd -t` validation remains the final rule-load gate.

7. **Backward compatibility unless intentionally broken**  
   Public CLI behavior, config keys, report fields, and generated XML semantics must not change silently.

8. **Small, reviewable changes**  
   Avoid broad rewrites that mix refactoring, behavior changes, formatting, and new features in one patch.

---

## 2. Architectural boundaries

The intended architecture is:

```text
Sigma source
  -> parser / pySigma normalization
  -> domain model
  -> deterministic validation
  -> optional advisor enrichment
  -> deterministic policy
  -> Wazuh backend
  -> XML validation
  -> native Wazuh validation
  -> deployment
```

### Parser and normalization layer

Responsibilities:

- load source files
- parse YAML safely
- normalize through pySigma
- preserve source location and parser metadata
- reject malformed Sigma

Must not:

- generate XML
- call deployment APIs
- assign rule IDs
- invoke an LLM
- silently coerce invalid structures

### Domain model

Responsibilities:

- expose normalized Sigma concepts
- provide typed access to title, level, tags, log source, and detection
- enforce domain invariants

Must not:

- perform filesystem writes
- perform network calls
- depend on CLI parsing
- contain Wazuh API logic

### Advisor layer

Responsibilities:

- extract deterministic features
- call an optional local model
- validate structured model output
- return a typed recommendation

Must not:

- generate XML
- assign IDs
- modify field mappings
- mutate Sigma rules
- bypass policy
- deploy rules
- become required for deterministic conversion

### Policy layer

Responsibilities:

- decide whether advisory output is accepted
- enforce confidence thresholds
- enforce maximum level deltas
- preserve safe defaults
- provide rejection reasons

Must not:

- call the model
- generate XML
- make network calls
- hide rejected recommendations

### Backend layer

Responsibilities:

- map normalized Sigma fields to Wazuh fields
- assign IDs from an owned range
- generate Wazuh XML
- apply already validated options such as a bounded level override

Must not:

- parse raw YAML
- call an LLM
- call Wazuh APIs
- perform deployment
- infer policy
- silently accept invalid levels or IDs

### Validator layer

Responsibilities:

- validate XML structure
- validate supported fields and constraints
- report actionable errors
- support native parser validation

Must not:

- repair invalid rules silently
- make semantic severity decisions
- deploy artifacts
- trust model output directly

### Deployment layer

Responsibilities:

- authenticate to Wazuh
- back up managed files where requested
- upload validated artifacts
- restart where explicitly requested
- verify resulting state
- roll back when configured

Must not:

- convert Sigma
- modify rule semantics
- call an LLM
- deploy unvalidated XML
- hide partial failure

---

## 3. Python standards

### Supported version

- Code MUST support the Python version declared in `pyproject.toml`.
- New syntax MUST not exceed the declared minimum version.
- Version changes require documentation and CI updates.

### Type safety

- All public functions and methods MUST have complete type annotations.
- New modules SHOULD pass strict static analysis.
- Avoid `Any`; use it only at external boundaries where the shape is genuinely unknown.
- `cast()` must not be used to suppress a real validation problem.
- `# type: ignore` requires a narrow error code and an explanatory comment.
- Use typed dataclasses, enums, `Literal`, protocols, or Pydantic models for structured data.

### Function design

- Functions SHOULD do one thing.
- Pure functions are preferred for normalization, mapping, feature extraction, and policy.
- Long functions SHOULD be decomposed when they mix validation, mutation, I/O, and formatting.
- Boolean parameters that materially alter behavior SHOULD be replaced with enums or named configuration objects.
- Public functions MUST document important preconditions, postconditions, and failure behavior.

### State management

- Avoid global mutable state.
- Dependency injection is preferred over hidden singleton access.
- Runtime configuration MUST be explicit.
- Reusing mutable default arguments is prohibited.
- Stateful generators such as rule-ID allocators must have clear ownership and lifetime.

### Exceptions

- Do not use bare `except`.
- Do not catch `Exception` unless at a deliberate process boundary.
- Expected failure modes MUST use explicit exception types.
- Exceptions must preserve original context with `raise ... from ...` when translated.
- Library code MUST not call `sys.exit()`.
- CLI boundaries may convert typed exceptions into non-zero exit codes and concise messages.
- Do not treat validation failures as warnings when the output would be unsafe.

### Logging

- Use module-level loggers.
- Do not log passwords, API tokens, authorization headers, or full secret-bearing configuration.
- Do not log full Sigma rule bodies at INFO level.
- Use structured, actionable messages.
- Error logs should identify the source file or rule title where safe.
- Do not both log and re-raise the same error at every layer; choose the appropriate boundary.

### Filesystem I/O

- Use `pathlib.Path`.
- Specify text encoding explicitly as UTF-8.
- Use atomic writes for generated artifacts where partial files could be consumed.
- Create parent directories deliberately.
- Never use unsafe temporary filenames.
- Generated artifacts must remain under documented build/report/output directories.

### Serialization

- YAML MUST be loaded with safe APIs.
- Never use `pickle` for cache or report data.
- JSON outputs MUST use stable schemas.
- Unknown fields in security-relevant model responses SHOULD be rejected.
- Schema changes require versioning and tests.

---

## 4. Data and domain invariants

The following invariants MUST be enforced:

- Wazuh rule IDs remain within the configured owned range.
- Duplicate IDs are rejected.
- Wazuh levels remain within 0-15.
- Generated canonical groups match `^sigma_[a-z0-9_]+$`.
- Sigma modifiers never appear as emitted Wazuh field names.
- Field mappings are versioned.
- Source Sigma remains valid Sigma.
- The backend receives normalized rule data.
- Deployment receives validated XML only.
- Optional advisory metadata never changes XML unless deterministic policy explicitly accepts it.

Do not weaken an invariant to make a failing test pass. Fix the cause or document a deliberate contract change.

---

## 5. LLM advisor rules

The local LLM is an optional semantic advisor, not an authority.

### Allowed jobs

The advisor may:

- recommend a Wazuh level
- estimate noise risk
- identify broad or weak detections
- flag potential telemetry mismatch
- produce a short analyst summary
- recommend human review

### Forbidden jobs

The advisor must not:

- generate or edit Wazuh XML
- assign rule IDs
- change field mappings
- remove detection conditions
- rewrite Sigma source automatically
- create parent-child rule dependencies
- decide deployment
- bypass tests or validators
- receive credentials or deployment secrets

### Output contract

- Output MUST be strict JSON.
- Output MUST validate against a typed schema.
- Unknown fields MUST be rejected unless explicitly allowed by schema version.
- Levels MUST be bounded to 0-15.
- Confidence MUST be bounded to 0-1.
- Reason codes and quality flags MUST come from controlled vocabularies.
- Malformed output MUST be treated as advisor failure.
- Free-form hidden reasoning MUST not be requested or persisted.

### Runtime constraints

For the reference 8 GB RAM / 2 CPU deployment:

- one rule per request
- one request at a time
- context capped at 4096 tokens unless benchmarks justify otherwise
- output capped at 300 tokens
- local endpoint bound to loopback by default
- changed-only analysis preferred
- content-addressed caching enabled
- extended reasoning disabled

### Failure behavior

- Advisor failure MUST NOT corrupt conversion output.
- Default behavior is fail-open to deterministic conversion.
- Fail-closed behavior requires explicit configuration.
- Model unavailability must be visible in reports.
- Policy rejection must be recorded with reasons.

---

## 6. Configuration standards

- Configuration must be typed and validated at startup.
- CLI flags override config values predictably.
- Environment variables may provide secrets but must not silently alter semantic behavior.
- Unsafe defaults are prohibited.
- External endpoints must default to localhost or secure schemes as appropriate.
- Unknown config keys SHOULD fail validation rather than being ignored.
- Configuration migrations must be documented.
- A sample config must remain synchronized with the implemented schema.

Avoid reading environment variables throughout the codebase. Resolve them once at the configuration boundary.

---

## 7. CLI standards

- Every command MUST provide useful `--help` output.
- Invalid combinations MUST fail before expensive work begins.
- Successful commands return exit code 0.
- Validation, conversion, configuration, and deployment failures return non-zero exit codes.
- Human-readable output should be concise.
- Machine-readable output must use explicit formats such as JSON.
- Destructive or production-affecting actions require explicit flags.
- `--insecure` must never be enabled by default.
- Deployment restart must be explicit.
- Apply-mode advisor behavior must be explicit.

CLI modules should orchestrate application services, not contain business logic.

---

## 8. Testing requirements

Every behavior change MUST include tests.

### Test pyramid

1. **Unit tests** for pure logic and invariants.
2. **Integration tests** for component boundaries.
3. **End-to-end tests** for production paths.
4. **Native Wazuh validation** for generated rule compatibility.

### Required coverage by change type

#### Parser changes

Must test:

- accepted input
- rejected input
- parser backend metadata
- fallback behavior
- malformed YAML

#### Backend changes

Must test:

- exact XML semantics
- field mapping
- escaping
- IDs
- levels
- groups
- deterministic repeated output, excluding deliberate timestamps

#### Validator changes

Must test:

- valid XML
- each new rejection condition
- actionable diagnostics
- boundary values

#### Advisor changes

Must test:

- strict schema parsing
- malformed output
- timeout
- unavailable server
- cache behavior
- policy acceptance and rejection
- fail-open and fail-closed behavior

#### Deployment changes

Must test:

- request formation
- authentication handling
- backup behavior
- rollback behavior
- restart behavior
- remote verification
- failure at each stage

### Test quality rules

- Do not mock the function under test.
- Prefer small fakes at external boundaries.
- Tests must not depend on execution order.
- Tests must not use live production endpoints.
- Time-dependent behavior should use injectable clocks or tolerant assertions.
- Random behavior must be seeded or removed.
- Golden files must be reviewed and minimal.
- Do not assert only that code “does not raise”; assert meaningful output and state.

### Before merging

At minimum run:

```bash
python -m compileall src tests
python -m pytest
python -m wazuh_sigma.converter.cli \
  --directory examples/sigma \
  --output build/sigma_rules.xml \
  --report build/conversion-report.json
python -m wazuh_sigma.validator.cli \
  --rules build/sigma_rules.xml \
  --output text
```

For backend, normalizer, or parser compatibility changes, also run native validation:

```bash
docker compose up -d
python scripts/normalize_wazuh_rules.py build/sigmahq \
  --target-rules-dir build/wazuh-builtin-rules
docker compose up -d --force-recreate
docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-analysisd -t
```

The native parser command must exit 0 with no output.

---

## 9. Security practices

- Treat all rule content as untrusted.
- Do not pass rule content to a shell.
- Do not construct shell commands through string concatenation.
- Use argument arrays for subprocess execution.
- Set subprocess timeouts.
- Capture and validate exit codes.
- Avoid `shell=True`.
- Validate remote filenames.
- Prevent path traversal.
- Keep TLS verification enabled by default.
- Require explicit opt-in for insecure certificates.
- Support trusted CA bundles.
- Never commit credentials or model weights.
- Verify downloaded model artifacts through trusted hashes where documented.
- Bind development services to loopback unless external exposure is intentional.
- Limit response and request sizes at external boundaries.
- Keep dependencies minimal and pinned within an intentional strategy.

Security-sensitive changes SHOULD include a short threat analysis in the PR description.

---

## 10. Dependency policy

Before adding a dependency, document:

- why the standard library is insufficient
- maintenance status
- license compatibility
- security history
- transitive dependency impact
- runtime and memory impact
- whether it is required in production or only development

Rules:

- Do not add `sigma-cli` as a hard runtime dependency while it conflicts with the project’s pySigma line.
- Keep optional LLM dependencies optional.
- Model runtime clients should prefer simple HTTP contracts over heavy SDKs.
- Development tools belong in development extras.
- Remove obsolete dependencies when functionality is removed.

---

## 11. API and schema compatibility

Public contracts include:

- installed command names
- CLI flags
- exit-code behavior
- `pipeline.yml` keys
- report JSON fields
- generated XML semantics
- Python APIs documented for external use

Changes to public contracts require:

- explicit documentation
- migration notes
- compatibility tests
- versioning where appropriate

Do not silently rename report fields or config keys.

---

## 12. Code review standards

Reviewers must evaluate:

- correctness
- architecture boundaries
- deterministic behavior
- failure modes
- input validation
- security implications
- test quality
- backwards compatibility
- operational impact
- documentation accuracy

Reject changes that:

- put business logic in CLI modules
- make hidden network calls
- silently swallow exceptions
- bypass native validation
- let model output directly mutate XML
- use broad untyped dictionaries where a schema is warranted
- duplicate field mapping logic
- weaken tests to accept broken behavior
- mix unrelated refactors with feature work
- introduce insecure defaults

---

## 13. Commit and pull request practices

Commits SHOULD be small and intentional.

Recommended commit prefixes:

- `feat:` new behavior
- `fix:` bug fix
- `refactor:` behavior-preserving restructuring
- `test:` tests only
- `docs:` documentation only
- `build:` packaging or dependency changes
- `ci:` pipeline changes
- `chore:` maintenance

Pull requests should include:

- problem statement
- design summary
- affected boundaries
- security considerations
- compatibility impact
- tests executed
- generated artifact impact
- rollback plan for deployment-affecting changes

Do not claim production readiness without native validation evidence where relevant.

---

## 14. Documentation rules

Documentation must describe current behavior, not intended behavior presented as complete.

When code changes:

- update README commands if CLI changes
- update `docs/PIPELINE.md` if stages change
- update `docs/RUNBOOK.md` if operations change
- update project structure documentation if ownership changes
- update sample configuration if config changes
- update `docs/ADVISOR_ROADMAP.md` when roadmap work is completed

Examples must be executable or clearly marked as pseudocode.

---

## 15. Performance and resource discipline

The project must remain usable on constrained systems.

- Avoid reading entire large corpora into memory when streaming or iteration is possible.
- Process rules independently where practical.
- Keep advisor concurrency at one for the reference machine.
- Cache expensive deterministic or model-derived results safely.
- Avoid repeated parsing of unchanged files.
- Benchmark before increasing context size or model size.
- Do not optimize by removing validation.
- Performance work must include before-and-after measurements.

---

## 16. Definition of a production-ready change

A change is production-ready only when:

- architectural ownership is clear
- inputs are validated
- outputs are typed or schema-validated
- errors are explicit
- safe defaults are preserved
- unit tests cover core logic
- integration tests cover boundaries
- documentation is updated
- compatibility impact is understood
- security implications are addressed
- generated XML passes project validation
- native Wazuh validation passes when rule compatibility is affected

---

## 17. Rules for coding agents

A coding agent working in this repository MUST:

1. Read the relevant source, tests, configuration, and documentation before editing.
2. State the intended boundary of the change.
3. Avoid inventing APIs or files without checking the repository.
4. Preserve deterministic behavior unless the task explicitly changes it.
5. Add or update tests with every behavior change.
6. Keep model-dependent behavior optional and isolated.
7. Never remove validation merely to make generated rules load.
8. Never claim tests passed unless they were executed successfully.
9. Report commands run and failures encountered.
10. Avoid unrelated cleanup.
11. Use existing project conventions unless there is a documented reason to improve them.
12. Prefer explicit, typed designs over clever abstractions.
13. Leave the repository in a coherent state if full completion is impossible.
14. Do not commit generated build artifacts unless the repository explicitly tracks them.
15. Do not expose secrets, private endpoints, or credentials in code, tests, logs, or documentation.

When uncertain, choose the design that is easier to validate, test, reproduce, and roll back.
