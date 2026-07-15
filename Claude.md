# Claude.md — Wazuh Sigma Pipeline

## Project Summary

This repository converts untrusted Sigma YAML detections into Wazuh XML rules. The conversion is deterministic, testable, and validates output against native Wazuh parsers before any deployment.

there is graphify in the folder so check it to know everything

See **Codex.md** for full engineering standards and normative rules (MUST, MUST NOT, SHOULD).

---

## Architecture at a Glance

```
Sigma source → parser + pySigma → domain model → validation →
optional advisor → deterministic policy → Wazuh backend →
XML validation → native Wazuh validation → deployment
```

**Key principle:** Each layer has one job. No layer calls layers out of order or invokes APIs across boundaries.

### Core modules (maintained paths)

- **`src/wazuh_sigma/converter/`** — Sigma loading, pySigma normalization, CLI dispatch (`sigma-convert`). `service.py` owns conversion orchestration.
- **`src/wazuh_sigma/backend/`** — Wazuh XML generation. Field mapping, ID assignment, level bounds.
- **`src/wazuh_sigma/validator/`** — Wazuh XML validation. CLI dispatch (`sigma-validate`), discovery, structure checks, pattern validation.
- **`src/wazuh_sigma/deploy/`** — Wazuh API client and deployment. `client.py` owns HTTP transport; `wazuh_api.py` owns safety flow and rollback.
- **`src/wazuh_sigma/config.py`, `pipeline.py`, `pipeline_stages.py`** — Configuration, top-level pipeline CLI, executable stages.
- **`src/wazuh_sigma/naming.py`** — Single canonical implementation of `sigma_{NAME}` naming.
- **Examples, tests, scripts** — See PROJECT_STRUCTURE.md for maintained vs. generated paths.

---

## Critical Rules

### Determinism and Testability

- **Parsing, field mapping, ID assignment, XML generation, policy decisions must be deterministic.**
- Conversion with the same input must produce identical output (excluding deliberate timestamps).
- All behavior is explicit and testable; no hidden retries, fallbacks, or network calls.

### Fail-Safe Design

- **Invalid inputs, missing optional services, malformed model responses, deployment failures must not produce partially trusted artifacts.**
- Errors are explicit exceptions, not silent coercions.
- Default to fail-closed on unsafe conditions unless explicitly configured otherwise.
- Do NOT repair invalid rules silently; validate before output.

### No Hidden Behavior

- Network calls, filesystem writes, environment variables, retries, and mutations **must be explicit and testable**.
- Advisor (LLM) output is optional and never modifies XML without deterministic policy review.
- Logging never includes secrets, full rule bodies at INFO level, or passwords.

### Data Invariants (Enforced)

- Wazuh rule IDs stay within configured range; duplicates rejected.
- Wazuh levels: 0–15 only.
- Canonical groups: `^sigma_[a-z0-9_]+$`.
- Sigma modifiers never appear as Wazuh field names.
- Field mappings versioned; source Sigma remains valid.

---

## When and How to Test

**Every behavior change requires tests.** See Codex §8 for test pyramid and required coverage by type.

### Before merging, run:

```bash
python -m pytest
python -m compileall src tests
python -m wazuh_sigma.converter.cli \
  --directory examples/sigma \
  --output build/sigma_rules.xml \
  --report build/conversion-report.json
python -m wazuh_sigma.validator.cli \
  --rules build/sigma_rules.xml --output text
```

### For backend or parser changes, also run native validation:

```bash
docker compose up -d
docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-analysisd -t
```

The native parser must exit 0 with no output. **This is the final rule-load gate.**

---

## The LLM Advisor Boundary

The optional OpenAI-backed advisor may:

- Recommend a Wazuh level.
- Estimate noise risk or identify weak detections.
- Produce a summary for analyst review.

The advisor must NOT:

- Generate or modify XML directly.
- Assign rule IDs or change field mappings.
- Bypass tests or validators.
- Remove detection conditions.
- Receive credentials or secrets.

**All advisor output is treated as untrusted JSON** — strict schema validation required. Policy engine explicitly accepts or rejects recommendations.

---

## Python and Code Quality

### Type safety

- All public functions **must** have complete type annotations.
- New modules should pass strict static analysis.
- Avoid `Any`; use it only at external boundaries.
- `cast()` and `# type: ignore` require narrow error codes and comments.

### Function design

- One thing per function.
- Pure functions preferred for normalization, mapping, policy, feature extraction.
- Long functions mixed with I/O, validation, and mutation should decompose.
- Boolean parameters that change behavior → use enums or config objects.

### Exceptions

- No bare `except` or broad `Exception` catch.
- Expected failures use explicit exception types.
- Preserve context with `raise ... from ...`.
- Library code: no `sys.exit()`.
- Translate exceptions at boundaries, not every layer.
- Validation failures are errors, not warnings, when output would be unsafe.

### Filesystem and serialization

- Use `pathlib.Path`; specify UTF-8 encoding explicitly.
- Atomic writes for generated artifacts.
- Safe YAML loading only.
- JSON outputs use stable schemas.
- Reject unknown fields in security-relevant model responses.

---

## Configuration and CLI

- Configuration is **typed and validated at startup.**
- CLI flags override config values predictably.
- Environment variables for secrets only; never silently alter semantic behavior.
- Unsafe defaults prohibited.
- Unknown config keys fail validation rather than silently ignored.

**CLI modules orchestrate; they never contain business logic.**

---

## Deployment Safety

Deployment receives **validated XML only**. Before upload:

- Ensure XML structure is valid.
- Verify all fields are in bounds (IDs, levels, groups).
- Test rules against sample logs if provided.
- Validate decoder and group references.

On failure:

- Stop before rollback unless explicitly configured.
- Report partial failure visibly.
- Never hide skipped or failed uploads.

---

## Security Essentials

- Treat all rule content as **untrusted**.
- No shell command construction from rule content.
- Use argument arrays for subprocess calls; set timeouts.
- Validate remote filenames; prevent path traversal.
- Keep TLS verification on by default; require explicit opt-in for insecure certs.
- Bind development services to loopback by default.
- Never commit credentials, model weights, or secrets.
- Limit request and response sizes at external boundaries.

---

## Dependency and Compatibility Policy

Before adding a dependency:

- Explain why stdlib is insufficient.
- Document maintenance status, license, security history.
- Note transitive impact, memory/runtime cost.
- Mark production vs. development requirement.

**Do not:**

- Add `sigma-cli` as hard runtime dependency while it conflicts with project's pySigma.
- Make LLM dependencies required for core conversion.
- Remove or downgrade dependencies without documenting the removal.

**Public contracts** (CLI commands, flags, exit codes, config keys, report JSON fields, XML semantics, documented Python APIs):

- Change only with documentation, migration notes, and compatibility tests.
- Silent renames prohibited.

---

## Code Review and Commit Standards

### Reviewers check:

- Correctness, architecture boundaries, deterministic behavior, failure modes.
- Input validation, security implications, test quality.
- Backwards compatibility, operational impact, documentation accuracy.

### Reject changes that:

- Put business logic in CLI.
- Make hidden network calls.
- Silently swallow exceptions.
- Bypass native validation.
- Let model output directly mutate XML.
- Use broad untyped dicts where schema warranted.
- Duplicate field-mapping logic.
- Weaken tests to accept broken behavior.
- Mix refactors with feature work.
- Introduce insecure defaults.

### Commit practices:

Use prefixes: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `build:`, `ci:`, `chore:`.

Keep commits small and intentional.

---

## Definition of Production-Ready

A change is production-ready only when:

- **Architectural ownership is clear.**
- **Inputs are validated; outputs are typed or schema-validated.**
- **Errors are explicit.**
- **Safe defaults preserved.**
- **Unit tests cover core logic; integration tests cover boundaries.**
- **Documentation is updated.**
- **Compatibility impact understood; security implications addressed.**
- **Generated XML passes project validation.**
- **Native Wazuh validation passes when rule compatibility is affected.**

---

## For Coding Agents

Before editing:

1. **Read the relevant source, tests, config, and documentation.**
2. **State the intended boundary of the change.**
3. **Avoid inventing APIs or files without checking the repo.**
4. **Preserve deterministic behavior** unless the task explicitly changes it.
5. **Add or update tests with every behavior change.**
6. **Keep model-dependent behavior optional and isolated.**
7. **Never remove validation to make generated rules load.**
8. **Report commands run and failures encountered.**
9. **Avoid unrelated cleanup.**
10. **Use existing project conventions unless there's a documented reason to improve them.**

**When uncertain:** Choose the design that is easier to validate, test, reproduce, and roll back.

---

## Useful Resources

- **Codex.md** — Full normative standards (MUST, MUST NOT, SHOULD).
- **docs/PROJECT_STRUCTURE.md** — Maintained vs. generated paths.
- **docs/PIPELINE.md** — Pipeline stages and flow.
- **docs/RUNBOOK.md** — Operational procedures.
- **docs/ADVISOR_ROADMAP.md** — LLM advisor future work.
- **pyproject.toml** — Python version, dependencies, CLI entry points.
- **graphify-out/GRAPH_REPORT.md** — Code structure and hubs (generated by graphify).

---

## Quick Checklist Before Submitting

- [ ] Behavior change includes tests.
- [ ] Type annotations on public functions.
- [ ] No broad exception handlers.
- [ ] Deterministic output verified (run conversion + validation).
- [ ] Native Wazuh validation passes for rule-affecting changes.
- [ ] Documentation updated (README, docs/, config sample).
- [ ] Commits small and intentional.
- [ ] No unrelated cleanup or refactoring.
- [ ] No secrets, credentials, or model weights in code/tests.
