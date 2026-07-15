# Advisor roadmap — Wazuh Sigma Pipeline

> **Status (Phases 1–3 implemented).** The report-only advisor path is built and
> tested: typed models, deterministic feature extraction, sanitization, versioned
> prompts, the deterministic policy engine, content-addressed caching, the OpenAI
> provider (structured outputs, retries, error mapping), converter/config/CLI
> integration, and report metadata. Mocked-provider tests run in the default CI
> suite; generated XML is unchanged in report-only mode. See
> [ADVISOR.md](ADVISOR.md) for usage. Remaining work: the reviewed evaluation
> corpus (Phase 4), enabling bounded review-mode overrides in production after
> evaluation (Phase 5), and operational hardening including the scheduled live
> regression job (Phase 6).

This roadmap defines the work required to add an OpenAI-powered rule advisor to the existing Sigma-to-Wazuh pipeline without weakening deterministic conversion, validation, reproducibility, security, or deployment safety.

The advisor is a semantic review component. It may recommend severity adjustments, identify likely noise, flag weak detection logic, and generate concise analyst-facing explanations. It must never become the source of truth for Sigma parsing, field mappings, rule identifiers, XML generation, native validation, or deployment.

---

## 1. Architectural objective

Add an optional OpenAI advisory stage after Sigma parsing and deterministic validation and before Wazuh XML generation.

```text
Sigma YAML
  -> pySigma parsing and normalization
  -> deterministic Sigma validation
  -> deterministic feature extraction
  -> input sanitization and redaction
  -> optional OpenAI advisor
  -> deterministic policy engine
  -> Wazuh XML backend
  -> XML validator
  -> native wazuh-analysisd -t validation
  -> deployment
```

Initial behavior must be report-only. Bounded level overrides may be enabled only after evaluation demonstrates acceptable accuracy and consistency.

### Non-goals

The advisor must not:

- generate raw Wazuh XML
- modify field mappings
- assign or reserve rule IDs
- create parent-child Wazuh relationships
- remove, rewrite, or broaden Sigma conditions
- bypass pySigma validation
- bypass XML validation
- bypass native Wazuh validation
- deploy rules
- restart Wazuh
- make autonomous production decisions
- process the entire SigmaHQ corpus in one request
- receive production event logs or customer telemetry
- receive credentials, API keys, tokens, or secrets
- become a mandatory dependency for deterministic conversion

---

## 2. Target provider and model strategy

Use the OpenAI API as the sole initial advisor provider.

### Primary model

- default model: `gpt-5.4-nano`
- use for severity calibration, noise assessment, quality flags, prioritization, and concise analyst summaries
- keep prompts compact and structured
- require strict structured output

### Escalation model

- escalation model: `gpt-5.4-mini`
- invoke only when configured and when the primary result is ambiguous, low confidence, or high impact
- escalation must be bounded by cost and request limits

### Escalation triggers

Candidate triggers:

- confidence below configured threshold
- severity recommendation exceeds the allowed delta
- rule targets credential access
- rule targets persistence
- rule targets privilege escalation
- rule targets defense evasion
- rule contains multiple selections and exclusions
- rule contains complex boolean conditions
- rule is marked experimental but recommends a high or critical level
- model flags human review
- primary and deterministic policy scores conflict materially

### Provider abstraction

Even though OpenAI is the only initial implementation, use a narrow provider interface so the rest of the codebase is not coupled directly to the SDK.

```text
src/wazuh_sigma/advisor/
  __init__.py
  models.py
  features.py
  sanitizer.py
  prompts.py
  policy.py
  cache.py
  service.py
  errors.py
  telemetry.py
  providers/
    __init__.py
    base.py
    openai.py
```

---

## 3. Typed advisor models

Create strict Pydantic models in `advisor/models.py`.

### Input models

Define models for:

- normalized rule metadata
- deterministic feature set
- sanitized advisor request
- provider request metadata
- escalation request metadata

Suggested input fields:

- rule content hash
- title
- description
- Sigma level
- Sigma status
- product
- service
- category
- ATT&CK tactics
- ATT&CK techniques
- field names
- operator types
- selection count
- filter count
- condition complexity
- whether the condition contains negation
- whether the rule uses broad wildcards
- whether the rule uses regex
- whether the rule contains one weak indicator
- whether the rule combines independent indicators
- whether false positives are documented
- false-positive count
- current deterministic Wazuh level
- policy baseline level
- expected telemetry class

### Output model

Require structured output with at least:

- `recommended_level: int`
- `confidence: float`
- `noise_risk: Literal["low", "medium", "high"]`
- `quality_flags: list[str]`
- `reason_codes: list[str]`
- `analyst_summary: str`
- `requires_human_review: bool`
- `priority: Literal["deploy", "deploy_with_lower_level", "needs_tuning", "needs_telemetry", "reject", "human_review"]`

### Validation requirements

- level must be between 0 and 15
- confidence must be between 0.0 and 1.0
- unknown fields must be rejected
- reason codes must use a controlled vocabulary
- quality flags must use a controlled vocabulary
- analyst summary must have a strict maximum length
- lists must have bounded lengths
- duplicate flags must be normalized
- malformed responses must never reach the backend
- provider refusal or empty output must be handled explicitly

---

## 4. Deterministic feature extraction

Implement `advisor/features.py` using pure, deterministic functions.

Candidate features:

- title and description
- Sigma level and status
- log source product, category, and service
- ATT&CK tactic and technique tags
- field names after normalization
- modifier/operator types
- number of selections
- number of filters
- condition depth
- boolean operator count
- presence of negation
- presence of `1 of`, `all of`, or wildcard selection patterns
- broad regex indicators
- broad wildcard indicators
- common administrative binaries
- suspicious command primitives
- documented false positives
- likely telemetry dependency
- whether the required telemetry is implied by log source
- single-indicator versus multi-indicator detection
- current deterministic Wazuh level
- policy-derived baseline level

Requirements:

- no API calls
- no filesystem access
- no global mutable state
- stable JSON serialization
- deterministic output for identical normalized rules
- explicit feature schema version
- unit tests for every derived feature
- avoid sending raw YAML when compact semantic features are sufficient

---

## 5. Input sanitization and redaction

Implement `advisor/sanitizer.py` before any external API request.

The sanitizer must identify and remove or replace:

- API keys
- bearer tokens
- passwords
- usernames where not semantically required
- internal hostnames
- internal domains
- internal IP addresses
- customer names
- tenant identifiers
- proprietary application names where unnecessary
- file-system paths containing usernames or customer identifiers
- comments that contain operational secrets

Requirements:

- redaction must be deterministic
- redaction rules must be versioned
- redacted values must use stable placeholders
- raw and sanitized payloads must never be logged at INFO level
- no raw request body in exception messages
- sanitizer behavior must be covered by unit tests
- report whether redaction occurred without exposing original values
- allow strict mode to reject a request if high-risk secrets are detected

---

## 6. OpenAI provider implementation

Implement `advisor/providers/openai.py` using the official OpenAI Python SDK.

### API contract

- use the Responses API
- use structured outputs or typed parsing
- enforce the Pydantic response schema
- set a bounded output token limit
- use deterministic or low-variance settings where supported
- do not request chain-of-thought
- do not persist hidden reasoning
- use one Sigma rule per request

### Required behavior

- API key read only from environment or a secret manager
- default environment variable: `OPENAI_API_KEY`
- configurable primary model
- configurable escalation model
- configurable request timeout
- configurable maximum retries
- exponential backoff with jitter for transient failures
- explicit handling for rate limits
- explicit handling for timeouts
- explicit handling for authentication failures
- explicit handling for invalid structured output
- explicit handling for refusals
- sanitized logging
- request IDs captured when available
- no secret values in logs or reports
- fail-open behavior controlled by configuration

### Retry policy

Retry only for transient failures such as:

- HTTP 429
- temporary 5xx responses
- connection resets
- gateway timeouts

Do not retry blindly for:

- authentication failure
- schema validation failure
- malformed output
- policy rejection
- invalid configuration

### Concurrency

- default concurrency: 1
- configurable bounded concurrency
- no unbounded async fan-out
- respect rate-limit headers when available
- support sequential processing as the safe default

---

## 7. Prompt design

Implement versioned prompts in `advisor/prompts.py`.

Prompt requirements:

- define the advisor as a detection-engineering reviewer
- include the Wazuh level rubric from 0 to 15
- explain that the model is advisory only
- prohibit XML generation
- prohibit field-mapping changes
- prohibit rule-ID changes
- prohibit deployment instructions
- prohibit rewriting detection logic
- require concise structured output
- use controlled reason-code vocabulary
- use controlled quality-flag vocabulary
- state that confidence reflects recommendation reliability
- instruct the model to mark ambiguous rules for human review
- instruct the model to distinguish parser validity from detection quality
- instruct the model to distinguish malicious specificity from operational noise

Prompt metadata must include:

- prompt version
- output schema version
- severity rubric version
- reason-code vocabulary version
- quality-flag vocabulary version

Prompt changes must invalidate relevant cache entries.

---

## 8. Deterministic policy engine

Implement `advisor/policy.py` as the final authority over model recommendations.

### Initial policy

- default mode: `report-only`
- low-confidence recommendations are never applied
- recommendations requiring human review are never applied
- maximum accepted level delta is configurable and defaults to 2
- recommendations outside 0-15 are rejected
- critical-level recommendations require a stronger confidence threshold
- experimental rules cannot be promoted automatically to critical
- rules with documented false positives cannot exceed a configurable ceiling without review
- a missing ATT&CK tag must not by itself block conversion
- provider failure must not block deterministic conversion when `fail_open` is true
- escalation output must pass the same policy checks
- if primary and escalation outputs conflict materially, require human review

### Suggested policy output

- default level
- policy baseline level
- primary recommendation
- escalation recommendation, if any
- effective level
- accepted flag
- rejection reasons
- review requirement
- advisor status
- confidence used for decision

### Backend boundary

The backend may accept only a validated `level_override: int | None`.

It must not receive:

- raw model output
- prompt text
- provider response objects
- API metadata
- sanitizer internals

---

## 9. Cache design

Implement content-addressed JSON caching in `advisor/cache.py`.

Cache key inputs:

- sanitized normalized rule JSON
- feature schema version
- sanitizer version
- prompt version
- output schema version
- policy version
- provider name
- primary model
- escalation model, when used

Requirements:

- SHA-256 cache keys
- atomic writes
- JSON only
- no pickle
- corrupted entries ignored safely
- stale entries invalidated by version changes
- configurable cache directory
- cache can be disabled
- no API keys or authorization headers stored
- no unsanitized rule content stored
- cache-hit metadata recorded in reports

Support a `changed-only` mode so unchanged rules do not trigger new API calls.

---

## 10. Advisor service orchestration

Implement `advisor/service.py`.

Responsibilities:

1. accept a validated normalized Sigma rule
2. extract deterministic features
3. sanitize the request
4. check cache
5. call the primary OpenAI model when needed
6. validate structured output
7. optionally escalate to the secondary model
8. pass results through deterministic policy
9. write cache entry
10. return a typed advisor decision

The service must:

- never mutate the Sigma rule
- never generate XML
- never deploy rules
- never hide provider failures
- preserve deterministic conversion when disabled
- make report-only behavior the default

---

## 11. Backend integration

Update the Wazuh backend to accept an optional validated level override.

Suggested API:

```python
def convert_rule(
    self,
    sigma_rule: SigmaRule,
    *,
    level_override: int | None = None,
) -> Element:
    ...
```

Requirements:

- no API calls in the backend
- no provider imports in the backend
- override must be between 0 and 15
- current Sigma-to-Wazuh mapping remains unchanged without override
- backend output stays deterministic
- advisor metadata must not leak into XML unless explicitly designed later

Tests must prove:

- no override preserves current behavior
- valid override is applied
- invalid override is rejected
- disabled advisor produces byte-equivalent output to the existing pipeline where timestamps are excluded

---

## 12. Converter integration

Update the converter orchestration layer.

Required flow:

1. load YAML
2. normalize with pySigma
3. validate Sigma rule
4. derive deterministic features
5. sanitize advisor input
6. optionally call OpenAI
7. resolve effective level through policy
8. convert through backend
9. record advisor metadata in conversion report

Requirements:

- advisor is opt-in
- report-only mode is default
- conversion behavior remains unchanged when disabled
- API calls are explicit and visible in configuration
- advisor failure is recorded
- fail-open conversion continues when configured
- fail-closed behavior must require explicit configuration
- no hidden network calls

---

## 13. CLI design

Add advisor options to conversion and pipeline CLIs.

Suggested commands:

```bash
sigma-pipeline advise --config pipeline.yml
sigma-pipeline smoke --config pipeline.yml --advisor
sigma-convert -d rules/sigma -o build/sigma_rules.xml --advisor
```

Suggested flags:

- `--advisor`
- `--advisor-mode report-only|review|apply`
- `--advisor-model`
- `--advisor-escalation-model`
- `--advisor-timeout`
- `--advisor-max-retries`
- `--advisor-min-confidence`
- `--advisor-max-level-delta`
- `--advisor-cache-dir`
- `--advisor-no-cache`
- `--advisor-changed-only`
- `--advisor-fail-closed`
- `--advisor-disable-escalation`
- `--advisor-max-cost-usd`
- `--advisor-max-requests`

Requirements:

- CLI flags override config
- defaults are safe
- invalid combinations fail early
- apply mode requires explicit opt-in
- missing API key produces an actionable error when advisor is enabled
- help text states that the advisor is non-authoritative

---

## 14. Configuration

Extend `pipeline.yml`.

```yaml
advisor:
  enabled: false
  mode: report-only
  provider: openai

  model: gpt-5.4-nano
  escalation_model: gpt-5.4-mini

  timeout_seconds: 30
  max_retries: 3
  minimum_confidence: 0.80
  maximum_level_delta: 2
  max_output_tokens: 300

  cache_directory: build/advisor-cache
  cache_enabled: true
  changed_only: true
  fail_open: true

  escalation:
    enabled: true
    confidence_below: 0.70
    high_impact_tactics:
      - credential_access
      - persistence
      - privilege_escalation
      - defense_evasion

  limits:
    max_requests: 1000
    max_cost_usd: 10.00
    concurrency: 1

  privacy:
    redact_internal_hosts: true
    redact_internal_domains: true
    reject_detected_secrets: true
```

Validation requirements:

- provider must be `openai`
- model names must be non-empty strings
- confidence must be within 0-1
- level delta must be non-negative
- timeout and retries must be bounded
- output tokens must be bounded
- cost limits must be non-negative
- concurrency must be bounded
- apply mode must not activate accidentally

---

## 15. Secret management

Requirements:

- API key must come from `OPENAI_API_KEY` or an approved secret manager
- never store the key in `pipeline.yml`
- never store the key in `.env.example`
- never commit `.env`
- never include the key in logs
- never include authorization headers in exceptions
- never include secrets in conversion reports
- CI secret must be scoped to only jobs that require live integration tests
- pull requests from untrusted forks must not receive the secret

Add documentation for:

- local environment setup
- GitLab CI secret setup
- key rotation
- revocation procedure
- troubleshooting authentication failures

---

## 16. Cost and usage controls

Implement usage accounting in `advisor/telemetry.py`.

Track:

- request count
- cache hits and misses
- primary model calls
- escalation calls
- input tokens
- output tokens
- estimated cost
- average latency
- error count by category
- rate-limit events

Requirements:

- enforce configurable maximum request count
- enforce configurable maximum estimated cost
- stop new model calls when a limit is reached
- continue deterministic conversion when fail-open is enabled
- record that advisor processing stopped due to limits
- do not log raw prompts or rules
- support per-run summary output

---

## 17. Report schema

Extend `conversion-report.json` with advisor metadata per rule.

Suggested shape:

```json
{
  "sigma_title": "Suspicious PowerShell Download",
  "wazuh_id": "900142",
  "source_file": "rules/sigma/powershell_download.yml",
  "advisor": {
    "enabled": true,
    "provider": "openai",
    "mode": "report-only",
    "primary_model": "gpt-5.4-nano",
    "escalation_model": "gpt-5.4-mini",
    "escalated": false,
    "prompt_version": "severity-v1",
    "feature_schema_version": "features-v1",
    "sanitizer_version": "sanitizer-v1",
    "policy_version": "policy-v1",
    "cache_hit": false,
    "redaction_applied": true,
    "default_level": 12,
    "policy_level": 10,
    "recommended_level": 9,
    "effective_level": 12,
    "confidence": 0.86,
    "accepted": false,
    "requires_human_review": false,
    "noise_risk": "medium",
    "quality_flags": ["missing_filter"],
    "reason_codes": ["common_administrative_behavior"],
    "analyst_summary": "Detects PowerShell remote-content retrieval behavior.",
    "status": "completed",
    "request_id": "redacted-or-safe-provider-request-id"
  }
}
```

Run-level report metadata should include:

- provider
- models
- request count
- cache statistics
- token usage
- estimated cost
- error summary
- escalation count
- limits reached

Never include:

- API keys
- authorization headers
- raw provider responses
- raw unsanitized prompts
- secrets detected during sanitization

---

## 18. Error model

Define explicit exceptions in `advisor/errors.py`:

- `AdvisorDisabledError`
- `AdvisorConfigurationError`
- `AdvisorAuthenticationError`
- `AdvisorRateLimitError`
- `AdvisorTimeoutError`
- `AdvisorUnavailableError`
- `AdvisorRefusalError`
- `AdvisorMalformedOutputError`
- `AdvisorSchemaValidationError`
- `AdvisorPolicyRejectionError`
- `AdvisorCacheError`
- `AdvisorCostLimitError`
- `AdvisorRequestLimitError`
- `AdvisorSanitizationError`

Do not use broad exceptions for expected provider failure modes.

---

## 19. Testing strategy

### Unit tests

Cover:

- deterministic feature extraction
- sanitizer behavior
- secret detection
- stable serialization
- cache-key generation
- cache corruption recovery
- prompt versioning
- response schema validation
- provider error mapping
- retry classification
- policy acceptance and rejection
- escalation logic
- cost and request limits
- fail-open behavior
- fail-closed behavior
- backend override validation

### Provider tests

Use mocked OpenAI responses for normal CI.

Test:

- successful structured output
- malformed output
- refusal
- timeout
- authentication failure
- 429 retry behavior
- 5xx retry behavior
- schema mismatch
- missing output
- escalation path

### Integration tests

Add optional live tests guarded by:

- `OPENAI_API_KEY`
- explicit test marker such as `pytest -m openai_integration`
- strict request and cost limits

Live tests must not run by default in normal CI.

### End-to-end tests

Prove:

- disabled advisor preserves existing conversion behavior
- report-only mode never changes XML levels
- review mode changes only policy-approved levels
- apply mode is explicit
- advisor failure does not block conversion when fail-open is enabled
- conversion report contains advisor metadata
- native Wazuh validation remains mandatory

---

## 20. Evaluation dataset and acceptance criteria

Build a reviewed evaluation corpus of representative Sigma rules.

Include:

- high-confidence malicious detections
- noisy administrative behavior
- broad PowerShell detections
- credential-access rules
- persistence rules
- privilege-escalation rules
- defense-evasion rules
- network detections
- Linux detections
- Windows detections
- experimental rules
- stable rules
- rules with documented false positives
- rules with complex conditions

For each rule, record reviewer-approved values for:

- expected Wazuh level band
- acceptable level range
- expected noise risk
- expected quality flags
- human-review requirement

Track:

- exact level agreement
- agreement within ±1
- false promotions
- false demotions
- review precision
- review recall
- noise-risk agreement
- malformed-output rate
- refusal rate
- primary-to-escalation improvement

Automatic level application must remain disabled until acceptance thresholds are documented and met.

---

## 21. CI/CD changes

Add CI jobs for:

- static type checking
- linting
- unit tests
- mocked provider tests
- converter tests
- validator tests
- byte compilation
- deterministic output tests
- native Wazuh parser validation

Optional scheduled job:

- live OpenAI regression evaluation
- uses protected CI secret
- runs against a small fixed corpus
- enforces a strict cost ceiling
- stores only sanitized reports

Normal pull-request CI must not depend on external API availability.

---

## 22. Documentation

Add or update:

- `docs/ADVISOR.md`
- `docs/OPENAI_SETUP.md`
- `docs/PRIVACY.md`
- `docs/ADVISOR_POLICY.md`
- `docs/ADVISOR_EVALUATION.md`
- `docs/RUNBOOK.md`
- `docs/PIPELINE.md`
- `README.md`

Documentation must explain:

- advisor purpose
- advisory versus authoritative boundaries
- OpenAI configuration
- secret management
- data sanitization
- cost controls
- caching
- escalation
- failure behavior
- report interpretation
- human-review workflow
- disabling the advisor
- incident response for leaked credentials

---

## 23. Delivery phases

### Phase 1 — Foundations

- create advisor package
- define typed models
- implement deterministic features
- implement sanitizer
- define controlled vocabularies
- define prompt and schema versions

### Phase 2 — OpenAI provider

- add official SDK dependency
- implement Responses API integration
- implement structured outputs
- implement error mapping
- implement retries and timeouts
- implement request IDs and safe telemetry

### Phase 3 — Report-only integration

- integrate service into converter
- add cache
- add report metadata
- add CLI and config
- keep XML unchanged

### Phase 4 — Evaluation

- build reviewed corpus
- compare recommendations
- tune prompts and policy
- validate escalation value
- document acceptance thresholds

### Phase 5 — Bounded review mode

- enable policy-approved level overrides
- retain maximum delta
- require human review for conflicts
- preserve native validation gates

### Phase 6 — Operational hardening

- finalize cost limits
- finalize privacy controls
- add scheduled regression tests
- add runbooks
- define rollback procedure

---

## 24. Definition of done

The OpenAI advisor feature is complete only when:

- advisor is optional
- disabled mode preserves existing behavior
- OpenAI is the only configured initial provider
- structured outputs are strictly validated
- secrets are never logged or reported
- input is sanitized before transmission
- report-only is the default mode
- deterministic policy remains authoritative
- backend remains provider-agnostic
- API failure is handled predictably
- caching avoids duplicate requests
- cost and request limits are enforced
- mocked provider tests pass in normal CI
- optional live tests are isolated and bounded
- conversion report records traceable advisor metadata
- XML validator still passes
- `wazuh-analysisd -t` still passes
- no advisor result can bypass deployment safeguards

---

## 25. Immediate implementation order

1. Add OpenAI SDK dependency behind the advisor feature path.
2. Create typed request and response models.
3. Implement deterministic feature extraction.
4. Implement sanitizer and secret detection.
5. Implement the OpenAI provider with structured output.
6. Add deterministic policy in report-only mode.
7. Add JSON cache and content hashing.
8. Extend conversion reports.
9. Add CLI and `pipeline.yml` configuration.
10. Add mocked provider tests.
11. Build the evaluation corpus.
12. Add optional bounded escalation.
13. Evaluate before allowing any automatic level override.
