# OpenAI rule advisor

The advisor is an **optional, non-authoritative** semantic reviewer that runs
after deterministic Sigma parsing/validation and before Wazuh XML generation. It
can recommend a Wazuh severity level, assess noise risk, flag weak detection
logic, identify likely telemetry gaps, and produce a short analyst summary.

It is **disabled by default**. When enabled it defaults to **report-only** mode,
which records recommendations in the conversion report but never changes the
generated XML. The deterministic pipeline behaves identically whether the
advisor is disabled, unavailable, or fails.

## What the advisor may and may not do

The advisor **may** recommend a level, assess noise risk, flag quality issues,
identify telemetry gaps, and summarize a rule for an analyst.

The advisor **must never** generate/edit XML, assign rule IDs, change field
mappings, rewrite detection logic, bypass pySigma/XML/`wazuh-analysisd -t`
validation, deploy rules, or receive credentials. The deterministic
[policy engine](../src/wazuh_sigma/advisor/policy.py) is the final authority over
every recommendation; the backend only ever receives a validated
`level_override: int | None`.

## Architecture

```
Sigma parsing -> deterministic validation -> deterministic feature extraction
  -> sanitization -> advisor provider -> deterministic policy -> backend
  -> XML validation -> native wazuh-analysisd -t -> deployment
```

Package layout (`src/wazuh_sigma/advisor/`): `models.py` (strict Pydantic
contracts), `features.py` (pure, versioned feature extraction), `sanitizer.py`
(deterministic redaction), `prompts.py` (versioned prompt contract), `policy.py`
(authoritative decision engine), `cache.py` (content-addressed JSON cache),
`service.py` (orchestration), `telemetry.py` (usage accounting), `errors.py`
(typed exceptions), and `providers/` (`base.py` protocol, `openai.py` provider).

The deterministic core never imports the advisor package; integration points
import it lazily only when the advisor is enabled.

## Enabling it

Install the optional extra and export your API key:

```bash
pip install -e ".[advisor]"
export OPENAI_API_KEY=sk-...        # never store the key in pipeline.yml
```

Enable it in `pipeline.yml` (see the `advisor:` block in the checked-in sample)
or per-invocation from the CLI:

```bash
# Config-driven, report-only advisory run:
sigma-pipeline advise --config pipeline.yml

# Smoke with the advisor attached:
sigma-pipeline smoke --config pipeline.yml --advisor

# Direct converter run:
sigma-convert -d rules/sigma -o build/sigma_rules.xml --advisor
```

CLI flags override config values. Key flags: `--advisor`, `--advisor-mode`
(`report-only|review|apply`), `--advisor-model`, `--advisor-escalation-model`,
`--advisor-min-confidence`, `--advisor-max-level-delta`, `--advisor-cache-dir`,
`--advisor-no-cache`, and `--advisor-fail-closed`. `apply` mode must be selected
explicitly and is intended only after evaluation.

## Modes and policy

- **report-only** (default): recommendations are recorded; XML is never changed.
- **review**: **also non-mutating.** Recommendations that pass policy are marked
  `eligible_for_application` and flagged `requires_human_review` in the report,
  but the effective level is left at the deterministic default. Use this to
  stage recommendations for human approval without touching XML.
- **apply**: the only mode that changes the effective level, and only for
  recommendations that pass every policy check. Explicit opt-in.

Only `apply` ever changes generated XML. The report distinguishes
`eligible_for_application` (passed policy) from `accepted` (actually applied).

The policy rejects recommendations that are low-confidence, exceed the maximum
level delta, promote experimental rules to critical, breach the false-positive
ceiling, or materially conflict between the primary and escalation models.

## Models

There is no default model ID. When the advisor is enabled you must set
`advisor.primary_model` (and optionally `advisor.escalation_model`) to models
your OpenAI account can access; an enabled advisor with no `primary_model` fails
configuration validation. Escalation is triggered deterministically — low
confidence, a large level delta from the baseline, a critical recommendation, a
model-requested review, or a high-impact ATT&CK tactic (credential access,
persistence, privilege escalation, defense evasion) — and the triggering reasons
are recorded in the report.

## Sanitization and secrets

Rule title/description are scrubbed for API keys, bearer tokens, passwords,
internal IPs/domains, and user paths before any request, using deterministic,
versioned placeholders. `strict_sanitization: true` rejects requests containing
high-risk secrets instead of redacting them. Secrets, prompts, and raw provider
responses are never logged or written to reports.

## Caching and cost control

Recommendations are cached by a SHA-256 key over the sanitized rule plus every
version string (feature schema, sanitizer, prompt, output schema, policy) and
the provider/model names, so unchanged rules never trigger a new API call and
any version bump invalidates stale entries automatically. `max_requests` caps
provider calls per run. On failure with `fail_open: true` (default), conversion
continues deterministically and the failure is recorded in the report.

## Report fields

Each converted rule gains an `advisor` block (status, provider/models, mode,
cache hit, redaction flag, versions, default/recommended/effective levels,
confidence, `accepted` and `eligible_for_application` flags, rejection reasons,
escalation reasons, noise risk, quality flags, reason codes, analyst summary,
and the provider `request_id`/`escalation_request_id`). A run-level `advisor`
block carries the telemetry snapshot. Reports never contain API keys,
authorization headers, raw prompts, or raw provider responses. The `request_id`
is the provider's non-secret response identifier, useful for correlating a
recommendation with provider-side logs.

## Testing

Mocked-provider tests run in the default suite (no network). Optional live tests
are marked `openai_integration`, require `OPENAI_API_KEY`, and never run by
default:

```bash
pytest -m openai_integration      # opt-in only
```
