# Conversion coverage and known limitations

This document records the current full-corpus Windows Sigma conversion state. It is evidence, not a target-state document.

## Current full Windows corpus run

- Date: 2026-07-15
- Source: `sigma/rules/windows/`
- Command:

```bash
python -m wazuh_sigma.converter.cli \
  --directory sigma/rules/windows \
  --output build/reports/current/windows-corpus/sigma_rules.xml \
  --report build/reports/current/windows-corpus/conversion-report.json \
  --start-id 900000 \
  --end-id 949999
```

| Metric | Value |
| --- | ---: |
| Rules discovered | 2,403 |
| Converted | 826 |
| Rejected | 1,577 |
| Conversion percentage | 34.37% |
| Baseline converted | 1,338 |
| Baseline conversion percentage | 55.68% |
| Converted delta vs baseline | -512 |
| Generated chunks | 4 |
| Rules per chunk | 207, 207, 206, 206 |
| XML validation | pass, 0 failures |
| Chunk XML validation | pass, 0 failures |
| Native `wazuh-analysisd -t` | not run in this environment |

The current conversion rate is materially below the previous 55.68% baseline. This is expected from stricter fail-closed mapping behavior, but it is still a production blocker until every lost rule is either recovered or explicitly justified.

Current generated evidence:

- `build/reports/current/windows-corpus/conversion-report.json`
- `build/reports/current/windows-corpus-regression.json`
- `build/reports/current/windows-corpus-regression.md`
- `build/reports/current/windows-removed-mapping-audit.json`
- `build/reports/current/windows-removed-mapping-audit.md`

## Removed-mapping audit

The cleanup removed 40 Windows mappings. Current reconciliation shows:

| Result | Count |
| --- | ---: |
| Removed fields audited | 40 |
| Fields with fixture evidence | 39 |
| Fields still used by Sigma | 22 |
| Fields needing fixture + Sigma review | 22 |
| Fields needing fixture-only review | 17 |
| Fields probably justified with no current evidence | 1 |

The following called-out fields have historical decoded-fixture evidence and must not be treated as “unsupported” solely because a cross-reference script failed to recognize them:

- `OriginalFileName`
- `ImageLoaded`
- `Product`
- `Description`
- `Company`
- `CallTrace`
- `GrantedAccess`
- `ProcessGuid`
- `SourceProcessGuid`
- `TargetProcessGuid`

Required next step: reconcile each field against exact fixture path, provider/channel/Event ID context, current Sigma usage, and native Wazuh behavior before either restoring or permanently rejecting it.

## Current failure classes

The regression report groups all current failures by:

- unsupported fields;
- unsupported modifiers;
- parser failures;
- pattern-length failures;
- lost rules relative to baseline.

Use:

```bash
python scripts/windows_corpus_regression.py \
  --current build/reports/current/windows-corpus/conversion-report.json \
  --baseline build/reports/windows-conversion-full-report.json \
  --json-output build/reports/current/windows-corpus-regression.json \
  --markdown-output build/reports/current/windows-corpus-regression.md
```

## Native Wazuh validation gap

XML validation is not equivalent to native Wazuh rule validation.

Production readiness requires running:

```bash
wazuh-analysisd -t
```

against:

- the complete generated ruleset;
- every generated chunk;
- the final deployed manager configuration.

This gate was not run locally because Docker/Wazuh native parser access was unavailable. It must be run in an environment with Wazuh manager binaries.

## Detection execution gap

Production readiness also requires event-to-rule tests:

```text
captured event -> expected generated rule ID
negative event -> no generated rule ID
```

Priority event sources:

- Sysmon 1, 3, 7, 10, 11, 13, 22;
- PowerShell 4104;
- Security 4624, 4662, 4688, 4697, 4720, 5140, 5145, 5156, 5157;
- System 7045;
- Defender;
- WMI;
- Task Scheduler.

The Caldera hidden-user execution path has been proven to execute on a live Windows agent, and Wazuh confirms the generated 4720 rules are loaded. Alert-index confirmation still requires indexer/dashboard credentials with alert-search access.
