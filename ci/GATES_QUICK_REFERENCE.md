# Windows Field Mapping CI Gates - Quick Reference

## The Six Gates at a Glance

```
┌─────────────────────────────────────────────────────────────────┐
│   Windows Field Mapping Validation Pipeline (github/workflows/ci.yml)
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Gate 1: field-registry-unit-tests (REQUIRED)                  │
│  ├─ tests/test_fields_windows.py                               │
│  └─ tests/test_backend_field_mapping.py                        │
│  ✓ Validates: Field models, registry ops, backend integration  │
│  ✗ Fails: Any test fails                                       │
│                                                                 │
│  Gate 2: decoded-fixture-verification (OPTIONAL WARNING)       │
│  ├─ Check VERIFIED mappings have fixture evidence              │
│  └─ Verify fixture paths exist and match                       │
│  ✓ Validates: Fixture coverage for decoded mappings            │
│  ✗ Fails: VERIFIED mapping missing fixture (can warn)          │
│                                                                 │
│  Gate 3: full-corpus-field-audit (REQUIRED)                    │
│  ├─ Count fields by confidence level                           │
│  ├─ Count fields by namespace                                  │
│  └─ Detect unsupported Windows fields                          │
│  ✓ Validates: Field inventory completeness                     │
│  ✗ Fails: Unsupported fields detected                          │
│                                                                 │
│  Gate 4: strict-conversion-test (REQUIRED)                     │
│  ├─ Convert examples/sigma in strict mode                      │
│  ├─ Generate conversion report                                 │
│  └─ Check for rejected rules or unknown fields                 │
│  ✓ Validates: Full conversion without rejections               │
│  ✗ Fails: Any rule rejected, unknown field                     │
│                                                                 │
│  Gate 5: native-wazuh-validation (REQUIRED)                    │
│  ├─ Parse XML for well-formedness                              │
│  ├─ Validate rule structure                                    │
│  ├─ Check rule levels (0-15)                                   │
│  └─ Check field name format (win.*)                            │
│  ✓ Validates: XML validity, rule constraints                   │
│  ✗ Fails: Invalid XML, level out of range                      │
│                                                                 │
│  Gate 6: end-to-end-fixture-tests (REQUIRED)                   │
│  ├─ tests/test_evtx_end_to_end.py                              │
│  ├─ Sysmon, Security, DNS, Application fixtures                │
│  └─ Field paths, capitalization, patterns                      │
│  ✓ Validates: Rules match actual events                        │
│  ✗ Fails: Field not found, capitalization wrong                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## When Gates Run

- **On every push to main**
- **On every pull request**
- **Triggers**: `push`, `pull_request`
- **Required for merge**: All 6 gates must pass (except Gate 2 can warn)

## How to Read a Failure

### Gate 1 Failure Example
```
FAILED tests/test_fields_windows.py::TestFieldMapping::test_field_mapping_system_namespace
AssertionError: assert 'win.system.eventID' == 'win.system.eventid'
```
**Action**: Fix field mapping casing in registry

### Gate 2 Failure Example
```
WARNING: 3 VERIFIED mappings missing fixture evidence:
  - LogonType -> win.eventdata.logonType
  - QueryName -> win.eventdata.queryName
  - SourcePort -> win.eventdata.sourcePort
```
**Action**: Add fixtures or change confidence to PROVISIONAL

### Gate 3 Failure Example
```
ERROR: Unsupported Windows fields detected in registry
```
**Action**: Review registry for orphaned or invalid fields

### Gate 4 Failure Example
```
ERROR: Strict mode conversion found rejected rules or unknown fields
Rule sigma_0001: Unknown field 'BadField' (product=windows)
Rejection reason: Field cannot be mapped in strict mode
```
**Action**: Add field to registry or remove from Sigma rules

### Gate 5 Failure Example
```
ERROR: Rule 900123 has invalid level 16
```
**Action**: Fix rule level (must be 0-15) in backend/advisor

### Gate 6 Failure Example
```
AssertionError: win.eventdata.image: Field not found in fixture
Expected: C:\Windows\System32\cmd.exe
Actual: Field path not found
```
**Action**: Check field exists in fixture, verify camelCase

## Running Gates Locally

```bash
# All gates at once
python -m pytest tests/test_fields_windows.py tests/test_backend_field_mapping.py
python -m pytest tests/test_evtx_end_to_end.py
python -m wazuh_sigma.converter.cli --directory examples/sigma --output build/test.xml --field-mapping-mode strict

# Single gate
python -m pytest tests/test_fields_windows.py -v              # Gate 1a
python -m pytest tests/test_backend_field_mapping.py -v       # Gate 1b
# Gate 2: visual inspection of fixtures/wazuh/windows/
# Gate 3: check field count in windows.py
python -m wazuh_sigma.converter.cli --directory examples/sigma --output build/test.xml --field-mapping-mode strict  # Gate 4
python3 -c "import xml.etree.ElementTree as ET; ET.parse('build/test.xml'); print('✓ Valid')"  # Gate 5
python -m pytest tests/test_evtx_end_to_end.py -v             # Gate 6
```

## Files Involved

| Component | File | Purpose |
|-----------|------|---------|
| Workflow | `.github/workflows/ci.yml` | Gate definitions |
| Config | `ci/validation-gates.yml` | Gate specifications |
| Docs | `ci/VALIDATION_GATES.md` | Full documentation |
| Registry | `src/wazuh_sigma/fields/windows.py` | Field mappings |
| Tests (1) | `tests/test_fields_windows.py` | Field model tests |
| Tests (1) | `tests/test_backend_field_mapping.py` | Backend tests |
| Fixtures | `tests/fixtures/wazuh/windows/*.json` | Event fixtures |
| Examples | `examples/sigma/` | Sigma rules to convert |
| Output | `build/sigma_rules_strict.xml` | Generated rules |
| Report | `build/conversion-report-strict.json` | Conversion report |

## Field Mapping Confidence Levels

| Level | Meaning | Fixture Required? | Example |
|-------|---------|------------------|---------|
| VERIFIED | Documented, tested, fixtures | Yes (if DECODED_FIXTURE) | EventID, Image, CommandLine |
| PROVISIONAL | Likely correct, less tested | No | Extended eventdata fields |

## Field Namespaces

| Namespace | Prefix | Source | Example |
|-----------|--------|--------|---------|
| SYSTEM | `win.system.*` | Event/System | eventID, providerName, channel |
| EVENTDATA | `win.eventdata.*` | Event/EventData | image, commandLine, logonType |

## Verification Sources

| Source | Trust Level | When Used |
|--------|------------|-----------|
| WINDOWS_DOCUMENTATION | High | Microsoft docs, Sysmon docs |
| DECODED_FIXTURE | High | Actual Wazuh decoded event |
| REPOSITORY_LEGACY | Medium | Project git history |

## Adding a New Field

### Quick Steps
1. Add to `src/wazuh_sigma/fields/windows.py`
2. Add fixture to `tests/fixtures/wazuh/windows/` (if VERIFIED)
3. Add test to `tests/test_fields_windows.py`
4. Add Sigma rule to `examples/sigma/` (if applicable)
5. Push and watch gates run

### Check Lists

**Before Pushing**
- [ ] Field mapping has all required attributes
- [ ] Namespace matches field prefix
- [ ] Products tuple is not empty
- [ ] If VERIFIED: fixture exists
- [ ] Tests pass locally
- [ ] Strict conversion succeeds
- [ ] Capitalization is exact camelCase

**After Push (CI)**
- [ ] Gate 1: Unit tests pass
- [ ] Gate 2: Fixtures verified
- [ ] Gate 3: Audit shows new field
- [ ] Gate 4: Conversion succeeds
- [ ] Gate 5: XML valid
- [ ] Gate 6: Fixtures match

## Troubleshooting Fast Path

**Gate failing?**

1. Check error message from CI logs
2. Find gate number (1-6) from failure
3. Go to `ci/VALIDATION_GATES.md` section for that gate
4. Read "Troubleshooting" subsection
5. Follow recommended action

**Example**:
- Failure in "Backend field mapping integration tests"
- That's Gate 1b
- Check VALIDATION_GATES.md → Gate 1 → Troubleshooting
- "Backend mapper test fails" → "Check backward compatibility"

## GitHub Actions Dashboard

**View CI Results**:
1. Go to Actions tab
2. Select "CI" workflow
3. Find your branch/PR
4. Click on `windows-field-mapping` job
5. Expand failed step for details

**Download Artifacts**:
1. Go to workflow run
2. Scroll to "Artifacts"
3. Download `windows-field-mapping-results`
4. Contains: XML, report, conversion log

## Key Metrics

| Metric | Current | Trend |
|--------|---------|-------|
| Total Field Mappings | 127 | Growing |
| VERIFIED Mappings | 42 | Stable |
| PROVISIONAL Mappings | 85 | Increasing |
| System Fields | 8 | Stable |
| EventData Fields | 119 | Growing |
| Fixture Files | 9 | Stable |
| Sigma Examples | N/A | Varies |

## Contact and Docs

- **Full Guide**: `ci/VALIDATION_GATES.md`
- **Configuration**: `ci/validation-gates.yml`
- **This Reference**: `ci/GATES_QUICK_REFERENCE.md`
- **Summary**: Root `CI_GATES_SUMMARY.md`

## One-Liners

```bash
# Run all gates locally
python -m pytest tests/test_fields_windows.py tests/test_backend_field_mapping.py tests/test_evtx_end_to_end.py && python -m wazuh_sigma.converter.cli --directory examples/sigma --output build/test.xml --field-mapping-mode strict && echo "All gates passed!"

# Check field count
python3 -c "from wazuh_sigma.fields.windows import WINDOWS_FIELD_MAPPINGS; print(f'Total fields: {len(WINDOWS_FIELD_MAPPINGS)}')"

# Verify XML is valid
python3 -c "import xml.etree.ElementTree as ET; ET.parse('build/sigma_rules_strict.xml'); print('XML is valid')" 2>&1

# Count VERIFIED mappings
python3 -c "from wazuh_sigma.fields.windows import WINDOWS_FIELD_MAPPINGS; from wazuh_sigma.fields.models import ConfidenceLevel; print(f\"VERIFIED: {sum(1 for m in WINDOWS_FIELD_MAPPINGS if m.confidence == ConfidenceLevel.VERIFIED)}\")"
```

## Legend

| Symbol | Meaning |
|--------|---------|
| ✓ | Success, passes, valid |
| ✗ | Failure, rejected, invalid |
| → | Maps to, converts to |
| \* | All, any, any match |
