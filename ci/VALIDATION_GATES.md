# Windows Field Mapping CI Validation Gates

This document describes the six CI validation gates for Windows field mapping in the Wazuh Sigma pipeline.

## Overview

The validation gates ensure that:
- Windows field mappings are correctly defined and tested
- Generated rules use supported Windows fields
- All field mappings are backed by verification evidence (fixtures)
- Full corpus conversion completes in strict mode
- Generated XML is valid and passes Wazuh validation
- End-to-end rule-to-event matching works correctly

All gates run as part of the `windows-field-mapping` GitHub Actions job on every push and pull request.

---

## Gate 1: Field Registry Unit Tests

**Status**: `field-registry-unit-tests`

**Purpose**: Validate the Windows field mapping registry and backend field mapper.

**Tests**:
- `tests/test_fields_windows.py` — Field mapping model validation, registry operations, namespace validation
- `tests/test_backend_field_mapping.py` — Backend integration, mode-dependent behavior, legacy compatibility

**Fail Conditions**:
- Any test fails in either file
- Registry lookup returns unexpected results
- Field mapping models are invalid (namespace mismatch, missing products, etc.)
- Backend mapper mode validation fails (strict/warn/legacy)
- Backward compatibility broken

**Sample Success Output**:
```
tests/test_fields_windows.py::TestFieldMapping::test_field_mapping_system_namespace PASSED
tests/test_fields_windows.py::TestFieldMappingRegistry::test_registry_lookup_found PASSED
tests/test_backend_field_mapping.py::TestSigmaFieldMapperIntegration::test_field_mapper_uses_registry PASSED
```

---

## Gate 2: Decoded Fixture Verification

**Status**: `decoded-fixture-verification`

**Purpose**: Verify that all VERIFIED field mappings with `DECODED_FIXTURE` verification source have corresponding fixture evidence.

**Validation**:
- Enumerate all field mappings with `confidence=VERIFIED` and `verification_source=DECODED_FIXTURE`
- Check that fixtures exist in `tests/fixtures/wazuh/windows/`
- Verify fixture paths are exact and consistent
- Report any VERIFIED mappings missing fixture evidence

**Fail Conditions**:
- Fixtures directory doesn't exist or is empty
- VERIFIED mapping marked as `DECODED_FIXTURE` has no corresponding fixture file
- Fixture path structure is inconsistent (should match namespace/event type)

**Sample Success Output**:
```
✓ All 42 VERIFIED mappings have fixture evidence
✓ Found 9 fixture files
✓ Fixture paths are consistent
```

**Sample Failure Output**:
```
WARNING: 3 VERIFIED mappings missing fixture evidence:
  - LogonType -> win.eventdata.logonType
  - QueryName -> win.eventdata.queryName
  - SourcePort -> win.eventdata.sourcePort
```

---

## Gate 3: Full Corpus Field Audit

**Status**: `full-corpus-field-audit`

**Purpose**: Audit the complete field inventory and detect unsupported Windows fields in the registry.

**Validation**:
- Count total field mappings and categorize by confidence level
- Count fields by namespace (system vs. eventdata)
- Detect unsupported Windows fields (fields that exist in rules but not in registry)
- Verify no orphaned or duplicate field definitions

**Fail Conditions**:
- Unsupported Windows fields detected in registry
- Field inventory audit reports consistency issues
- Total mapping count changes unexpectedly (indicates incomplete migration)
- Namespace distribution anomalies

**Sample Success Output**:
```
Field Inventory Audit Report
============================
Total mappings: 127
  - VERIFIED: 42
  - PROVISIONAL: 85
Namespaces:
  - system: 8
  - eventdata: 119
✓ No unsupported Windows fields detected in registry
✓ Field inventory audit passed
```

---

## Gate 4: Strict Conversion Test

**Status**: `strict-conversion-test`

**Purpose**: Perform full ruleset conversion in strict mode and reject any rules with unknown or rejected fields.

**Validation**:
- Convert entire `examples/sigma` directory using `--field-mapping-mode strict`
- Generate conversion report
- Parse conversion output for rejected rules or unknown field errors
- Fail if any rules are rejected or unsupported fields are encountered

**Fail Conditions**:
- Any Sigma rule is rejected during conversion
- Unknown Windows fields are encountered and cannot be mapped
- Conversion mode is not strict (UnsupportedWindowsFieldError must be raised)
- Conversion terminates with non-zero exit code

**Sample Success Output**:
```
Converting sigma rules from examples/sigma
✓ Strict mode conversion completed without rejected rules
Generated: 127 rules
Conversion time: 2.34s
```

**Sample Failure Output**:
```
ERROR: Strict mode conversion found rejected rules or unknown fields
Rule sigma_0001: Unknown field 'UnsupportedWindowsField' (product=windows)
Rejection reason: Field cannot be mapped in strict mode
```

---

## Gate 5: Native Wazuh Validation

**Status**: `native-wazuh-validation`

**Purpose**: Validate generated XML against Wazuh schema and business rules.

**Validation**:
- Parse generated XML for well-formedness
- Count rules and verify structure
- Check rule IDs are within configured range
- Validate all rule levels are 0-15
- Verify all field names follow `win.{namespace}.{fieldName}` pattern
- Optional: Run `wazuh-analysisd -t` in Docker container (future enhancement)

**Fail Conditions**:
- XML is malformed or not well-formed
- Rule level is outside 0-15 range
- Rule ID format is invalid
- Field names don't match `win.*` pattern
- XML schema violations detected

**Sample Success Output**:
```
✓ XML is well-formed
✓ Found 127 rules
✓ All rules have valid levels (0-15)
✓ Native Wazuh XML validation passed
```

**Sample Failure Output**:
```
ERROR: Rule 900123 has invalid level 16
ERROR: Rule 900124 has non-numeric level: "critical"
✗ Found 2 validation issues
```

---

## Gate 6: End-to-End Fixture Tests

**Status**: `end-to-end-fixture-tests`

**Purpose**: Validate that generated Wazuh rules correctly match event fixture data.

**Tests**:
- `tests/test_evtx_end_to_end.py` — Rule field existence, capitalization matching, pattern matching against fixtures

**Validation**:
- For each fixture (Sysmon, Security logon, DNS, Application error), verify:
  - All generated field paths exist in the fixture
  - Field name capitalization matches fixture exactly
  - Rule patterns match expected field values

**Fail Conditions**:
- Generated field path doesn't exist in fixture
- Field capitalization doesn't match fixture (e.g., `eventid` vs. `eventID`)
- Regex pattern doesn't match expected value
- Fixture loading fails or fixture is missing
- Field traversal fails at any level

**Sample Success Output**:
```
tests/test_evtx_end_to_end.py::TestSysmonProcessCreationE2E::test_sysmon_field_paths_are_correct PASSED
tests/test_evtx_end_to_end.py::TestSysmonProcessCreationE2E::test_sysmon_capitalization_matches_fixture PASSED
tests/test_evtx_end_to_end.py::TestSecurityLogonE2E::test_security_logon_fields_exist PASSED
```

**Sample Failure Output**:
```
AssertionError: win.eventdata.image: Field not found in fixture
Expected: C:\Windows\System32\cmd.exe
Actual: Field path not found
```

---

## Gate Dependencies and Ordering

Gates run in sequence with dependencies:

```
1. field-registry-unit-tests (no dependency)
   ↓
2. decoded-fixture-verification (depends on passing gate 1)
   ↓
3. full-corpus-field-audit (depends on gates 1-2)
   ↓
4. strict-conversion-test (depends on gates 1-3)
   ↓
5. native-wazuh-validation (depends on gate 4)
   ↓
6. end-to-end-fixture-tests (depends on gates 4-5)
```

If any gate fails, subsequent gates are still executed (for full visibility) but the overall job fails.

---

## Configuration

### Environment Variables

None required. All gates use built-in paths and configurations.

### Files and Directories

- **Registry**: `src/wazuh_sigma/fields/windows.py` (WINDOWS_FIELD_MAPPINGS)
- **Tests**: `tests/test_fields_windows.py`, `tests/test_backend_field_mapping.py`, `tests/test_evtx_end_to_end.py`
- **Fixtures**: `tests/fixtures/wazuh/windows/*.json`
- **Sigma Examples**: `examples/sigma/`
- **Output**: `build/sigma_rules_strict.xml`, `build/conversion-report-strict.json`

### Modes and Constraints

- **Field Mapping Mode**: `strict` (any unknown field causes conversion failure)
- **Confidence Levels**: `VERIFIED` mappings expected for core fields; `PROVISIONAL` for extended fields
- **Namespaces**: `system` (Event/System elements), `eventdata` (Event/EventData elements)
- **Rule Level Range**: 0-15
- **Rule ID Range**: Configured in `ci/pipeline.yml` (default: 900000-949999)

---

## Adding New Fields or Mappings

When adding a new Windows field mapping:

1. **Add to registry** (`src/wazuh_sigma/fields/windows.py`):
   - Include full `FieldMapping` with all metadata
   - Use `confidence=ConfidenceLevel.PROVISIONAL` initially
   - Provide documentation reference and notes

2. **Add fixture evidence** (if confidence=VERIFIED):
   - Add fixture JSON to `tests/fixtures/wazuh/windows/`
   - Ensure fixture includes the field in decoded form
   - Gate 2 will verify the fixture exists

3. **Add unit tests**:
   - Add test case to `tests/test_fields_windows.py`
   - Test registry lookup, resolution, and validation
   - Test backend mapper integration

4. **Add end-to-end test** (if applicable):
   - Add Sigma rule to `examples/sigma/` that uses the field
   - Verify it converts without errors in strict mode
   - Gate 4 will validate the conversion

5. **Run gates locally**:
   ```bash
   python -m pytest tests/test_fields_windows.py tests/test_backend_field_mapping.py
   python -m wazuh_sigma.converter.cli --directory examples/sigma --output build/test.xml --field-mapping-mode strict
   python -m pytest tests/test_evtx_end_to_end.py
   ```

---

## Troubleshooting

### Gate 1 Failures (Unit Tests)

**Problem**: Field mapping test fails
- Verify field is in `WINDOWS_FIELD_MAPPINGS`
- Check namespace matches field prefix (`win.system.*` vs. `win.eventdata.*`)
- Verify products tuple is not empty

**Problem**: Backend mapper test fails
- Check mode is valid: `strict`, `warn`, or `legacy`
- Verify registry is initialized with WINDOWS_FIELD_MAPPINGS
- Check backward compatibility: `map_field()` static method must work

### Gate 2 Failures (Fixture Verification)

**Problem**: VERIFIED mapping has no fixture
- Add fixture JSON to `tests/fixtures/wazuh/windows/`
- Change mapping to `confidence=ConfidenceLevel.PROVISIONAL` if no fixture available
- Change `verification_source` if not using DECODED_FIXTURE

### Gate 3 Failures (Field Audit)

**Problem**: Unsupported Windows fields detected
- Remove or reclassify the offending field
- Ensure all fields in registry are documented

### Gate 4 Failures (Strict Conversion)

**Problem**: Rule rejected in strict mode
- Check rule uses only supported Windows fields
- Add missing field to registry
- Reduce mapping confidence to PROVISIONAL if unsure

### Gate 5 Failures (Wazuh Validation)

**Problem**: Invalid rule level
- Levels must be 0-15
- Check advisor or policy doesn't set level > 15

**Problem**: XML is malformed
- Check backend code for XML generation bugs
- Validate field names use `win.` prefix

### Gate 6 Failures (Fixture Tests)

**Problem**: Field not found in fixture
- Check fixture has the field decoded
- Verify capitalization: camelCase in fixture, lowercase in path

**Problem**: Capitalization mismatch
- Fixture uses actual Windows field capitalization
- Generated rule field path must match exactly
- Common issue: `eventid` (wrong) vs. `eventID` (correct)

---

## Dashboard and Monitoring

Gates are monitored via GitHub Actions:
- **Job**: `windows-field-mapping`
- **Artifact**: `windows-field-mapping-results` (XML, report, logs)
- **Status**: Badge in README showing pass/fail

For continuous monitoring, subscribe to:
- GitHub Actions notifications
- PR status checks (required before merge)
- Artifact downloads for detailed reports
