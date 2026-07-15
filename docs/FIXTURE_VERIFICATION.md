# Fixture Verification Engine

This document describes the fixture verification engine, which validates field mappings against real Windows event fixtures with exact case-sensitive matching.

## Overview

The fixture verification engine provides:

1. **Exact case-sensitive field matching** — Never uses `.lower()`. If a field name doesn't match exactly, verification fails with a diagnostic suggestion.
2. **Context-aware lookup** — Verifies fields exist in the correct provider/channel/event_id context.
3. **Structured results** — Returns typed `VerificationResult` objects with status, error message, and suggestions.
4. **Provenance validation** — Checks fixture metadata and evidence documents.
5. **Diagnostic suggestions** — Provides near-matches for case mismatches or similar fields.

## Core Concept: Exact Case Matching

This engine **never uses case-insensitive comparisons**. The forbidden pattern:

```python
# FORBIDDEN
if field.lower() == expected.lower():
    return True  # WRONG - allows case mismatches
```

Instead, all lookups are exact:

```python
# REQUIRED
if field != expected:
    return CaseMismatchError(field, expected)
```

This is essential because Windows event fields are case-sensitive in Wazuh's decoder output.

## Module Structure

```
src/wazuh_sigma/fixtures/
├── __init__.py              # Public API exports
├── errors.py                # Custom exceptions
├── models.py                # Typed data models
├── loader.py                # Load and validate fixtures
├── catalogue.py             # Build and query fixture index
├── verifier.py              # Verify fields against fixtures
└── provenance.py            # Validate provenance and evidence
```

## Quick Start

### 1. Load Fixtures

```python
from wazuh_sigma.fixtures import build_fixture_catalogue

# Scan fixture directory
catalogue = build_fixture_catalogue("tests/fixtures/wazuh")

# Now you have indexed fixtures
print(f"Loaded {catalogue.size()} fixtures")
```

### 2. Verify a Field

```python
from wazuh_sigma.fixtures import verify_exact_path

result = verify_exact_path(
    field_name="win.system.eventID",
    catalogue=catalogue,
    provider="Microsoft-Windows-Security-Auditing",
    channel="Security",
    event_id=4624,
)

if result.is_verified():
    print(f"✓ Field verified in {result.fixture}")
else:
    print(f"✗ {result.status}: {result.error}")
    if result.suggestion:
        print(f"  Did you mean: {result.suggestion}?")
```

### 3. Check Fixture Provenance

```python
from wazuh_sigma.fixtures import validate_and_check_evidence

status = validate_and_check_evidence(
    entry=catalogue_entry,
    evidence_base_dir="docs/fixture-evidence",
    require_evidence=False,
)

if status["provenance_valid"]:
    print("✓ Provenance is valid")
else:
    print(f"✗ Errors: {status['errors']}")
```

## Data Models

### FixtureMetadata

Metadata extracted from a fixture's `_fixture_metadata` section:

```python
@dataclass(frozen=True)
class FixtureMetadata:
    fixture_schema_version: str       # "wazuh-windows-fixture-v1"
    wazuh_version: str                # "4.14.6"
    windows_version: str              # "Windows 11 23H2"
    provider: str                     # e.g., "Microsoft-Windows-Security-Auditing"
    channel: str                      # e.g., "Security"
    event_id: int                     # e.g., 4624
    source_type: str                  # captured_wazuh_alert, official_microsoft_docs, etc.
    capture_method: str               # How the fixture was captured
    captured_at: str                  # ISO8601 timestamp
    sanitized: bool                   # Whether values are sanitized
    sanitization_notes: str           # What was sanitized
    source_sha256: str                # SHA256 of original
    evidence_reference: str           # Path to evidence document
```

### FixtureCatalogueEntry

A loaded fixture with all fields indexed:

```python
@dataclass(frozen=True)
class FixtureCatalogueEntry:
    fixture_path: str                           # /path/to/fixture.json
    metadata: FixtureMetadata                   # Metadata object
    all_fields: frozenset[str]                  # All field paths (case-sensitive)
```

### VerificationResult

Result of verification with full diagnostic info:

```python
@dataclass(frozen=True)
class VerificationResult:
    status: Literal[
        "verified",          # Field found with exact case
        "unverified",        # Field not found
        "case_mismatch",     # Field exists with different case
        "context_mismatch",  # No fixture for this context
    ]
    fixture: Optional[str]              # Path to fixture used
    field: str                          # Field being verified
    provider: Optional[str]             # Provider from fixture
    channel: Optional[str]              # Channel from fixture
    event_id: Optional[int]             # Event ID from fixture
    error: Optional[str]                # Error message (None if verified)
    suggestion: Optional[str]           # Diagnostic suggestion
```

## Key Functions

### verify_exact_path()

Verify a field exists in a specific fixture context with exact case matching.

```python
def verify_exact_path(
    field_name: str,
    catalogue: FixtureCatalogue,
    provider: str,
    channel: str,
    event_id: int,
) -> VerificationResult:
    """Verify field exists in fixture with exact case and context.
    
    Returns "verified" only if:
    - Fixture exists for (provider, channel, event_id)
    - Field exists with EXACT case match
    
    Returns "case_mismatch" if field exists with different case.
    Returns "context_mismatch" if no fixture for this context.
    Returns "unverified" if field not found anywhere.
    """
```

### verify_mapping_against_fixtures()

Verify a field across multiple fixtures (more permissive).

```python
def verify_mapping_against_fixtures(
    field_name: str,
    catalogue: FixtureCatalogue,
    provider: Optional[str] = None,
    channel: Optional[str] = None,
    event_id: Optional[int] = None,
) -> VerificationResult:
    """Verify field mapping across matching fixtures.
    
    If specific context provided, verify against that fixture.
    Otherwise, search across all matching fixtures.
    
    Still rejects case mismatches.
    """
```

### find_case_insensitive_match()

Find a field with same name but different case (diagnostic only).

```python
def find_case_insensitive_match(
    field_name: str,
    available_fields: frozenset[str],
) -> Optional[str]:
    """Find field with same name but different case.
    
    Used only for diagnostics. Never returns as verified.
    """
```

### find_similar_fields()

Find similar fields using difflib (diagnostic suggestions).

```python
def find_similar_fields(
    field_name: str,
    catalogue: FixtureCatalogue,
    max_suggestions: int = 3,
) -> list[str]:
    """Find fields similar to input.
    
    Used for diagnostic suggestions only.
    Never passes verification unless exact match.
    """
```

### build_fixture_catalogue()

Recursively scan a directory and load all fixtures.

```python
def build_fixture_catalogue(
    fixture_dir: str | Path
) -> FixtureCatalogue:
    """Build fixture catalogue by scanning directory.
    
    Invalid/malformed fixtures are skipped with logging.
    Returns catalogue with all successfully loaded fixtures.
    """
```

### validate_and_check_evidence()

Validate provenance metadata and check evidence document existence.

```python
def validate_and_check_evidence(
    entry: FixtureCatalogueEntry,
    evidence_base_dir: Optional[str | Path] = None,
    require_evidence: bool = False,
) -> dict[str, bool]:
    """Validate provenance and check evidence.
    
    Returns:
    {
        "provenance_valid": bool,
        "evidence_exists": bool,
        "errors": list of error messages
    }
    """
```

## Fixture File Format

Fixtures are JSON files with a structure and metadata:

```json
{
  "win": {
    "system": {
      "eventID": 4624,
      "channel": "Security",
      "computer": "WORKSTATION01",
      "providerName": "Microsoft-Windows-Security-Auditing"
    },
    "eventdata": {
      "targetUserName": "admin",
      "targetUserSid": "S-1-5-21-...",
      "logonType": "2"
    }
  },
  "_fixture_metadata": {
    "fixture_schema_version": "wazuh-windows-fixture-v1",
    "wazuh_version": "4.14.6",
    "windows_version": "Windows 11 23H2",
    "provider": "Microsoft-Windows-Security-Auditing",
    "channel": "Security",
    "event_id": 4624,
    "source_type": "captured_wazuh_alert",
    "capture_method": "archives.json",
    "captured_at": "2026-07-13T16:33:47.836987Z",
    "sanitized": true,
    "sanitization_notes": "Hostnames, usernames, IPs replaced",
    "source_sha256": "90f9706c04858cce49a2e5d0993a7ef1...",
    "evidence_reference": "docs/fixture-evidence/4624.md"
  }
}
```

## Error Handling

The module defines specific exception types for different failure modes:

```python
# Case mismatch - field exists but wrong case
from wazuh_sigma.fixtures import CaseMismatchError

# Context mismatch - field in wrong provider
from wazuh_sigma.fixtures import ContextMismatchError

# Missing evidence document
from wazuh_sigma.fixtures import MissingEvidenceError

# Invalid schema version
from wazuh_sigma.fixtures import InvalidFixtureSchemaError

# Invalid source_type
from wazuh_sigma.fixtures import InvalidFixtureSourceTypeError

# Missing metadata field
from wazuh_sigma.fixtures import MissingFixtureMetadataError

# Fixture lookup failed
from wazuh_sigma.fixtures import FixtureLookupError
```

## Verification Workflow

The typical verification workflow is:

```python
from wazuh_sigma.fixtures import (
    build_fixture_catalogue,
    verify_exact_path,
    validate_and_check_evidence,
)

# 1. Load fixtures
catalogue = build_fixture_catalogue("tests/fixtures/wazuh")

# 2. Verify field mapping
result = verify_exact_path(
    field_name="win.system.eventID",
    catalogue=catalogue,
    provider="Microsoft-Windows-Security-Auditing",
    channel="Security",
    event_id=4624,
)

if result.is_verified():
    print(f"✓ Verified: {result.field}")
    
    # 3. Optional: Check fixture provenance
    fixture = catalogue.lookup_exact(
        provider=result.provider,
        channel=result.channel,
        event_id=result.event_id,
    )
    
    status = validate_and_check_evidence(fixture)
    if status["provenance_valid"]:
        print("✓ Provenance valid")
else:
    print(f"✗ {result.status}")
    if result.suggestion:
        print(f"  Suggestion: {result.suggestion}")
```

## Case Sensitivity Rules

### MUST: Exact case matching

```python
# ✓ CORRECT - exact comparison
if field == "win.system.eventID":
    ...

# ✗ WRONG - case-insensitive comparison
if field.lower() == "win.system.eventid":
    ...
```

### MUST: Preserve case in diagnostics

When suggesting corrections, preserve the exact case from the fixture:

```python
# If fixture has "win.system.eventID" but user provided "win.system.eventid":
suggestion = "win.system.eventID"  # Exact case from fixture
```

### MUST NOT: Accept case-mismatched fields

Never pass verification for fields that differ only in case:

```python
result = verify_exact_path("win.system.eventid", ...)  # lowercase
assert result.status == "case_mismatch"
assert result.is_verified() == False  # Never verified!
```

## Testing

Run the fixture verification tests:

```bash
python -m pytest tests/test_fixtures_verification.py -v
```

Test coverage includes:

- Fixture loading and schema validation
- Case-sensitive field extraction
- Exact path verification
- Case mismatch detection
- Context mismatch detection
- Provenance validation
- Evidence document checking
- Similar field suggestions

## Integration with Field Mapping

The fixture verification engine integrates with the field mapping registry to validate mappings:

```python
from wazuh_sigma.fields import FieldMappingRegistry
from wazuh_sigma.fixtures import verify_exact_path, build_fixture_catalogue

# Create mapping registry
registry = FieldMappingRegistry()

# Load fixture catalogue
catalogue = build_fixture_catalogue("tests/fixtures/wazuh")

# Verify a mapping
mapping = registry.get_mapping("EventID", product="windows")
if mapping:
    result = verify_exact_path(
        field_name=mapping.wazuh_field,
        catalogue=catalogue,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4624,
    )
    
    if result.is_verified():
        print(f"✓ Mapping verified against fixture")
    else:
        print(f"✗ Mapping verification failed: {result.error}")
```

## Future Enhancements

Potential improvements to the fixture verification engine:

1. **Batch verification** — Verify multiple fields/mappings in one pass
2. **Performance optimization** — Cache catalogue in memory
3. **Evidence document parsing** — Load and validate evidence markdown files
4. **Fixture generation** — Create fixtures from real Wazuh alerts
5. **Diff reporting** — Show exact differences between expected and actual fields
