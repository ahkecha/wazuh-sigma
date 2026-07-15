"""Fixture verification engine for field mapping validation.

This module provides tools to:
1. Load and validate Windows event fixtures from JSON
2. Build a searchable catalogue of fixtures
3. Verify field mappings against fixtures with exact case matching
4. Check fixture provenance and evidence

Key features:
- Exact case-sensitive field name matching (NEVER uses .lower())
- Structured verification results with diagnostic suggestions
- Context-aware lookups (provider, channel, event_id)
- Provenance validation and evidence checking
"""

from .catalogue import (
    FixtureCatalogue,
    build_fixture_catalogue,
    lookup_fixture,
)
from .errors import (
    CaseMismatchError,
    ContextMismatchError,
    FixtureLookupError,
    FixtureValidationError,
    InvalidFixtureSchemaError,
    InvalidFixtureSourceTypeError,
    MissingEvidenceError,
    MissingFixtureMetadataError,
)
from .loader import (
    extract_all_fields,
    load_fixture,
    load_fixture_catalogue_entry,
    validate_fixture_schema,
)
from .models import (
    FixtureCatalogueEntry,
    FixtureMetadata,
    FixtureSourceType,
    FieldPath,
    VerificationResult,
)
from .provenance import (
    check_evidence_document,
    validate_and_check_evidence,
    validate_provenance,
)
from .verifier import (
    find_case_insensitive_match,
    find_similar_fields,
    verify_exact_path,
    verify_mapping_against_fixtures,
)

__all__ = [
    # Models
    "FixtureCatalogueEntry",
    "FixtureMetadata",
    "FixtureSourceType",
    "FieldPath",
    "VerificationResult",
    # Errors
    "FixtureValidationError",
    "CaseMismatchError",
    "ContextMismatchError",
    "MissingEvidenceError",
    "InvalidFixtureSchemaError",
    "InvalidFixtureSourceTypeError",
    "MissingFixtureMetadataError",
    "FixtureLookupError",
    # Loader
    "load_fixture",
    "validate_fixture_schema",
    "extract_all_fields",
    "load_fixture_catalogue_entry",
    # Catalogue
    "FixtureCatalogue",
    "build_fixture_catalogue",
    "lookup_fixture",
    # Verifier
    "verify_exact_path",
    "verify_mapping_against_fixtures",
    "find_case_insensitive_match",
    "find_similar_fields",
    # Provenance
    "validate_provenance",
    "check_evidence_document",
    "validate_and_check_evidence",
]
