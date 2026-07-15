"""Validate fixture provenance and evidence documents."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from .errors import MissingEvidenceError
from .models import FixtureCatalogueEntry

logger = logging.getLogger(__name__)


def validate_provenance(entry: FixtureCatalogueEntry) -> None:
    """Validate fixture provenance metadata.

    Checks that:
    - fixture_schema_version is recognized
    - source_type is valid (captured_* or official_*)
    - All required metadata fields are present and non-empty
    - Evidence reference is provided

    Args:
        entry: FixtureCatalogueEntry to validate

    Raises:
        ValueError: If provenance is invalid
    """
    metadata = entry.metadata

    if not metadata.fixture_schema_version:
        raise ValueError("fixture_schema_version must not be empty")

    if not metadata.source_type:
        raise ValueError("source_type must not be empty")

    if not metadata.provider:
        raise ValueError("provider must not be empty")

    if not metadata.channel:
        raise ValueError("channel must not be empty")

    if metadata.event_id < 0:
        raise ValueError(f"event_id must be >= 0, got {metadata.event_id}")

    if not metadata.captured_at:
        raise ValueError("captured_at must not be empty")

    if not metadata.source_sha256:
        raise ValueError("source_sha256 must not be empty")

    if not metadata.evidence_reference:
        raise ValueError("evidence_reference must not be empty")

    logger.debug(f"Provenance validation passed for {entry.fixture_path}")


def check_evidence_document(
    entry: FixtureCatalogueEntry,
    evidence_base_dir: Optional[str | Path] = None,
) -> bool:
    """Check if evidence document exists.

    Args:
        entry: FixtureCatalogueEntry with evidence reference
        evidence_base_dir: Base directory for evidence files (optional).
                           If provided, evidence_reference is resolved relative to this.
                           If not provided, evidence_reference is treated as absolute.

    Returns:
        True if evidence document exists, False otherwise

    Raises:
        MissingEvidenceError: If evidence document is required and missing
    """
    reference = entry.metadata.evidence_reference

    if not reference:
        raise MissingEvidenceError(entry.fixture_path, reference)

    if evidence_base_dir:
        evidence_path = Path(evidence_base_dir) / reference
    else:
        evidence_path = Path(reference)

    exists = evidence_path.exists()

    if exists:
        logger.debug(
            f"Evidence document found for {entry.fixture_path}: "
            f"{evidence_path}"
        )
    else:
        logger.warning(
            f"Evidence document missing for {entry.fixture_path}: "
            f"{evidence_path}"
        )

    return exists


def validate_and_check_evidence(
    entry: FixtureCatalogueEntry,
    evidence_base_dir: Optional[str | Path] = None,
    require_evidence: bool = False,
) -> dict[str, bool]:
    """Validate provenance and check evidence document.

    Args:
        entry: FixtureCatalogueEntry to validate
        evidence_base_dir: Base directory for evidence files (optional)
        require_evidence: If True, raise MissingEvidenceError if evidence missing

    Returns:
        Dictionary with validation results:
        {
            "provenance_valid": bool,
            "evidence_exists": bool,
            "errors": list of error messages
        }

    Raises:
        MissingEvidenceError: If require_evidence=True and evidence missing
    """
    errors = []

    try:
        validate_provenance(entry)
        provenance_valid = True
    except ValueError as e:
        provenance_valid = False
        errors.append(f"Provenance validation failed: {e}")

    try:
        evidence_exists = check_evidence_document(
            entry, evidence_base_dir=evidence_base_dir
        )
    except (MissingEvidenceError, OSError) as e:
        evidence_exists = False
        errors.append(f"Evidence check failed: {e}")

    if require_evidence and not evidence_exists:
        raise MissingEvidenceError(
            entry.fixture_path, entry.metadata.evidence_reference
        )

    return {
        "provenance_valid": provenance_valid,
        "evidence_exists": evidence_exists,
        "errors": errors,
    }
