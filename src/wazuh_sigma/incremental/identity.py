"""Deterministic rule identity derivation."""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Literal

from wazuh_sigma.sigma import SigmaRule

logger = logging.getLogger("SigmaIncremental.identity")


def derive_rule_identity(sigma_rule: SigmaRule, source_path: str | None = None) -> tuple[str, Literal["sigma_uuid", "fallback_hash"]]:
    """Derive stable rule identity from Sigma rule.

    Preferred: Sigma UUID (if present and valid).
    Fallback: SHA-256 of canonical relative path + title.

    Returns: (identity, source) where source is "sigma_uuid" or "fallback_hash".
    """
    # Try Sigma UUID first, but only when it is actually a valid UUID.
    rule_id = sigma_rule.raw_rule.get("id")
    if rule_id and _is_valid_uuid(str(rule_id)):
        logger.debug(
            "Using Sigma UUID as identity for rule %s: %s",
            sigma_rule.title,
            rule_id,
        )
        return str(rule_id), "sigma_uuid"
    if rule_id:
        logger.warning(
            "Ignoring invalid Sigma UUID for rule %s and using fallback identity: %s",
            sigma_rule.title,
            rule_id,
        )

    # Fallback to hash of path + title
    path = source_path or sigma_rule.source_file or "unknown"
    canonical_path = path.replace("\\", "/")  # Normalize for cross-platform consistency
    key_material = f"{canonical_path}:{sigma_rule.title}"
    identity = hashlib.sha256(key_material.encode("utf-8")).hexdigest()
    logger.warning(
        "Using fallback identity hash for rule %s (no Sigma UUID): %s",
        sigma_rule.title,
        identity,
    )
    return identity, "fallback_hash"


def _is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except (TypeError, ValueError):
        return False
    return True
