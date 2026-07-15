"""Persistent rule identity and Wazuh ID allocation manifest."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from wazuh_sigma.incremental.errors import (
    DuplicateRuleIDError,
    DuplicateRuleIdentityError,
    ManifestCorruptionError,
    ManifestError,
    RuleIDRangeExhaustedError,
)
from wazuh_sigma.incremental.models import RuleManifest
from wazuh_sigma.reporting import write_text_artifact

logger = logging.getLogger("SigmaIncremental.manifest")


class ManifestManager:
    """Load, validate, and persist rule manifests."""

    def __init__(self, manifest_file: Path | str):
        self.manifest_file = Path(manifest_file)

    def load(self) -> RuleManifest:
        """Load existing manifest or create empty one."""
        if not self.manifest_file.exists():
            logger.info("Creating new manifest at %s", self.manifest_file)
            return RuleManifest(
                field_mapping_version="unknown",
                next_id=900000,
            )

        try:
            payload = json.loads(self.manifest_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise ManifestCorruptionError(f"manifest file is unreadable: {e}") from e

        try:
            return RuleManifest.model_validate(payload)
        except ValidationError as e:
            raise ManifestCorruptionError(f"manifest is invalid: {e}") from e

    def save(self, manifest: RuleManifest) -> None:
        """Atomically write manifest to file."""
        try:
            payload = manifest.model_dump(mode="json")
            serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
            write_text_artifact(self.manifest_file, serialized)
            logger.info("Saved manifest to %s", self.manifest_file)
        except (OSError, TypeError, ValueError) as e:
            raise ManifestError(f"failed to save manifest: {e}") from e

    def validate_and_update(
        self,
        manifest: RuleManifest,
        rule_identity: str,
        source_path: str,
        fingerprint: str,
        identity_source: Literal["sigma_uuid", "fallback_hash"],
        wazuh_rule_id: int | None = None,
        rule_id_range: tuple[int, int] | None = None,
    ) -> tuple[RuleManifest, int]:
        """Validate manifest state and allocate or reuse a rule ID.

        Returns: (updated_manifest, allocated_wazuh_rule_id)
        """
        # Check for duplicate identity in active rules
        if rule_identity in manifest.active:
            existing = manifest.active[rule_identity]
            logger.debug(
                "Reusing existing ID %d for rule identity %s",
                existing.wazuh_rule_id,
                rule_identity,
            )
            # Update entry (may have different source path)
            existing.source_path = source_path
            existing.fingerprint = fingerprint
            return manifest, existing.wazuh_rule_id

        # Check for duplicate identity in retired rules
        if rule_identity in manifest.retired:
            raise DuplicateRuleIdentityError(
                f"rule identity {rule_identity} was previously retired; "
                "cannot reuse across complete deletions"
            )

        # Allocate new ID
        if rule_id_range is None:
            raise ValueError("rule_id_range required for new ID allocation")

        start_id, end_id = rule_id_range
        if manifest.next_id > end_id:
            raise RuleIDRangeExhaustedError(
                f"exhausted rule ID range: next_id={manifest.next_id} > end_id={end_id}"
            )

        new_id = manifest.allocate_id_for_identity(
            rule_identity,
            source_path,
            fingerprint,
            identity_source,
            end_id,
        )
        logger.debug("Allocated new ID %d for rule identity %s", new_id, rule_identity)
        return manifest, new_id

    def detect_deleted_identities(
        self,
        current_identities: set[str],
        manifest: RuleManifest,
    ) -> RuleManifest:
        """Move identities not in current set to retired."""
        deleted = set(manifest.active.keys()) - current_identities
        for rule_identity in deleted:
            entry = manifest.active[rule_identity]
            logger.info(
                "Retiring deleted rule identity %s (was ID %d)",
                rule_identity,
                entry.wazuh_rule_id,
            )
            manifest.retire_identity(rule_identity, entry.wazuh_rule_id)
        return manifest

    def check_final_integrity(self, manifest: RuleManifest) -> None:
        """Verify no duplicates in final active or retired states."""
        # Check for duplicate IDs in active rules
        active_ids = [e.wazuh_rule_id for e in manifest.active.values()]
        if len(active_ids) != len(set(active_ids)):
            duplicates = [
                id_ for id_ in set(active_ids) if active_ids.count(id_) > 1
            ]
            raise DuplicateRuleIDError(f"duplicate rule IDs in manifest: {duplicates}")

        # Check for ID collisions between active and retired
        active_ids_set = set(active_ids)
        retired_ids = [e.wazuh_rule_id for e in manifest.retired.values()]
        collisions = active_ids_set & set(retired_ids)
        if collisions:
            raise ManifestError(f"rule IDs appear in both active and retired: {collisions}")

        allocated_ids = active_ids + retired_ids
        if allocated_ids and manifest.next_id <= max(allocated_ids):
            raise ManifestError(
                "manifest next_id would reuse an allocated or retired rule ID: "
                f"next_id={manifest.next_id}, max_allocated={max(allocated_ids)}"
            )
