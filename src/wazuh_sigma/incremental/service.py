"""Incremental conversion orchestration service."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

from wazuh_sigma.incremental.cache import ConversionCache
from wazuh_sigma.incremental.errors import ConversionCacheError, DuplicateRuleIdentityError, ManifestCorruptionError
from wazuh_sigma.incremental.fingerprint import compute_conversion_fingerprint
from wazuh_sigma.incremental.identity import derive_rule_identity
from wazuh_sigma.incremental.manifest import ManifestManager
from wazuh_sigma.incremental.models import CacheEntry, RuleManifest
from wazuh_sigma.sigma import SigmaRule

logger = logging.getLogger("SigmaIncremental.service")


@dataclass(frozen=True)
class ConversionCacheStatus:
    """Status of conversion for a single rule."""

    rule_identity: str
    identity_source: str
    fingerprint: str
    wazuh_rule_id: int
    cached: bool  # True if using cached fragment
    xml_fragment: str


class IncrementalConverterService:
    """Orchestrate incremental conversion with caching and persistent IDs."""

    def __init__(
        self,
        cache_dir: Path | str,
        manifest_file: Path | str,
        *,
        enabled: bool = True,
        field_mapping_version: str = "default",
        backend_output_version: str = "wazuh-xml-v1",
        rule_id_range: tuple[int, int] = (900000, 999999),
        field_mapping: dict[str, str] | None = None,
        backend_settings: dict[str, Any] | None = None,
        strict_cache: bool = False,
    ):
        self.enabled = enabled
        self.field_mapping_version = field_mapping_version
        self.backend_output_version = backend_output_version
        self.rule_id_range = rule_id_range
        self.field_mapping = field_mapping or {}
        self.backend_settings = backend_settings or {}
        self.strict_cache = strict_cache
        self.cache = ConversionCache(cache_dir, enabled=enabled, strict=strict_cache)
        self.manifest_manager = ManifestManager(manifest_file)
        if enabled and not Path(manifest_file).exists() and self._has_existing_cache_entries():
            raise ManifestCorruptionError(
                "incremental manifest is missing while conversion cache entries exist; "
                "refusing to allocate fresh IDs because this could conflict with prior output"
            )
        self.manifest = self.manifest_manager.load()
        if not self.manifest.active and not self.manifest.retired:
            self.manifest.next_id = rule_id_range[0]
        self.manifest.field_mapping_version = field_mapping_version
        self.manifest.backend_output_version = backend_output_version
        self.manifest_manager.check_final_integrity(self.manifest)
        self._processed_identities: set[str] = set()
        self.cache_hits = 0
        self.cache_misses = 0

    def process_rule(
        self,
        sigma_rule: SigmaRule,
        source_path: str | None = None,
        advisor_level_override: int | None = None,
    ) -> tuple[ConversionCacheStatus, Element | None]:
        """Process a rule: check cache, allocate ID, validate fragment.

        Returns: (status, xml_element)

        xml_element is None if cached fragment validation failed (cache miss).
        The element is not ready for final assembly; it will be re-serialized.
        """
        if not self.enabled:
            raise RuntimeError("incremental service disabled")

        # Derive stable identity
        rule_identity, identity_source = derive_rule_identity(
            sigma_rule,
            source_path=source_path,
        )
        if rule_identity in self._processed_identities:
            raise DuplicateRuleIdentityError(
                f"duplicate rule identity in current conversion run: {rule_identity}"
            )
        self._processed_identities.add(rule_identity)

        # Compute fingerprint
        fingerprint = compute_conversion_fingerprint(
            sigma_rule,
            wazuh_rule_id=900000,  # Placeholder; real ID will be allocated below
            field_mapping_version=self.field_mapping_version,
            field_mapping=self.field_mapping,
            backend_output_version=self.backend_output_version,
            rule_id_range=self.rule_id_range,
            advisor_level_override=advisor_level_override,
            backend_settings=self.backend_settings,
        )

        # Allocate or reuse rule ID
        self.manifest, wazuh_rule_id = self.manifest_manager.validate_and_update(
            self.manifest,
            rule_identity,
            source_path or sigma_rule.source_file or "unknown",
            fingerprint,
            identity_source,
            rule_id_range=self.rule_id_range,
        )

        # Recompute fingerprint with real ID
        fingerprint = compute_conversion_fingerprint(
            sigma_rule,
            wazuh_rule_id=wazuh_rule_id,
            field_mapping_version=self.field_mapping_version,
            field_mapping=self.field_mapping,
            backend_output_version=self.backend_output_version,
            rule_id_range=self.rule_id_range,
            advisor_level_override=advisor_level_override,
            backend_settings=self.backend_settings,
        )
        self.manifest.active[rule_identity].fingerprint = fingerprint

        # Try to use cached fragment
        cached_entry = self.cache.get(fingerprint)
        if cached_entry:
            try:
                xml_str = self.cache.validate_fragment(cached_entry, wazuh_rule_id)
                logger.info(
                    "Using cached fragment for rule %s (ID %d)",
                    sigma_rule.title,
                    wazuh_rule_id,
                )
                status = ConversionCacheStatus(
                    rule_identity=rule_identity,
                    identity_source=identity_source,
                    fingerprint=fingerprint,
                    wazuh_rule_id=wazuh_rule_id,
                    cached=True,
                    xml_fragment=xml_str,
                )
                self.cache_hits += 1
                return status, None
            except ConversionCacheError as e:
                if self.strict_cache:
                    raise
                logger.warning(
                    "Cached fragment for rule %s is invalid: %s; reconverting",
                    sigma_rule.title,
                    e,
                )

        # Cache miss; signal for caller to convert.
        self.cache_misses += 1
        status = ConversionCacheStatus(
            rule_identity=rule_identity,
            identity_source=identity_source,
            fingerprint=fingerprint,
            wazuh_rule_id=wazuh_rule_id,
            cached=False,
            xml_fragment="",
        )
        return status, None

    def store_converted_fragment(
        self,
        status: ConversionCacheStatus,
        xml_fragment: str,
        sigma_title: str,
    ) -> None:
        """Store a freshly converted XML fragment in cache."""
        if not self.enabled:
            return

        entry = CacheEntry(
            rule_identity=status.rule_identity,
            source_path=self.manifest.active[status.rule_identity].source_path,
            fingerprint=status.fingerprint,
            wazuh_rule_id=status.wazuh_rule_id,
            sigma_title=sigma_title,
            xml_fragment=xml_fragment,
            metadata={
                "field_mapping_version": self.field_mapping_version,
                "backend_output_version": self.backend_output_version,
            },
        )
        self.cache.put(entry)

    def finalize_manifest(
        self,
        current_identities: set[str],
    ) -> RuleManifest:
        """Detect deletions and finalize manifest state."""
        if not self.enabled:
            raise RuntimeError("incremental service disabled")

        # Move deleted identities to retired
        self.manifest = self.manifest_manager.detect_deleted_identities(
            current_identities,
            self.manifest,
        )

        # Verify integrity
        self.manifest_manager.check_final_integrity(self.manifest)

        return self.manifest

    def save_manifest(self) -> None:
        """Atomically persist manifest."""
        if not self.enabled:
            return
        self.manifest_manager.save(self.manifest)

    def get_report_data(self) -> dict[str, Any]:
        """Generate incremental conversion report data."""
        if not self.enabled:
            return {}

        return {
            "enabled": True,
            "manifest_version": self.manifest.schema_version,
            "id_allocation_version": self.manifest.id_allocation_version,
            "backend_output_version": self.manifest.backend_output_version,
            "next_id": self.manifest.next_id,
            "active_rules": len(self.manifest.active),
            "retired_rules": len(self.manifest.retired),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
        }

    def _has_existing_cache_entries(self) -> bool:
        entries_dir = self.cache.entries_dir
        return entries_dir.is_dir() and any(entries_dir.glob("*.json"))
