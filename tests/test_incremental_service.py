"""Tests for incremental conversion service."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from tests.advisor_helpers import make_rule
from wazuh_sigma.incremental.cache import ConversionCache
from wazuh_sigma.incremental.errors import (
    ConversionCacheError,
    DuplicateRuleIdentityError,
    ManifestCorruptionError,
    ManifestError,
    RuleIDRangeExhaustedError,
)
from wazuh_sigma.incremental.fingerprint import compute_conversion_fingerprint
from wazuh_sigma.incremental.identity import derive_rule_identity
from wazuh_sigma.incremental.manifest import ManifestManager
from wazuh_sigma.incremental.models import CacheEntry, RuleManifest
from wazuh_sigma.incremental.service import IncrementalConverterService


class TestManifestManager:
    """Manifest loading, saving, and validation tests."""

    def test_create_new_manifest(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "manifest.json"
            manager = ManifestManager(path)
            manifest = manager.load()
            assert manifest.next_id == 900000
            assert len(manifest.active) == 0

    def test_load_existing_manifest(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "manifest.json"
            # Create a manifest
            manifest1 = RuleManifest(field_mapping_version="wazuh-4.14", next_id=900000)
            manifest1.allocate_id_for_identity(
                "test-uuid",
                "rules/test.yml",
                "a" * 64,
                "sigma_uuid",
                999999,
            )
            manager = ManifestManager(path)
            manager.save(manifest1)

            # Load it back
            manifest2 = manager.load()
            assert manifest2.next_id == 900001
            assert "test-uuid" in manifest2.active

    def test_save_manifest_atomic(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "manifest.json"
            manifest = RuleManifest(field_mapping_version="wazuh-4.14", next_id=900000)
            manifest.allocate_id_for_identity(
                "test-uuid",
                "rules/test.yml",
                "a" * 64,
                "sigma_uuid",
                999999,
            )
            manager = ManifestManager(path)
            manager.save(manifest)

            assert path.exists()
            loaded = json.loads(path.read_text(encoding="utf-8"))
            assert loaded["next_id"] == 900001

    def test_reject_corrupted_manifest(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "manifest.json"
            path.write_text("{corrupted json}", encoding="utf-8")
            manager = ManifestManager(path)
            with pytest.raises(Exception):  # ManifestCorruptionError
                manager.load()

    def test_detect_deleted_identities(self) -> None:
        manifest = RuleManifest(field_mapping_version="wazuh-4.14", next_id=900000)
        manifest.allocate_id_for_identity(
            "uuid-1",
            "rules/test1.yml",
            "a" * 64,
            "sigma_uuid",
            999999,
        )
        manifest.allocate_id_for_identity(
            "uuid-2",
            "rules/test2.yml",
            "b" * 64,
            "sigma_uuid",
            999999,
        )
        assert len(manifest.active) == 2

        manager = ManifestManager(Path("/tmp/unused"))
        current = {"uuid-1"}  # Only uuid-1 remains
        manifest = manager.detect_deleted_identities(current, manifest)

        assert "uuid-1" in manifest.active
        assert "uuid-2" not in manifest.active
        assert "uuid-2" in manifest.retired

    def test_final_integrity_rejects_rewound_next_id(self) -> None:
        manifest = RuleManifest(field_mapping_version="wazuh-4.14", next_id=900000)
        manifest.allocate_id_for_identity(
            "uuid-1",
            "rules/test1.yml",
            "a" * 64,
            "sigma_uuid",
            999999,
        )
        manifest.next_id = 900000

        manager = ManifestManager(Path("/tmp/unused"))
        with pytest.raises(ManifestError, match="next_id would reuse"):
            manager.check_final_integrity(manifest)


class TestConversionCache:
    """Cache storage and retrieval tests."""

    def test_cache_disabled(self) -> None:
        with TemporaryDirectory() as tmpdir:
            cache = ConversionCache(tmpdir, enabled=False)
            result = cache.get("a" * 64)
            assert result is None

    def test_store_and_retrieve_entry(self) -> None:
        from wazuh_sigma.incremental.models import CacheEntry

        with TemporaryDirectory() as tmpdir:
            cache = ConversionCache(tmpdir, enabled=True)
            fingerprint = "a" * 64
            entry = CacheEntry(
                rule_identity="test-uuid",
                source_path="rules/test.yml",
                fingerprint=fingerprint,
                wazuh_rule_id=900000,
                sigma_title="Test",
                xml_fragment='<rule id="900000"/>',
            )
            cache.put(entry)

            retrieved = cache.get(fingerprint)
            assert retrieved is not None
            assert retrieved.wazuh_rule_id == 900000

    def test_cache_miss_on_missing_file(self) -> None:
        with TemporaryDirectory() as tmpdir:
            cache = ConversionCache(tmpdir, enabled=True)
            result = cache.get("missing_fingerprint")
            assert result is None

    def test_validate_cached_fragment(self) -> None:
        from wazuh_sigma.incremental.models import CacheEntry

        with TemporaryDirectory() as tmpdir:
            cache = ConversionCache(tmpdir, enabled=True)
            entry = CacheEntry(
                rule_identity="test-uuid",
                source_path="rules/test.yml",
                fingerprint="a" * 64,
                wazuh_rule_id=900000,
                sigma_title="Test",
                xml_fragment='<rule id="900000" level="5"/>',
            )
            xml_str = cache.validate_fragment(entry, 900000)
            assert "900000" in xml_str

    def test_validate_rejects_wrong_rule_id(self) -> None:
        with TemporaryDirectory() as tmpdir:
            cache = ConversionCache(tmpdir, enabled=True)
            entry = CacheEntry(
                rule_identity="test-uuid",
                source_path="rules/test.yml",
                fingerprint="a" * 64,
                wazuh_rule_id=900000,
                sigma_title="Test",
                xml_fragment='<rule id="900001"/>',  # Wrong ID
            )
            with pytest.raises(ConversionCacheError, match="does not match expected"):
                cache.validate_fragment(entry, 900000)

    def test_strict_cache_rejects_corrupted_entry(self) -> None:
        with TemporaryDirectory() as tmpdir:
            cache = ConversionCache(tmpdir, enabled=True, strict=True)
            fingerprint = "a" * 64
            (Path(tmpdir) / "entries" / f"{fingerprint}.json").write_text(
                "{bad json}",
                encoding="utf-8",
            )

            with pytest.raises(ConversionCacheError, match="unreadable cache entry"):
                cache.get(fingerprint)


class TestRuleIdentity:
    """Rule identity derivation tests."""

    def test_valid_sigma_uuid_is_preferred(self) -> None:
        rule = make_rule(id="036d9a52-7a13-11ec-a8a3-0242ac120002")

        identity, source = derive_rule_identity(rule)

        assert identity == "036d9a52-7a13-11ec-a8a3-0242ac120002"
        assert source == "sigma_uuid"

    def test_invalid_sigma_id_uses_fallback(self) -> None:
        rule = make_rule(id="not-a-uuid", title="Fallback Rule", source_file="rules/fallback.yml")

        identity, source = derive_rule_identity(rule, source_path="rules/fallback.yml")

        assert identity != "not-a-uuid"
        assert len(identity) == 64
        assert source == "fallback_hash"


class TestConversionFingerprint:
    """Fingerprint input coverage tests."""

    def test_field_mapping_contents_invalidate_fingerprint(self) -> None:
        rule = make_rule(id="036d9a52-7a13-11ec-a8a3-0242ac120002")

        first = compute_conversion_fingerprint(
            rule,
            wazuh_rule_id=900000,
            field_mapping_version="same-version",
            field_mapping={"Image": "win.eventdata.image"},
            backend_output_version="wazuh-xml-v1",
            rule_id_range=(900000, 949999),
        )
        second = compute_conversion_fingerprint(
            rule,
            wazuh_rule_id=900000,
            field_mapping_version="same-version",
            field_mapping={"Image": "custom.image"},
            backend_output_version="wazuh-xml-v1",
            rule_id_range=(900000, 949999),
        )

        assert first != second

    def test_report_only_advisor_metadata_is_not_fingerprinted(self) -> None:
        rule = make_rule(id="036d9a52-7a13-11ec-a8a3-0242ac120002")
        base_kwargs = {
            "wazuh_rule_id": 900000,
            "field_mapping_version": "mapping-v1",
            "field_mapping": {"Image": "win.eventdata.image"},
            "backend_output_version": "wazuh-xml-v1",
            "rule_id_range": (900000, 949999),
        }

        first = compute_conversion_fingerprint(rule, **base_kwargs)
        second = compute_conversion_fingerprint(rule, **base_kwargs)
        changed_level = compute_conversion_fingerprint(
            rule,
            **base_kwargs,
            advisor_level_override=12,
        )

        assert first == second
        assert first != changed_level


class TestIncrementalConverterService:
    """End-to-end incremental conversion service tests."""

    def test_first_run_converts_all_rules(self) -> None:
        with TemporaryDirectory() as tmpdir:
            service = IncrementalConverterService(
                cache_dir=tmpdir,
                manifest_file=Path(tmpdir) / "manifest.json",
                enabled=True,
                field_mapping_version="wazuh-4.14",
                rule_id_range=(900000, 999999),
            )

            rule = make_rule(id="test-uuid-1", title="Test Rule")
            status, _ = service.process_rule(rule)

            assert status.wazuh_rule_id == 900000
            assert not status.cached
            assert status.fingerprint == status.fingerprint

    def test_reuse_existing_identity(self) -> None:
        with TemporaryDirectory() as tmpdir:
            manifest_file = Path(tmpdir) / "manifest.json"
            service = IncrementalConverterService(
                cache_dir=tmpdir,
                manifest_file=manifest_file,
                enabled=True,
                field_mapping_version="wazuh-4.14",
                rule_id_range=(900000, 999999),
            )

            rule1 = make_rule(id="test-uuid", title="Test Rule")
            status1, _ = service.process_rule(rule1)

            # Simulate persisting and reloading
            service.save_manifest()
            service2 = IncrementalConverterService(
                cache_dir=tmpdir,
                manifest_file=manifest_file,
                enabled=True,
                field_mapping_version="wazuh-4.14",
                rule_id_range=(900000, 999999),
            )

            status2, _ = service2.process_rule(rule1)
            assert status2.wazuh_rule_id == status1.wazuh_rule_id

    def test_exhausted_range_fails(self) -> None:
        with TemporaryDirectory() as tmpdir:
            service = IncrementalConverterService(
                cache_dir=tmpdir,
                manifest_file=Path(tmpdir) / "manifest.json",
                enabled=True,
                field_mapping_version="wazuh-4.14",
                rule_id_range=(900000, 900000),  # Only one ID
            )

            rule1 = make_rule(id="uuid-1", title="Test 1")
            service.process_rule(rule1)

            rule2 = make_rule(id="uuid-2", title="Test 2")
            with pytest.raises(RuleIDRangeExhaustedError):
                service.process_rule(rule2)

    def test_finalize_detects_deleted_rules(self) -> None:
        with TemporaryDirectory() as tmpdir:
            service = IncrementalConverterService(
                cache_dir=tmpdir,
                manifest_file=Path(tmpdir) / "manifest.json",
                enabled=True,
                field_mapping_version="wazuh-4.14",
                rule_id_range=(900000, 999999),
            )

            rule1 = make_rule(id="uuid-1", title="Test 1")
            status1, _ = service.process_rule(rule1)

            rule2 = make_rule(id="uuid-2", title="Test 2")
            status2, _ = service.process_rule(rule2)

            # Only uuid-1 remains
            manifest = service.finalize_manifest({status1.rule_identity})
            assert status1.rule_identity in manifest.active
            assert status2.rule_identity not in manifest.active
            assert status2.rule_identity in manifest.retired

    def test_duplicate_identity_in_same_run_fails(self) -> None:
        with TemporaryDirectory() as tmpdir:
            service = IncrementalConverterService(
                cache_dir=tmpdir,
                manifest_file=Path(tmpdir) / "manifest.json",
                enabled=True,
                field_mapping_version="wazuh-4.14",
                rule_id_range=(900000, 999999),
            )

            rule1 = make_rule(id="036d9a52-7a13-11ec-a8a3-0242ac120002", title="One")
            rule2 = make_rule(id="036d9a52-7a13-11ec-a8a3-0242ac120002", title="Two")
            service.process_rule(rule1)

            with pytest.raises(DuplicateRuleIdentityError, match="duplicate rule identity"):
                service.process_rule(rule2)

    def test_missing_manifest_with_existing_cache_fails_explicitly(self) -> None:
        with TemporaryDirectory() as tmpdir:
            cache = ConversionCache(tmpdir, enabled=True)
            cache.put(
                CacheEntry(
                    rule_identity="036d9a52-7a13-11ec-a8a3-0242ac120002",
                    source_path="rules/test.yml",
                    fingerprint="a" * 64,
                    wazuh_rule_id=900000,
                    sigma_title="Test",
                    xml_fragment='<rule id="900000" level="5"/>',
                )
            )

            with pytest.raises(ManifestCorruptionError, match="manifest is missing"):
                IncrementalConverterService(
                    cache_dir=tmpdir,
                    manifest_file=Path(tmpdir) / "manifest.json",
                    enabled=True,
                    field_mapping_version="wazuh-4.14",
                    rule_id_range=(900000, 999999),
                )

    def test_strict_cached_fragment_validation_error_raises(self) -> None:
        with TemporaryDirectory() as tmpdir:
            service = IncrementalConverterService(
                cache_dir=tmpdir,
                manifest_file=Path(tmpdir) / "manifest.json",
                enabled=True,
                field_mapping_version="wazuh-4.14",
                rule_id_range=(900000, 999999),
                strict_cache=True,
            )
            rule = make_rule(id="036d9a52-7a13-11ec-a8a3-0242ac120002", title="Test")
            status, _ = service.process_rule(rule)
            service.store_converted_fragment(status, '<rule id="900001" level="5"/>', "Test")
            service.save_manifest()

            service2 = IncrementalConverterService(
                cache_dir=tmpdir,
                manifest_file=Path(tmpdir) / "manifest.json",
                enabled=True,
                field_mapping_version="wazuh-4.14",
                rule_id_range=(900000, 999999),
                strict_cache=True,
            )

            with pytest.raises(ConversionCacheError, match="does not match expected"):
                service2.process_rule(rule)
