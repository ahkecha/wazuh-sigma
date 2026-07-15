"""Tests for incremental cache models and schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from wazuh_sigma.incremental.models import (
    CacheEntry,
    ManifestEntry,
    RuleManifest,
)


class TestManifestEntry:
    """ManifestEntry validation tests."""

    def test_valid_entry(self) -> None:
        entry = ManifestEntry(
            source_path="rules/sigma/test.yml",
            fingerprint="a" * 64,
            wazuh_rule_id=900000,
            identity_source="sigma_uuid",
        )
        assert entry.wazuh_rule_id == 900000

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            ManifestEntry(
                source_path="rules/sigma/test.yml",
                fingerprint="a" * 64,
                wazuh_rule_id=900000,
                identity_source="sigma_uuid",
                extra_field="should_fail",  # type: ignore
            )

    def test_rejects_invalid_fingerprint(self) -> None:
        with pytest.raises(ValidationError):
            ManifestEntry(
                source_path="rules/sigma/test.yml",
                fingerprint="invalid_fingerprint",
                wazuh_rule_id=900000,
                identity_source="sigma_uuid",
            )

    def test_rejects_non_positive_wazuh_id(self) -> None:
        with pytest.raises(ValidationError):
            ManifestEntry(
                source_path="rules/sigma/test.yml",
                fingerprint="a" * 64,
                wazuh_rule_id=0,
                identity_source="sigma_uuid",
            )


class TestCacheEntry:
    """CacheEntry validation tests."""

    def test_valid_entry(self) -> None:
        entry = CacheEntry(
            rule_identity="test-uuid",
            source_path="rules/sigma/test.yml",
            fingerprint="a" * 64,
            wazuh_rule_id=900000,
            sigma_title="Test Rule",
            xml_fragment='<rule id="900000" level="5"/>',
        )
        assert entry.wazuh_rule_id == 900000

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            CacheEntry(
                rule_identity="test-uuid",
                source_path="rules/sigma/test.yml",
                fingerprint="a" * 64,
                wazuh_rule_id=900000,
                sigma_title="Test Rule",
                xml_fragment="<rule/>",
                extra_field="should_fail",  # type: ignore
            )

    def test_rejects_invalid_fingerprint_length(self) -> None:
        with pytest.raises(ValidationError):
            CacheEntry(
                rule_identity="test-uuid",
                source_path="rules/sigma/test.yml",
                fingerprint="too_short",
                wazuh_rule_id=900000,
                sigma_title="Test Rule",
                xml_fragment="<rule/>",
            )


class TestRuleManifest:
    """RuleManifest validation and state management tests."""

    def test_default_manifest(self) -> None:
        manifest = RuleManifest(field_mapping_version="wazuh-4.14", next_id=900000)
        assert manifest.field_mapping_version == "wazuh-4.14"
        assert manifest.next_id == 900000
        assert len(manifest.active) == 0
        assert len(manifest.retired) == 0

    def test_allocate_id_for_new_identity(self) -> None:
        manifest = RuleManifest(field_mapping_version="wazuh-4.14", next_id=900000)
        new_id = manifest.allocate_id_for_identity(
            "test-uuid",
            "rules/test.yml",
            "a" * 64,
            "sigma_uuid",
            999999,
        )
        assert new_id == 900000
        assert manifest.next_id == 900001
        assert "test-uuid" in manifest.active

    def test_allocate_reuses_existing_identity(self) -> None:
        manifest = RuleManifest(field_mapping_version="wazuh-4.14", next_id=900000)
        id1 = manifest.allocate_id_for_identity(
            "test-uuid",
            "rules/test.yml",
            "a" * 64,
            "sigma_uuid",
            999999,
        )
        id2 = manifest.allocate_id_for_identity(
            "test-uuid",
            "rules/test.yml",
            "b" * 64,
            "sigma_uuid",
            999999,
        )
        assert id1 == id2
        assert manifest.next_id == 900001  # Only incremented once

    def test_allocate_fails_when_exhausted(self) -> None:
        manifest = RuleManifest(field_mapping_version="wazuh-4.14", next_id=1000000)
        with pytest.raises(ValueError, match="exhausted rule ID range"):
            manifest.allocate_id_for_identity(
                "test-uuid",
                "rules/test.yml",
                "a" * 64,
                "sigma_uuid",
                999999,  # end_id < next_id
            )

    def test_retire_identity_moves_to_retired(self) -> None:
        manifest = RuleManifest(field_mapping_version="wazuh-4.14", next_id=900000)
        manifest.allocate_id_for_identity(
            "test-uuid",
            "rules/test.yml",
            "a" * 64,
            "sigma_uuid",
            999999,
        )
        assert "test-uuid" in manifest.active

        manifest.retire_identity("test-uuid", 900000)
        assert "test-uuid" not in manifest.active
        assert "test-uuid" in manifest.retired

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            RuleManifest(
                field_mapping_version="wazuh-4.14",
                next_id=900000,
                extra_field="should_fail",  # type: ignore
            )
