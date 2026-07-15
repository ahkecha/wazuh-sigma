"""Integration tests for backend field mapping with Windows context."""

import pytest

from wazuh_sigma.backend.wazuh import SigmaFieldMapper, WazuhBackendConfig
from wazuh_sigma.fields.errors import UnsupportedWindowsFieldError
from wazuh_sigma.fields.registry import FieldMappingRegistry


class TestSigmaFieldMapperIntegration:
    """Integration tests for SigmaFieldMapper with new registry."""

    def test_field_mapper_uses_registry(self):
        """Test that SigmaFieldMapper uses the registry for Windows fields."""
        mapper = SigmaFieldMapper()

        # Known Windows field should be found in registry
        result = mapper.map("EventID", product="windows")
        assert result == "win.system.eventID"

    def test_field_mapper_backward_compat_map_field_static(self):
        """Test backward compatibility of static map_field method."""
        # Static method should still work without registry
        result = SigmaFieldMapper.map_field("EventID")
        assert result == "win.system.eventID"

    def test_field_mapper_context_aware_image(self):
        """Test context-aware mapping of Image field."""
        mapper = SigmaFieldMapper()
        result = mapper.map("Image", product="windows", service="sysmon")
        assert result == "win.eventdata.image"

    def test_field_mapper_windows_unknown_field_strict(self):
        """Test that strict mode rejects unknown Windows fields."""
        mapper = SigmaFieldMapper(mode="strict")
        with pytest.raises(UnsupportedWindowsFieldError):
            mapper.map("UnknownWindowsField", product="windows")

    def test_field_mapper_windows_unknown_field_warn(self):
        """Test that warn mode raises ValueError for unknown Windows fields (safe behavior)."""
        mapper = SigmaFieldMapper(mode="warn")
        with pytest.raises(ValueError, match="cannot be emitted"):
            mapper.map("UnknownWindowsField", product="windows")

    def test_field_mapper_windows_unknown_field_legacy(self):
        """Test that legacy mode returns lowercase fallback."""
        mapper = SigmaFieldMapper(mode="legacy")
        result = mapper.map("UnknownWindowsField", product="windows")
        assert result == "unknownwindowsfield"

    def test_field_mapper_non_windows_fallback(self):
        """Test that non-Windows fields use safe fallback."""
        mapper = SigmaFieldMapper(mode="legacy")
        result = mapper.map("CustomField", product="linux")
        assert result == "customfield"

    def test_backend_config_mode_validation(self):
        """Test that WazuhBackendConfig validates mode."""
        # Valid mode should not raise
        config = WazuhBackendConfig(windows_field_mapping_mode="strict")
        assert config.windows_field_mapping_mode == "strict"

        # Invalid mode should raise
        with pytest.raises(ValueError, match="must be"):
            WazuhBackendConfig(windows_field_mapping_mode="invalid")

    def test_backend_config_parent_rule_mapping_version(self):
        """Test that parent rule mapping version is in config."""
        config = WazuhBackendConfig()
        assert config.parent_rule_mapping_version == "wazuh-4.14-windows-parent-v1"

    def test_field_mapper_with_custom_registry(self):
        """Test SigmaFieldMapper with custom registry."""
        custom_registry = FieldMappingRegistry()
        mapper = SigmaFieldMapper(registry=custom_registry)

        # Should use the custom registry
        result = mapper.map("EventID", product="windows")
        assert result == "win.system.eventID"

    def test_field_mapper_preserves_field_mapping_dict(self):
        """Test that legacy field_mapping dict still works."""
        custom_mapping = {"CustomField": "custom.field"}
        mapper = SigmaFieldMapper(mapping=custom_mapping)

        # Should find in the legacy dict when not in registry
        result = mapper.map("CustomField")
        assert result == "custom.field"

    def test_field_mapper_precedence_registry_over_dict(self):
        """Test that registry takes precedence over legacy dict."""
        custom_mapping = {"EventID": "should.not.use.this"}
        mapper = SigmaFieldMapper(mapping=custom_mapping)

        # Registry should take precedence
        result = mapper.map("EventID", product="windows")
        assert result == "win.system.eventID"  # From registry, not custom_mapping

    def test_field_mapper_hash_field_exact_case(self):
        """Test that hash fields preserve exact camelCase."""
        mapper = SigmaFieldMapper()

        assert mapper.map("MD5", product="windows") == "win.eventdata.md5"
        assert mapper.map("SHA1", product="windows") == "win.eventdata.sha1"
        assert mapper.map("SHA256", product="windows") == "win.eventdata.sha256"
        assert mapper.map("Imphash", product="windows") == "win.eventdata.imphash"

    def test_field_mapper_system_namespace_fields(self):
        """Test that system namespace fields are correctly mapped."""
        mapper = SigmaFieldMapper()

        assert mapper.map("EventID", product="windows") == "win.system.eventID"
        assert mapper.map("Provider_Name", product="windows") == "win.system.providerName"
        assert mapper.map("Channel", product="windows") == "win.system.channel"
        assert mapper.map("ComputerName", product="windows") == "win.system.computer"

    def test_field_mapper_eventdata_namespace_fields(self):
        """Test that eventdata namespace fields are correctly mapped."""
        mapper = SigmaFieldMapper()

        assert mapper.map("Image", product="windows") == "win.eventdata.image"
        assert mapper.map("CommandLine", product="windows") == "win.eventdata.commandLine"
        assert mapper.map("ParentImage", product="windows") == "win.eventdata.parentImage"
        assert mapper.map("TargetUserName", product="windows") == "win.eventdata.targetUserName"
        assert mapper.map("LogonType", product="windows") == "win.eventdata.logonType"

    def test_field_mapper_with_spaces(self):
        """Test that fields with spaces are handled correctly."""
        mapper = SigmaFieldMapper(mode="legacy")

        # Unknown field with space should become underscore
        result = mapper.map("Unknown Field", product="linux")
        assert result == "unknown_field"

    def test_field_mapper_fallback_to_legacy_dict(self):
        """Test that legacy dict is used in legacy mode but not in warn mode."""
        # In legacy mode, legacy dict should be used
        legacy_mapper = SigmaFieldMapper(
            mapping={"SomeOldField": "old.field.name"},
            mode="legacy"
        )
        result = legacy_mapper.map("SomeOldField", product="windows")
        assert result == "old.field.name"  # From legacy dict

        # In warn mode, legacy dict should NOT be used for unknown Windows fields
        warn_mapper = SigmaFieldMapper(
            mapping={"UnknownField": "old.field.name"},
            mode="warn"
        )
        with pytest.raises(ValueError, match="cannot be emitted"):
            warn_mapper.map("UnknownField", product="windows")

    def test_field_mapper_mode_configuration(self):
        """Test that field mapper respects mode configuration."""
        strict_mapper = SigmaFieldMapper(mode="strict")
        warn_mapper = SigmaFieldMapper(mode="warn")
        legacy_mapper = SigmaFieldMapper(mode="legacy")

        # Known field should work in all modes
        assert strict_mapper.map("EventID", product="windows") == "win.system.eventID"
        assert warn_mapper.map("EventID", product="windows") == "win.system.eventID"
        assert legacy_mapper.map("EventID", product="windows") == "win.system.eventID"

        # Unknown Windows field behavior differs by mode
        with pytest.raises(UnsupportedWindowsFieldError):
            strict_mapper.map("UnknownField", product="windows")

        # Warn mode now raises ValueError instead of returning lowercase (safe behavior)
        with pytest.raises(ValueError, match="cannot be emitted"):
            warn_mapper.map("UnknownField", product="windows")

        # Legacy mode still allows lowercase fallback (unsafe but supported for migration)
        assert legacy_mapper.map("UnknownField", product="windows") == "unknownfield"
