"""Tests for the new safe field resolution behavior."""

import pytest

from wazuh_sigma.backend.wazuh import SigmaFieldMapper, WazuhRuleGenerator, WazuhRuleIDGenerator
from wazuh_sigma.fields.errors import InvalidMappingConfigError, UnsupportedWindowsFieldError
from wazuh_sigma.fields.models import (
    FieldMapping,
    FieldNamespace,
    FieldResolutionResult,
    VerificationSource,
)
from wazuh_sigma.fields.registry import FieldMappingRegistry


class TestFieldResolutionResult:
    """Tests for the FieldResolutionResult dataclass."""

    def test_resolved_status_should_emit(self):
        """Test that 'resolved' status indicates field should be emitted."""
        result = FieldResolutionResult(
            field_name="win.system.eventID",
            status="resolved",
        )
        assert result.should_emit() is True
        assert result.get_field_name_or_raise() == "win.system.eventID"

    def test_legacy_fallback_status_should_emit(self):
        """Test that 'legacy_fallback' status indicates field should be emitted."""
        result = FieldResolutionResult(
            field_name="customfield",
            status="legacy_fallback",
            warning_message="Using unsafe fallback",
        )
        assert result.should_emit() is True
        assert result.get_field_name_or_raise() == "customfield"

    def test_warning_status_should_not_emit(self):
        """Test that 'warning' status indicates field should NOT be emitted."""
        result = FieldResolutionResult(
            field_name=None,
            status="warning",
            warning_message="Unsupported Windows field",
        )
        assert result.should_emit() is False
        with pytest.raises(ValueError, match="has no field_name"):
            result.get_field_name_or_raise()

    def test_unsupported_status_should_not_emit(self):
        """Test that 'unsupported' status indicates field should NOT be emitted."""
        result = FieldResolutionResult(
            field_name=None,
            status="unsupported",
            warning_message="No mapping found",
        )
        assert result.should_emit() is False
        with pytest.raises(ValueError, match="has no field_name"):
            result.get_field_name_or_raise()


class TestRegistryResolveReturnsResult:
    """Tests that registry.resolve() returns FieldResolutionResult with safe behavior."""

    def test_registry_resolve_returns_result_type(self):
        """Test that registry.resolve() returns FieldResolutionResult."""
        registry = FieldMappingRegistry()
        result = registry.resolve("EventID", product="windows", mode="strict")
        assert isinstance(result, FieldResolutionResult)
        assert result.status == "resolved"
        assert result.field_name == "win.system.eventID"

    def test_strict_mode_raises_on_unsupported_windows_field(self):
        """Test that strict mode raises for unsupported Windows fields."""
        registry = FieldMappingRegistry()
        with pytest.raises(UnsupportedWindowsFieldError):
            registry.resolve("UnknownWindowsField", product="windows", mode="strict")

    def test_warn_mode_returns_warning_status_for_windows_field(self):
        """Test that warn mode returns warning status (not lowercase fallback)."""
        registry = FieldMappingRegistry()
        result = registry.resolve(
            "UnknownWindowsField", product="windows", mode="warn"
        )
        assert isinstance(result, FieldResolutionResult)
        assert result.status == "warning"
        assert result.field_name is None
        assert "Unsupported Windows field" in result.warning_message
        assert result.should_emit() is False

    def test_warn_mode_returns_warning_status_for_non_windows_unknown(self):
        """Test that warn mode returns warning status for unknown non-Windows fields."""
        registry = FieldMappingRegistry()
        result = registry.resolve("UnknownField", product="linux", mode="warn")
        assert isinstance(result, FieldResolutionResult)
        assert result.status == "warning"
        assert result.field_name is None
        assert result.should_emit() is False

    def test_legacy_mode_returns_legacy_fallback_status(self):
        """Test that legacy mode returns legacy_fallback status."""
        registry = FieldMappingRegistry()
        result = registry.resolve(
            "UnknownWindowsField", product="windows", mode="legacy"
        )
        assert isinstance(result, FieldResolutionResult)
        assert result.status == "legacy_fallback"
        assert result.field_name == "unknownwindowsfield"
        assert result.should_emit() is True


class TestSigmaFieldMapperWithNewResult:
    """Tests for SigmaFieldMapper using new FieldResolutionResult."""

    def test_mapper_resolve_field_returns_result(self):
        """Test that mapper.resolve_field() returns FieldResolutionResult."""
        mapper = SigmaFieldMapper(mode="strict")
        result = mapper.resolve_field("EventID", product="windows")
        assert isinstance(result, FieldResolutionResult)
        assert result.status == "resolved"
        assert result.field_name == "win.system.eventID"

    def test_mapper_map_raises_on_warning_status(self):
        """Test that mapper.map() raises ValueError on warning status (not returning lowercase)."""
        mapper = SigmaFieldMapper(mode="warn")
        with pytest.raises(ValueError, match="cannot be emitted"):
            mapper.map("UnknownWindowsField", product="windows")

    def test_mapper_map_raises_on_unsupported_status(self):
        """Test that mapper.map() raises ValueError on unsupported status."""
        mapper = SigmaFieldMapper(mode="strict")
        with pytest.raises(UnsupportedWindowsFieldError):
            mapper.map("UnknownWindowsField", product="windows")

    def test_mapper_map_returns_legacy_fallback_for_legacy_mode(self):
        """Test that mapper.map() returns lowercase fallback only in legacy mode."""
        mapper = SigmaFieldMapper(mode="legacy")
        result = mapper.map("UnknownWindowsField", product="windows")
        assert result == "unknownwindowsfield"


class TestCustomMappingValidation:
    """Tests for custom mapping validation with mode safety."""

    def test_add_custom_mapping_unprefixed_windows_strict_raises(self):
        """Test that unprefixed Windows fields are rejected in strict mode."""
        registry = FieldMappingRegistry()
        mapping = FieldMapping(
            sigma_field="CustomField",
            wazuh_field="custom_field",  # Not win.* prefix
            namespace=FieldNamespace.STATIC,
            products=("windows",),
        )
        with pytest.raises(
            InvalidMappingConfigError, match="unprefixed Windows fields bypass"
        ):
            registry.add_custom_mappings([mapping], mode="strict")

    def test_add_custom_mapping_unprefixed_windows_warn_raises(self):
        """Test that unprefixed Windows fields are rejected in warn mode."""
        registry = FieldMappingRegistry()
        mapping = FieldMapping(
            sigma_field="CustomField",
            wazuh_field="custom_field",  # Not win.* prefix
            namespace=FieldNamespace.STATIC,
            products=("windows",),
        )
        with pytest.raises(
            InvalidMappingConfigError, match="unprefixed Windows fields bypass"
        ):
            registry.add_custom_mappings([mapping], mode="warn")

    def test_add_custom_mapping_unprefixed_windows_legacy_allows(self):
        """Test that unprefixed Windows fields are allowed in legacy mode."""
        registry = FieldMappingRegistry()
        mapping = FieldMapping(
            sigma_field="CustomField",
            wazuh_field="custom_field",  # Not win.* prefix
            namespace=FieldNamespace.STATIC,
            products=("windows",),
        )
        # Should not raise in legacy mode
        registry.add_custom_mappings([mapping], mode="legacy")
        assert mapping in registry.mappings

    def test_add_custom_mapping_prefixed_windows_strict_allows(self):
        """Test that prefixed Windows fields are allowed in strict mode."""
        registry = FieldMappingRegistry()
        mapping = FieldMapping(
            sigma_field="CustomField",
            wazuh_field="win.eventdata.customField",
            namespace=FieldNamespace.EVENTDATA,
            products=("windows",),
        )
        # Should not raise
        registry.add_custom_mappings([mapping], mode="strict")
        assert mapping in registry.mappings

    def test_add_custom_mapping_non_windows_allows_unprefixed(self):
        """Test that non-Windows fields can be unprefixed in all modes."""
        registry = FieldMappingRegistry()
        mapping = FieldMapping(
            sigma_field="LinuxField",
            wazuh_field="linux.field",
            namespace=FieldNamespace.GENERIC,
            products=("linux",),
        )
        # Should not raise in any mode
        registry.add_custom_mappings([mapping], mode="strict")
        assert mapping in registry.mappings


class TestWarnModeNeverEmitsLowercase:
    """Integration tests proving warn mode never emits lowercase fallback fields."""

    def test_warn_mode_skips_unknown_windows_field_in_rule(self):
        """Test that warn mode skips unknown Windows fields in generated rules."""
        # Create a minimal rule-like object
        from unittest.mock import Mock

        mapper = SigmaFieldMapper(mode="warn")
        id_gen = WazuhRuleIDGenerator()
        rule_gen = WazuhRuleGenerator(id_gen, field_mapper=mapper)

        sigma_rule = Mock()
        sigma_rule.title = "Test Rule"
        sigma_rule.detection = {"UnknownWindowsField": "some_value"}
        sigma_rule.tags = []
        sigma_rule.level = "medium"
        sigma_rule.logsource = {"product": "windows"}
        sigma_rule.get_event_source = Mock(return_value=None)

        rule = rule_gen.generate(sigma_rule)

        # Count how many fields were emitted
        field_elems = rule.findall("field")
        field_names = [elem.get("name") for elem in field_elems]

        # The unknown field should NOT have been emitted with lowercase fallback
        assert "unknownwindowsfield" not in field_names
        assert len(field_elems) == 0  # No fields emitted at all since it's unknown

    def test_warn_mode_emits_known_fields(self):
        """Test that warn mode still emits known fields."""
        from unittest.mock import Mock

        mapper = SigmaFieldMapper(mode="warn")
        id_gen = WazuhRuleIDGenerator()
        rule_gen = WazuhRuleGenerator(id_gen, field_mapper=mapper)

        sigma_rule = Mock()
        sigma_rule.title = "Test Rule"
        sigma_rule.detection = {"EventID": "4688"}
        sigma_rule.tags = []
        sigma_rule.level = "medium"
        sigma_rule.logsource = {"product": "windows"}
        sigma_rule.get_event_source = Mock(return_value=None)

        rule = rule_gen.generate(sigma_rule)

        # Find the eventID field
        field_found = False
        for elem in rule:
            if elem.tag == "field" and elem.get("name") == "win.system.eventID":
                field_found = True
                break

        assert field_found, "Known field should be emitted in warn mode"

    def test_warn_mode_multiple_fields_skips_unknown(self):
        """Test that warn mode processes multiple fields correctly, skipping unknowns."""
        from unittest.mock import Mock

        mapper = SigmaFieldMapper(mode="warn")
        id_gen = WazuhRuleIDGenerator()
        rule_gen = WazuhRuleGenerator(id_gen, field_mapper=mapper)

        sigma_rule = Mock()
        sigma_rule.title = "Test Rule"
        sigma_rule.detection = {
            "EventID": "4688",
            "UnknownField": "test",
            "Image": "test.exe",
        }
        sigma_rule.tags = []
        sigma_rule.level = "medium"
        sigma_rule.logsource = {"product": "windows"}
        sigma_rule.get_event_source = Mock(return_value=None)

        rule = rule_gen.generate(sigma_rule)

        # Get all field names
        field_elems = rule.findall("field")
        field_names = [elem.get("name") for elem in field_elems]

        # Known fields should be present
        assert "win.system.eventID" in field_names or any(
            "eventID" in name for name in field_names
        )
        assert "win.eventdata.image" in field_names or any(
            "image" in name for name in field_names
        )

        # Unknown field should NOT be present as lowercase
        assert "unknownfield" not in field_names

    def test_strict_mode_raises_on_unknown_windows_field(self):
        """Test that strict mode raises exception for unknown Windows fields."""
        from unittest.mock import Mock

        mapper = SigmaFieldMapper(mode="strict")
        id_gen = WazuhRuleIDGenerator()
        rule_gen = WazuhRuleGenerator(id_gen, field_mapper=mapper)

        sigma_rule = Mock()
        sigma_rule.title = "Test Rule"
        sigma_rule.detection = {"UnknownWindowsField": "some_value"}
        sigma_rule.tags = []
        sigma_rule.level = "medium"
        sigma_rule.logsource = {"product": "windows"}
        sigma_rule.get_event_source = Mock(return_value=None)

        with pytest.raises(UnsupportedWindowsFieldError):
            rule_gen.generate(sigma_rule)

    def test_legacy_mode_emits_lowercase(self):
        """Test that legacy mode does emit lowercase fallback."""
        from unittest.mock import Mock

        mapper = SigmaFieldMapper(mode="legacy")
        id_gen = WazuhRuleIDGenerator()
        rule_gen = WazuhRuleGenerator(id_gen, field_mapper=mapper)

        sigma_rule = Mock()
        sigma_rule.title = "Test Rule"
        sigma_rule.detection = {"UnknownWindowsField": "some_value"}
        sigma_rule.tags = []
        sigma_rule.level = "medium"
        sigma_rule.logsource = {"product": "windows"}
        sigma_rule.get_event_source = Mock(return_value=None)

        rule = rule_gen.generate(sigma_rule)

        # In legacy mode, the lowercase fallback should be emitted
        field_elems = rule.findall("field")
        field_names = [elem.get("name") for elem in field_elems]

        assert "unknownwindowsfield" in field_names
