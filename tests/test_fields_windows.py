"""Tests for Windows EVTX field mapping registry and models."""

import pytest

from wazuh_sigma.fields.errors import InvalidMappingConfigError, UnsupportedWindowsFieldError
from wazuh_sigma.fields.models import (
    ConfidenceLevel,
    FieldMapping,
    FieldNamespace,
    VerificationSource,
)
from wazuh_sigma.fields.registry import FieldMappingRegistry
from wazuh_sigma.fields.windows import WINDOWS_FIELD_MAPPINGS


class TestFieldMapping:
    """Tests for FieldMapping model."""

    def test_field_mapping_system_namespace(self):
        """Test creating a system namespace mapping."""
        mapping = FieldMapping(
            sigma_field="EventID",
            wazuh_field="win.system.eventID",
            namespace=FieldNamespace.SYSTEM,
            products=("windows",),
            documentation_reference="https://example.com",
            verification_source=VerificationSource.WINDOWS_DOCUMENTATION,
            confidence=ConfidenceLevel.VERIFIED,
        )
        assert mapping.sigma_field == "EventID"
        assert mapping.wazuh_field == "win.system.eventID"
        assert mapping.namespace == FieldNamespace.SYSTEM

    def test_field_mapping_eventdata_namespace(self):
        """Test creating an eventdata namespace mapping."""
        mapping = FieldMapping(
            sigma_field="Image",
            wazuh_field="win.eventdata.image",
            namespace=FieldNamespace.EVENTDATA,
            products=("windows",),
            services=("sysmon",),
            documentation_reference="https://example.com",
            verification_source=VerificationSource.DECODED_FIXTURE,
            confidence=ConfidenceLevel.VERIFIED,
        )
        assert mapping.wazuh_field == "win.eventdata.image"
        assert mapping.namespace == FieldNamespace.EVENTDATA

    def test_field_mapping_namespace_mismatch_raises(self):
        """Test that namespace mismatch is caught."""
        with pytest.raises(ValueError, match="Namespace mismatch"):
            FieldMapping(
                sigma_field="EventID",
                wazuh_field="win.system.eventID",
                namespace=FieldNamespace.EVENTDATA,  # Wrong!
                products=("windows",),
            )

    def test_field_mapping_applies_to_with_context(self):
        """Test applies_to method with logsource context."""
        mapping = FieldMapping(
            sigma_field="Image",
            wazuh_field="win.eventdata.image",
            namespace=FieldNamespace.EVENTDATA,
            products=("windows",),
            services=("sysmon",),
        )
        assert mapping.applies_to(product="windows", service="sysmon") is True
        assert mapping.applies_to(product="windows", service="security") is False
        assert mapping.applies_to(product="linux") is False

    def test_field_mapping_case_insensitive_applies_to(self):
        """Test that applies_to is case-insensitive."""
        mapping = FieldMapping(
            sigma_field="Image",
            wazuh_field="win.eventdata.image",
            namespace=FieldNamespace.EVENTDATA,
            products=("windows",),
            services=("sysmon",),
        )
        assert mapping.applies_to(product="WINDOWS", service="SYSMON") is True


class TestFieldMappingRegistry:
    """Tests for FieldMappingRegistry."""

    def test_registry_lookup_found(self):
        """Test looking up a known mapping."""
        registry = FieldMappingRegistry()
        mapping = registry.lookup("EventID", product="windows")
        assert mapping is not None
        assert mapping.wazuh_field == "win.system.eventID"

    def test_registry_lookup_not_found(self):
        """Test looking up an unknown field."""
        registry = FieldMappingRegistry()
        mapping = registry.lookup("UnknownField", product="windows")
        assert mapping is None

    def test_registry_resolve_with_context(self):
        """Test resolving a field with product context."""
        registry = FieldMappingRegistry()
        result = registry.resolve("Image", product="windows", service="sysmon")
        assert result.status == "resolved"
        assert result.field_name == "win.eventdata.image"

    def test_registry_resolve_image_with_product_only(self):
        """Test resolving Image with only product context."""
        registry = FieldMappingRegistry()
        result = registry.resolve("Image", product="windows")
        assert result.status == "resolved"
        assert result.field_name == "win.eventdata.image"

    def test_registry_resolve_unknown_windows_field_strict(self):
        """Test strict mode rejects unknown Windows fields."""
        registry = FieldMappingRegistry()
        with pytest.raises(UnsupportedWindowsFieldError):
            registry.resolve("UnknownWindowsField", product="windows", mode="strict")

    def test_registry_resolve_unknown_windows_field_warn(self):
        """Test warn mode returns warning status (safe behavior) for unknown Windows fields."""
        registry = FieldMappingRegistry()
        result = registry.resolve("UnknownWindowsField", product="windows", mode="warn")
        assert result.status == "warning"
        assert result.field_name is None
        assert result.should_emit() is False

    def test_registry_resolve_unknown_windows_field_legacy(self):
        """Test legacy mode returns lowercase fallback."""
        registry = FieldMappingRegistry()
        result = registry.resolve("UnknownWindowsField", product="windows", mode="legacy")
        assert result.status == "legacy_fallback"
        assert result.field_name == "unknownwindowsfield"
        assert result.should_emit() is True

    def test_registry_resolve_unknown_non_windows_legacy(self):
        """Test legacy mode for non-Windows unknown fields."""
        registry = FieldMappingRegistry()
        result = registry.resolve("SomeField", product="linux", mode="legacy")
        assert result.status == "legacy_fallback"
        assert result.field_name == "somefield"
        assert result.should_emit() is True

    def test_registry_resolve_non_windows_strict(self):
        """Test strict mode for non-Windows unknown fields."""
        registry = FieldMappingRegistry()
        result = registry.resolve("SomeField", product="linux", mode="strict")
        assert result.status == "unsupported"
        assert result.field_name is None
        assert result.should_emit() is False

    def test_registry_add_mapping(self):
        """Test adding a custom mapping."""
        registry = FieldMappingRegistry()
        custom = FieldMapping(
            sigma_field="CustomField",
            wazuh_field="win.eventdata.customField",
            namespace=FieldNamespace.EVENTDATA,
            products=("windows",),
            documentation_reference="internal",
            verification_source=VerificationSource.REPOSITORY_LEGACY,
            confidence=ConfidenceLevel.PROVISIONAL,
        )
        registry.add_mapping(custom)
        mapping = registry.lookup("CustomField", product="windows")
        assert mapping is not None
        assert mapping.wazuh_field == "win.eventdata.customField"

    def test_registry_add_invalid_mapping_no_field(self):
        """Test that invalid mappings are rejected."""
        registry = FieldMappingRegistry()
        invalid = FieldMapping(
            sigma_field="",
            wazuh_field="win.eventdata.field",
            namespace=FieldNamespace.EVENTDATA,
        )
        with pytest.raises(InvalidMappingConfigError):
            registry.add_mapping(invalid)

    def test_registry_validate_windows_field_format(self):
        """Test Windows field format validation."""
        valid = FieldMapping(
            sigma_field="EventID",
            wazuh_field="win.system.eventID",
            namespace=FieldNamespace.SYSTEM,
        )
        # Should not raise
        FieldMappingRegistry._validate_mapping(valid)

    def test_registry_validate_namespace_consistency(self):
        """Test that namespace validation is strict."""
        with pytest.raises(ValueError):
            FieldMapping(
                sigma_field="Test",
                wazuh_field="win.eventdata.test",
                namespace=FieldNamespace.SYSTEM,  # Mismatch!
            )

    def test_windows_field_mappings_coverage(self):
        """Test that core Windows fields are in the mapping."""
        registry = FieldMappingRegistry(WINDOWS_FIELD_MAPPINGS)

        # System fields
        assert registry.lookup("EventID", product="windows") is not None
        assert registry.lookup("Provider_Name", product="windows") is not None
        assert registry.lookup("Channel", product="windows") is not None
        assert registry.lookup("ComputerName", product="windows") is not None

        # EventData fields
        assert registry.lookup("Image", product="windows") is not None
        assert registry.lookup("CommandLine", product="windows") is not None
        assert registry.lookup("TargetUserName", product="windows") is not None
        assert registry.lookup("LogonType", product="windows") is not None
        assert registry.lookup("QueryName", product="windows") is not None

    def test_field_mapping_exact_camelcase(self):
        """Test that exact camelCase is preserved."""
        registry = FieldMappingRegistry()

        # Test exact spelling
        result = registry.resolve("CommandLine", product="windows")
        assert result.status == "resolved"
        assert result.field_name == "win.eventdata.commandLine"  # camelCase!

        result = registry.resolve("TargetUserName", product="windows")
        assert result.status == "resolved"
        assert result.field_name == "win.eventdata.targetUserName"  # camelCase!

    def test_field_mapping_mode_invalid_raises(self):
        """Test that invalid mode raises."""
        registry = FieldMappingRegistry()
        with pytest.raises(ValueError, match="Invalid mode"):
            registry.resolve("EventID", product="windows", mode="invalid")

    def test_logon_type_context_security(self):
        """Test that LogonType is found in security context."""
        registry = FieldMappingRegistry()
        mapping = registry.lookup("LogonType", product="windows", service="security")
        assert mapping is not None
        assert mapping.wazuh_field == "win.eventdata.logonType"

    def test_hash_fields_exact_case(self):
        """Test that hash fields use exact camelCase."""
        registry = FieldMappingRegistry()
        assert registry.resolve("MD5", product="windows").field_name == "win.eventdata.md5"
        assert registry.resolve("SHA1", product="windows").field_name == "win.eventdata.sha1"
        assert registry.resolve("SHA256", product="windows").field_name == "win.eventdata.sha256"
        assert registry.resolve("Imphash", product="windows").field_name == "win.eventdata.imphash"

    def test_dns_query_name_field(self):
        """Test DNS query field mapping."""
        registry = FieldMappingRegistry()
        mapping = registry.lookup("QueryName", product="windows", service="dns-client")
        assert mapping is not None
        assert mapping.wazuh_field == "win.eventdata.queryName"
        assert mapping.confidence == ConfidenceLevel.VERIFIED

    @pytest.mark.parametrize(
        ("sigma_field", "service", "category", "wazuh_field"),
        [
            ("OriginalFileName", "sysmon", "process_creation", "win.eventdata.originalFileName"),
            ("OriginalFileName", "sysmon", "image_load", "win.eventdata.originalFileName"),
            ("Description", "sysmon", "process_creation", "win.eventdata.description"),
            ("Product", "sysmon", "process_creation", "win.eventdata.product"),
            ("Company", "sysmon", "image_load", "win.eventdata.company"),
            ("IntegrityLevel", "sysmon", "process_creation", "win.eventdata.integrityLevel"),
            ("ProcessGuid", "sysmon", "process_creation", "win.eventdata.processGuid"),
            ("ParentProcessGuid", "sysmon", "process_creation", "win.eventdata.parentProcessGuid"),
            ("ImageLoaded", "sysmon", "image_load", "win.eventdata.imageLoaded"),
            ("GrantedAccess", "sysmon", "process_access", "win.eventdata.grantedAccess"),
            ("CallTrace", "sysmon", "process_access", "win.eventdata.callTrace"),
            ("SourceProcessGuid", "sysmon", "process_access", "win.eventdata.sourceProcessGUID"),
            ("TargetProcessGuid", "sysmon", "process_access", "win.eventdata.targetProcessGUID"),
            ("PipeName", "sysmon", "pipe_created", "win.eventdata.pipeName"),
            ("Signed", "sysmon", "image_load", "win.eventdata.signed"),
            ("Signature", "sysmon", "image_load", "win.eventdata.signature"),
            ("SignatureStatus", "sysmon", "image_load", "win.eventdata.signatureStatus"),
            ("CurrentDirectory", "sysmon", "process_creation", "win.eventdata.currentDirectory"),
            ("FileVersion", "sysmon", "process_creation", "win.eventdata.fileVersion"),
            ("FileVersion", "sysmon", "image_load", "win.eventdata.fileVersion"),
            ("ParentUser", "sysmon", "process_creation", "win.eventdata.parentUser"),
            ("LogonId", "sysmon", "process_creation", "win.eventdata.logonId"),
            ("Contents", "sysmon", "create_stream_hash", "win.eventdata.contents"),
            ("Hash", "sysmon", "create_stream_hash", "win.eventdata.hash"),
            ("ScriptBlockText", "powershell", "ps_script", "win.eventdata.scriptBlockText"),
            ("Path", "powershell", "ps_script", "win.eventdata.path"),
            ("Data", "application", None, "win.eventdata.data"),
            ("AppName", "application", None, "win.eventdata.source"),
            ("ExceptionCode", "application", None, "win.eventdata.exceptionCode"),
            ("Data", "powershell-classic", None, "win.eventdata.data"),
            ("Data", None, "ps_classic_start", "win.eventdata.data"),
            ("Data", None, "ps_classic_provider_start", "win.eventdata.data"),
            ("ImagePath", "system", None, "win.eventdata.imagePath"),
            ("ServiceFileName", "system", None, "win.eventdata.imagePath"),
            ("ServiceName", "system", None, "win.eventdata.serviceName"),
            ("ObjectName", "security", None, "win.eventdata.objectName"),
            ("ProcessName", "security", None, "win.eventdata.processName"),
            ("ObjectType", "security", None, "win.eventdata.objectType"),
            ("AccessMask", "security", None, "win.eventdata.accessMask"),
            ("AccessList", "security", None, "win.eventdata.accessList"),
            ("PrivilegeList", "security", None, "win.eventdata.privilegeList"),
            ("Service", "security", None, "win.eventdata.service"),
            ("TargetName", "security", None, "win.eventdata.targetName"),
            ("KeyLength", "security", None, "win.eventdata.keyLength"),
            ("Status", "security", None, "win.eventdata.status"),
            ("Workstation", "security", None, "win.eventdata.workstation"),
            ("ProcessPath", "bits-client", None, "win.eventdata.processPath"),
            ("processPath", "bits-client", None, "win.eventdata.processPath"),
            ("LocalName", "bits-client", None, "win.eventdata.localName"),
            ("RemoteName", "bits-client", None, "win.eventdata.remoteName"),
            ("Path", "windefend", None, "win.eventdata.path"),
            ("NewValue", "windefend", None, "win.eventdata.new Value"),
            ("Path", "taskscheduler", None, "win.eventdata.path"),
            ("Action", "firewall-as", None, "win.eventdata.action"),
            ("ApplicationPath", "firewall-as", None, "win.eventdata.applicationPath"),
            ("ModifyingApplication", "firewall-as", None, "win.eventdata.modifyingApplication"),
        ],
    )
    def test_restored_fixture_backed_windows_mappings_exact_paths(
        self,
        sigma_field,
        service,
        category,
        wazuh_field,
    ):
        """Restored mappings must keep exact decoded Wazuh fixture paths."""
        registry = FieldMappingRegistry()

        result = registry.resolve(
            sigma_field,
            product="windows",
            service=service,
            category=category,
        )

        assert result.status == "resolved"
        assert result.field_name == wazuh_field
