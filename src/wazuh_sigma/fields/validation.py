"""Field validation and schema checks."""

from __future__ import annotations

from wazuh_sigma.fields.models import FieldMapping, FieldNamespace


class FieldValidator:
    """Validates fields against Wazuh decoded event schemas."""

    @staticmethod
    def validate_windows_field_format(wazuh_field: str) -> tuple[bool, str]:
        """Validate that a Windows field has correct format.

        Args:
            wazuh_field: The Wazuh field name to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not wazuh_field.startswith("win."):
            return False, f"Windows field must start with 'win.' prefix, got: {wazuh_field!r}"

        parts = wazuh_field.split(".")
        if len(parts) < 3:
            return (
                False,
                f"Windows field must have at least 3 parts (win.namespace.fieldname), got: {wazuh_field!r}",
            )

        namespace = parts[1]
        if namespace not in ("system", "eventdata"):
            return (
                False,
                f"Windows field namespace must be 'system' or 'eventdata', got: {namespace!r}",
            )

        field_name = parts[2]
        if not field_name:
            return False, f"Windows field name cannot be empty: {wazuh_field!r}"

        # Field name should use camelCase (no underscores, preserved case)
        if "_" in field_name:
            return (
                False,
                f"Windows field name should use camelCase, not snake_case: {wazuh_field!r}",
            )

        return True, ""

    @staticmethod
    def validate_mapping_consistency(mapping: FieldMapping) -> tuple[bool, str]:
        """Validate that a mapping is internally consistent.

        Args:
            mapping: The mapping to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Namespace must match field prefix
        if mapping.wazuh_field.startswith("win."):
            is_valid, msg = FieldValidator.validate_windows_field_format(mapping.wazuh_field)
            if not is_valid:
                return False, msg

            extracted_ns = FieldNamespace(mapping.wazuh_field.split(".")[1])
            if extracted_ns != mapping.namespace:
                return (
                    False,
                    f"Namespace mismatch: field prefix indicates {extracted_ns.value} "
                    f"but mapping specifies {mapping.namespace.value}",
                )

        return True, ""

    @staticmethod
    def validate_against_fixture(
        mapping: FieldMapping,
        decoded_event: dict,
    ) -> tuple[bool, str]:
        """Validate that a field mapping exists in a decoded event.

        Args:
            mapping: The mapping to validate
            decoded_event: A decoded Wazuh event as a dict

        Returns:
            Tuple of (field_exists, error_message)
        """
        parts = mapping.wazuh_field.split(".")
        current = decoded_event
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return (
                    False,
                    f"Field {mapping.wazuh_field!r} not found in decoded event",
                )
        return True, ""
