"""Field mapping registry with context-aware lookup."""

from __future__ import annotations

from typing import Sequence

from wazuh_sigma.fields.errors import InvalidMappingConfigError, UnsupportedWindowsFieldError
from wazuh_sigma.fields.models import FieldMapping, FieldNamespace, FieldResolutionResult
from wazuh_sigma.fields.windows import WINDOWS_FIELD_MAPPINGS


class FieldMappingRegistry:
    """Registry for Sigma field to Wazuh field mappings.

    Provides context-aware lookup based on product, service, and category.
    """

    def __init__(self, mappings: Sequence[FieldMapping] | None = None):
        self.mappings = list(mappings) if mappings else list(WINDOWS_FIELD_MAPPINGS)
        self._index: dict[str, FieldMapping] = {}
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        """Build a quick lookup index."""
        self._index.clear()
        for mapping in self.mappings:
            # Index by sigma_field for quick lookup (assumes no duplicates with same context)
            key = mapping.sigma_field
            if key not in self._index:
                self._index[key] = mapping

    def lookup(
        self,
        sigma_field: str,
        *,
        product: str | None = None,
        service: str | None = None,
        category: str | None = None,
    ) -> FieldMapping | None:
        """Look up a mapping for the given Sigma field and context.

        Returns the mapping if found, None if no exact match but lookup is optional,
        or raises an exception for unsupported Windows fields.

        Args:
            sigma_field: The Sigma field name to look up
            product: Log source product (e.g., 'windows')
            service: Log source service (e.g., 'sysmon', 'security')
            category: Log source category (e.g., 'process_creation')

        Returns:
            FieldMapping if found and applicable to context
            None if no mapping exists
        """
        # Find all mappings for this field
        candidates = [m for m in self.mappings if m.sigma_field == sigma_field]

        if not candidates:
            return None

        # Filter by context
        applicable = [
            m
            for m in candidates
            if m.applies_to(product=product, service=service, category=category)
        ]

        if applicable:
            # Prefer more specific mappings (with services/categories)
            applicable.sort(
                key=lambda m: (len(m.services) + len(m.categories)), reverse=True
            )
            return applicable[0]

        # No exact context match. If a mapping exists without context restrictions, use it
        unrestricted = [
            m
            for m in candidates
            if not m.products and not m.services and not m.categories
        ]
        if unrestricted:
            return unrestricted[0]

        # Multiple candidates but none match the context
        if candidates:
            return None

        return None

    def resolve(
        self,
        sigma_field: str,
        *,
        product: str | None = None,
        service: str | None = None,
        category: str | None = None,
        mode: str = "strict",
    ) -> FieldResolutionResult:
        """Resolve a Sigma field to a Wazuh field name, returning structured result.

        Args:
            sigma_field: The Sigma field name
            product: Log source product
            service: Log source service
            category: Log source category
            mode: Resolution mode:
                - 'strict': Raise for unsupported Windows fields, return unsupported for non-Windows unknowns
                - 'warn': Return warning status for unsupported Windows fields, do not emit
                - 'legacy': Allow lowercase fallback for all unknown fields (unsafe)

        Returns:
            FieldResolutionResult with status indicating safety level and field_name (if safe to emit)

        Raises:
            UnsupportedWindowsFieldError: If Windows field is unsupported and mode is 'strict'
            ValueError: If mode is invalid
        """
        if mode not in ("strict", "warn", "legacy"):
            raise ValueError(f"Invalid mode: {mode!r}. Must be 'strict', 'warn', or 'legacy'")

        mapping = self.lookup(
            sigma_field,
            product=product,
            service=service,
            category=category,
        )

        if mapping:
            # Field found and verified
            return FieldResolutionResult(
                field_name=mapping.wazuh_field,
                status="resolved",
                verification=mapping.verification_source,
            )

        # No mapping found
        normalized_product = product.lower() if product else None

        if normalized_product == "windows":
            if mode == "strict":
                raise UnsupportedWindowsFieldError(
                    sigma_field=sigma_field,
                    product=product,
                    service=service,
                    category=category,
                )
            elif mode == "warn":
                # Windows field unsupported in warn mode: return warning, do NOT emit
                return FieldResolutionResult(
                    field_name=None,
                    status="warning",
                    warning_message=f"Unsupported Windows field {sigma_field!r} (product={product}, service={service}, category={category}): not emitting. See docs/windows-evtx-field-mapping.md for verified mappings.",
                )
            elif mode == "legacy":
                # Unsafe fallback for migration
                fallback = sigma_field.lower().replace(" ", "_")
                return FieldResolutionResult(
                    field_name=fallback,
                    status="legacy_fallback",
                    warning_message=f"Using legacy fallback {fallback!r} for unknown Windows field {sigma_field!r}",
                )

        # Non-Windows unknown field
        if mode == "warn":
            # Unknown field in warn mode: return warning, do NOT emit
            return FieldResolutionResult(
                field_name=None,
                status="warning",
                warning_message=f"Unknown field {sigma_field!r} with product={product}: not emitting.",
            )
        elif mode == "legacy":
            # Legacy mode: allow lowercase fallback for all unknowns
            fallback = sigma_field.lower().replace(" ", "_")
            return FieldResolutionResult(
                field_name=fallback,
                status="legacy_fallback",
                warning_message=f"Using legacy fallback {fallback!r} for unknown field {sigma_field!r}",
            )

        # strict mode for non-Windows: no mapping, no fallback
        return FieldResolutionResult(
            field_name=None,
            status="unsupported",
            warning_message=f"No mapping found for field {sigma_field!r} with product={product}",
        )

    def add_mapping(self, mapping: FieldMapping) -> None:
        """Add a mapping to the registry.

        Args:
            mapping: The mapping to add

        Raises:
            InvalidMappingConfigError: If the mapping is invalid or conflicts with existing mappings
        """
        self._validate_mapping(mapping)
        self.mappings.append(mapping)
        self._rebuild_index()

    def add_custom_mappings(
        self, custom_mappings: Sequence[FieldMapping], *, mode: str = "strict"
    ) -> None:
        """Add multiple custom mappings at once.

        Args:
            custom_mappings: Sequence of mappings to add
            mode: Resolution mode to validate against:
                - 'strict': Reject unprefixed Windows fields
                - 'warn': Reject unprefixed Windows fields
                - 'legacy': Allow unprefixed fallbacks

        Raises:
            InvalidMappingConfigError: If any mapping is invalid
        """
        for mapping in custom_mappings:
            self._validate_mapping(mapping)
            self._validate_custom_mapping_for_mode(mapping, mode=mode)
        self.mappings.extend(custom_mappings)
        self._rebuild_index()

    @staticmethod
    def _validate_mapping(mapping: FieldMapping) -> None:
        """Validate a mapping before adding it.

        Args:
            mapping: The mapping to validate

        Raises:
            InvalidMappingConfigError: If validation fails
        """
        if not mapping.sigma_field:
            raise InvalidMappingConfigError("Mapping must have a non-empty sigma_field")
        if not mapping.wazuh_field:
            raise InvalidMappingConfigError("Mapping must have a non-empty wazuh_field")

        # Validate namespace consistency
        if mapping.wazuh_field.startswith("win."):
            parts = mapping.wazuh_field.split(".")
            if len(parts) < 2:
                raise InvalidMappingConfigError(
                    f"Windows field {mapping.wazuh_field!r} must have namespace (e.g., win.system or win.eventdata)"
                )
            namespace_part = parts[1]
            if namespace_part not in ("system", "eventdata"):
                raise InvalidMappingConfigError(
                    f"Windows field {mapping.wazuh_field!r} must use system or eventdata namespace"
                )
            if mapping.namespace.value != namespace_part:
                raise InvalidMappingConfigError(
                    f"Namespace mismatch: field {mapping.wazuh_field!r} indicates {namespace_part} "
                    f"but namespace={mapping.namespace.value}"
                )

        # Validate documentation reference is present for verified mappings
        if mapping.confidence.value == "verified" and not mapping.documentation_reference:
            raise InvalidMappingConfigError(
                f"Verified mapping for {mapping.sigma_field!r} must have documentation_reference"
            )

    @staticmethod
    def _validate_custom_mapping_for_mode(mapping: FieldMapping, *, mode: str) -> None:
        """Validate that a custom mapping is safe for the given resolution mode.

        Custom unprefixed Windows fields (e.g., 'queryname', 'processpath') are unsafe
        in strict and warn modes because they bypass field verification.

        Args:
            mapping: The mapping to validate
            mode: Resolution mode ('strict', 'warn', 'legacy')

        Raises:
            InvalidMappingConfigError: If custom mapping violates mode safety rules
        """
        # Only check Windows products for Windows safety
        is_windows_product = any(
            p.lower() == "windows" for p in (mapping.products or ())
        )
        if not is_windows_product and not mapping.products:
            # No product restriction means it applies to Windows too
            is_windows_product = True

        if not is_windows_product:
            return

        # Check if the Wazuh field is unprefixed (not win.*)
        is_unprefixed = not mapping.wazuh_field.startswith("win.")

        if is_unprefixed and mode in ("strict", "warn"):
            raise InvalidMappingConfigError(
                f"Custom mapping {mapping.sigma_field!r} -> {mapping.wazuh_field!r} is unsafe for mode={mode!r}: "
                f"unprefixed Windows fields bypass field verification. "
                f"Use 'win.system.*' or 'win.eventdata.*' prefix, or use mode='legacy'."
            )
