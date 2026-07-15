"""Exceptions for field mapping errors."""

from __future__ import annotations


class FieldMappingError(Exception):
    """Base exception for field mapping errors."""

    pass


class UnsupportedWindowsFieldError(FieldMappingError):
    """Raised when a Windows field is not in the verified mapping registry."""

    def __init__(
        self,
        sigma_field: str,
        *,
        product: str | None = None,
        service: str | None = None,
        category: str | None = None,
        source_file: str | None = None,
        rule_title: str | None = None,
    ):
        self.sigma_field = sigma_field
        self.product = product
        self.service = service
        self.category = category
        self.source_file = source_file
        self.rule_title = rule_title

        parts = [f"Unsupported Windows field: {sigma_field!r}"]
        if rule_title:
            parts.append(f"rule: {rule_title}")
        if source_file:
            parts.append(f"source: {source_file}")

        context = []
        if product:
            context.append(f"product={product}")
        if service:
            context.append(f"service={service}")
        if category:
            context.append(f"category={category}")
        if context:
            parts.append(f"context: {', '.join(context)}")

        parts.append("See docs/windows-evtx-field-mapping.md for verified mappings.")

        super().__init__(" | ".join(parts))


class InvalidMappingConfigError(FieldMappingError):
    """Raised when field mapping configuration is invalid."""

    pass
