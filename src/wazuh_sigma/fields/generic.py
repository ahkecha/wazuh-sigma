"""Generic field resolution for non-Windows log sources."""

from __future__ import annotations


class GenericFieldMapper:
    """Handles field mapping for non-Windows log sources.

    For non-Windows sources, we use a simple safe fallback that maintains
    backward compatibility while avoiding silent corruption of field names.
    """

    @staticmethod
    def resolve(sigma_field: str, mode: str = "strict") -> str | None:
        """Resolve a field name generically (for non-Windows sources).

        Args:
            sigma_field: The Sigma field name
            mode: Resolution behavior:
                - 'strict': Return None for unknown fields
                - 'warn': Return safe lowercase version with warning context
                - 'legacy': Return lowercase version (unsafe fallback)

        Returns:
            A field name suitable for Wazuh, or None if unknown and strict mode
        """
        if mode not in ("strict", "warn", "legacy"):
            raise ValueError(f"Invalid mode: {mode!r}")

        if mode == "strict":
            return None
        elif mode == "warn":
            # Caller will log a warning; return a safe lowercase version
            return sigma_field.lower().replace(" ", "_")
        else:  # legacy
            # Unsafe fallback for backward compatibility
            return sigma_field.lower().replace(" ", "_")
