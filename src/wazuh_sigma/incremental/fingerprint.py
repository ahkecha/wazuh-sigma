"""Deterministic conversion fingerprinting."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from wazuh_sigma.incremental.errors import ConversionFingerprintError
from wazuh_sigma.incremental.models import RULE_ID_ALLOCATION_VERSION
from wazuh_sigma.naming import NAMING_VERSION
from wazuh_sigma.sigma import PARSER_NORMALIZATION_VERSION, SigmaRule

logger = logging.getLogger("SigmaIncremental.fingerprint")

CONVERSION_FINGERPRINT_VERSION = "conversion-fingerprint-v1"


def compute_conversion_fingerprint(
    sigma_rule: SigmaRule,
    *,
    wazuh_rule_id: int,
    field_mapping_version: str,
    field_mapping: dict[str, str] | None = None,
    backend_output_version: str,
    rule_id_range: tuple[int, int],
    advisor_level_override: int | None = None,
    backend_settings: dict[str, Any] | None = None,
) -> str:
    """Compute deterministic SHA-256 fingerprint of conversion inputs.

    Includes every input that can affect generated XML:
    - Normalized Sigma rule
    - Wazuh rule ID
    - Converter versions
    - Field mapping version and effective mapping contents
    - Backend output version
    - Parser normalization version
    - Naming version
    - ID allocation version
    - Rule ID range
    - XML-affecting backend settings
    - Advisor effective level when XML-affecting

    Excludes:
    - Timestamps
    - Cache paths
    - API request IDs
    - Advisor report metadata (report-only/review modes)
    """
    try:
        rule_dict = sigma_rule.raw_rule
        if not rule_dict:
            raise ConversionFingerprintError("raw_rule is empty or None")

        fingerprint_material = {
            "fingerprint_version": CONVERSION_FINGERPRINT_VERSION,
            "normalized_sigma_rule": json.loads(json.dumps(rule_dict, default=str)),
            "wazuh_rule_id": wazuh_rule_id,
            "field_mapping_version": field_mapping_version,
            "field_mapping": _canonical_mapping(field_mapping),
            "backend_output_version": backend_output_version,
            "parser_normalization_version": PARSER_NORMALIZATION_VERSION,
            "naming_version": NAMING_VERSION,
            "id_allocation_version": RULE_ID_ALLOCATION_VERSION,
            "rule_id_range": list(rule_id_range),
            "backend_settings": backend_settings or {},
            "advisor_level_override": advisor_level_override,
        }

        canonical = json.dumps(
            fingerprint_material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        logger.debug(
            "Computed fingerprint for rule %s: %s",
            sigma_rule.title,
            fingerprint,
        )
        return fingerprint

    except (TypeError, ValueError) as e:
        raise ConversionFingerprintError(f"failed to compute fingerprint: {e}") from e


def _canonical_mapping(mapping: dict[str, str] | None) -> dict[str, str]:
    if not mapping:
        return {}
    return {str(key): str(value) for key, value in sorted(mapping.items())}
