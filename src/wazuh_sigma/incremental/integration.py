"""Integration layer between converter and incremental cache service."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any
from xml.etree.ElementTree import Element

from wazuh_sigma.backend.wazuh import DEFAULT_FIELD_MAPPING
from wazuh_sigma.incremental.service import ConversionCacheStatus, IncrementalConverterService
from wazuh_sigma.sigma import SigmaRule

logger = logging.getLogger("SigmaIncremental.integration")


def effective_field_mapping(config: Any) -> dict[str, str]:
    """Return the exact field mapping contents used by the Wazuh backend."""
    mapping = dict(DEFAULT_FIELD_MAPPING)
    if config.wazuh.field_mapping:
        mapping.update(config.wazuh.field_mapping)
    return mapping


def build_incremental_service(config: Any) -> IncrementalConverterService | None:
    """Build incremental service from pipeline config.

    Returns None if incremental caching is disabled.
    """
    if not config.incremental_cache.enabled:
        return None

    return IncrementalConverterService(
        cache_dir=config.incremental_cache.directory,
        manifest_file=config.incremental_cache.manifest,
        enabled=True,
        field_mapping_version=config.wazuh.field_mapping_version,
        backend_output_version="wazuh-xml-v1",
        rule_id_range=(config.wazuh.rule_id_start, config.wazuh.rule_id_end),
        field_mapping=effective_field_mapping(config),
        backend_settings={
            "root_group_name": "sigma_rules,",
        },
        strict_cache=config.incremental_cache.strict,
    )


def process_rule_with_cache(
    service: IncrementalConverterService | None,
    sigma_rule: SigmaRule,
    source_path: str | None = None,
    advisor_level_override: int | None = None,
) -> tuple[ConversionCacheStatus | None, int | None]:
    """Check incremental cache for rule and allocate Wazuh ID.

    Returns: (cache_status, wazuh_rule_id)

    cache_status is None if incremental caching is disabled.
    wazuh_rule_id is allocated regardless of cache hit/miss.
    """
    if service is None:
        return None, None

    status, _ = service.process_rule(
        sigma_rule,
        source_path=source_path,
        advisor_level_override=advisor_level_override,
    )
    return status, status.wazuh_rule_id


def extract_cached_xml(status: ConversionCacheStatus) -> Element | None:
    """Parse cached XML fragment into an Element.

    Returns None if not cached.
    """
    if not status.cached:
        return None

    try:
        return ET.fromstring(status.xml_fragment)
    except ET.ParseError as e:
        logger.warning("Cached XML fragment is malformed: %s", e)
        return None


def record_conversion_for_cache(
    service: IncrementalConverterService | None,
    status: ConversionCacheStatus | None,
    xml_element: Element,
    sigma_title: str,
) -> None:
    """Store freshly converted rule in cache."""
    if service is None or status is None:
        return

    if status.cached:
        return  # Already cached

    # Serialize element to store in cache
    xml_str = ET.tostring(xml_element, encoding="unicode")
    service.store_converted_fragment(status, xml_str, sigma_title)


def finalize_incremental_manifest(
    service: IncrementalConverterService | None,
    current_rule_identities: set[str],
) -> dict[str, Any] | None:
    """Finalize manifest and return report data.

    Must be called after all rules are processed.
    """
    if service is None:
        return None

    manifest = service.finalize_manifest(current_rule_identities)
    service.save_manifest()
    return service.get_report_data()
