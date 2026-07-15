"""
Windows event analysis and fixture generation package.

Provides utilities for analyzing Windows event logs, generating test fixtures,
and producing optimization reports for Windows field mappings.
"""

from wazuh_sigma.windows.analysis import (
    analyze_field_structure,
    build_inventory,
    deduplicate_by_schema,
    get_field_type,
    group_and_deduplicate,
    parse_json_files,
    schema_hash,
)
from wazuh_sigma.windows.fixture_generation import (
    build_inventory as build_fixture_inventory,
    create_fixture_content,
    create_fixtures,
    generate_field_mapping_docs,
    get_channel_filename,
    get_provider_directory_name,
)
from wazuh_sigma.windows.optimization import (
    analyze_mapping_usage,
    calculate_coverage_delta,
    create_field_resolution_matrix,
    generate_summary_markdown,
    identify_added_mappings,
    identify_removed_mappings,
    identify_unused_fixtures,
    load_evidence_classification,
    load_field_catalog,
)

__all__ = [
    # Analysis
    "analyze_field_structure",
    "build_inventory",
    "deduplicate_by_schema",
    "get_field_type",
    "group_and_deduplicate",
    "parse_json_files",
    "schema_hash",
    # Fixture Generation
    "build_fixture_inventory",
    "create_fixture_content",
    "create_fixtures",
    "generate_field_mapping_docs",
    "get_channel_filename",
    "get_provider_directory_name",
    # Optimization
    "analyze_mapping_usage",
    "calculate_coverage_delta",
    "create_field_resolution_matrix",
    "generate_summary_markdown",
    "identify_added_mappings",
    "identify_removed_mappings",
    "identify_unused_fixtures",
    "load_evidence_classification",
    "load_field_catalog",
]
