# Windows Analysis Package Quick Start Guide

## Overview

The `wazuh_sigma.windows` package provides three integrated tools for Windows event analysis, fixture generation, and optimization reporting.

## Installation

The package is part of the main project. No additional installation needed beyond the project setup.

## Command Line Usage

### 1. Audit Windows Events

Analyze Windows events from JSON files extracted from Elasticsearch or Wazuh logs.

```bash
sigma-windows-analysis audit \
  --input-dir local \
  --output inventory.json
```

**Options:**
- `--input-dir` (default: `local`) - Directory containing JSON event files
- `--output` - Output file for inventory JSON (default: stdout)

**Output Example:**
```json
{
  "total_events": 150,
  "total_unique_schemas": 12,
  "event_groups": [
    {
      "provider": "Microsoft-Windows-Security-Auditing",
      "channel": "Security",
      "eventID": "4688",
      "eventCount": 45,
      "system_fields": {...},
      "eventdata_fields": {...},
      "sample_event": {...}
    }
  ]
}
```

### 2. Build Fixtures

Generate test fixtures from Windows event groups.

```bash
sigma-windows-analysis build-fixtures \
  --input inventory.json \
  --output-dir tests/fixtures/wazuh \
  --inventory-file build/reports/fixture_inventory.json \
  --docs-file docs/windows_field_mapping.md
```

**Options:**
- `--input` (required) - JSON file from `audit` command
- `--output-dir` (default: `tests/fixtures/wazuh`) - Fixture output directory
- `--inventory-file` - Inventory report location
- `--docs-file` - Field mapping documentation location

**Generated Files:**
```
tests/fixtures/wazuh/
├── security/
│   ├── security_event_4624.json
│   ├── security_event_4688.json
│   └── ...
├── sysmon/
│   ├── operational_event_1.json
│   └── ...
└── system/
    └── ...
```

### 3. Optimize Field Mappings

Generate comprehensive optimization reports for Windows field mappings.

```bash
sigma-windows-analysis optimize \
  --fixtures-dir tests/fixtures \
  --reports-dir build/reports \
  --output-format all
```

**Options:**
- `--fixtures-dir` (default: `tests/fixtures`) - Fixtures directory
- `--reports-dir` (default: `build/reports`) - Reports output directory
- `--output-format` (default: `all`) - Format: `json`, `markdown`, or `all`

**Generated Reports:**
- `windows-mapping-usage.json` - Detailed mapping analysis
- `windows-mappings-removed.json` - Deprecated mappings
- `windows-mappings-added.json` - Newly validated mappings
- `windows-field-resolution.json` - Field resolution matrix
- `windows-coverage-delta.json` - Coverage metrics
- `windows-unused-fixtures.json` - Low-value fixtures
- `windows-optimization-summary.md` - Executive summary

## Programmatic Usage

### Example 1: Analyze Events and Get Inventory

```python
from pathlib import Path
from wazuh_sigma.windows.analysis import (
    parse_json_files,
    group_and_deduplicate,
    build_inventory,
)

# Parse events from JSON files
events = parse_json_files(Path("local"))

# Group and deduplicate
grouped_events = group_and_deduplicate(events)

# Build inventory
inventory = build_inventory(grouped_events)

# Access results
for item in inventory:
    print(f"{item['provider']}/{item['channel']}: {item['eventID']} ({item['eventCount']} events)")
```

### Example 2: Create Fixtures Programmatically

```python
from pathlib import Path
from wazuh_sigma.windows.fixture_generation import (
    create_fixtures,
    build_inventory,
)
from datetime import datetime, timezone

# Create fixtures from event groups
event_groups_file = Path("inventory.json")
fixtures_dir = Path("tests/fixtures/wazuh")
extracted_at = datetime.now(timezone.utc).isoformat() + "Z"

created, updated = create_fixtures(event_groups_file, fixtures_dir, extracted_at)
print(f"Created {created} fixtures")

# Build inventory report
inventory = build_inventory(event_groups_file, fixtures_dir)
print(f"Total fixtures: {len(inventory['fixtures'])}")
```

### Example 3: Analyze Field Mappings

```python
from wazuh_sigma.windows.optimization import (
    load_field_catalog,
    load_evidence_classification,
    analyze_mapping_usage,
)
from pathlib import Path

# Load data
fixtures_dir = Path("tests/fixtures")
reports_dir = Path("build/reports")
catalog = load_field_catalog(fixtures_dir)
evidence = load_evidence_classification(reports_dir)

# Analyze (requires field models to be available)
try:
    from wazuh_sigma.fields.windows import WINDOWS_FIELD_MAPPINGS
    usage_data = analyze_mapping_usage(WINDOWS_FIELD_MAPPINGS, catalog, evidence)
    
    # Show statistics
    verified = sum(1 for m in usage_data.values() if m['confidence'] == 'verified')
    high = sum(1 for m in usage_data.values() if m['confidence'] == 'high')
    print(f"Verified: {verified}, High confidence: {high}")
except ImportError:
    print("Field models not available")
```

## Complete Workflow Example

### Step 1: Prepare Windows Event JSON Files

Place Windows event JSON files in a `local/` directory. Each file should contain Elasticsearch response format:

```json
{
  "hits": {
    "hits": [
      {
        "_source": {
          "data": {
            "win": {
              "system": {
                "providerName": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "eventID": "4624"
              },
              "eventdata": {
                "LogonType": "2",
                "TargetUserName": "SYSTEM"
              }
            }
          }
        }
      }
    ]
  }
}
```

### Step 2: Run the Complete Pipeline

```bash
# Step 1: Analyze events and create inventory
sigma-windows-analysis audit \
  --input-dir local \
  --output inventory.json

# Step 2: Generate fixtures
sigma-windows-analysis build-fixtures \
  --input inventory.json \
  --output-dir tests/fixtures/wazuh

# Step 3: Generate optimization reports
sigma-windows-analysis optimize \
  --fixtures-dir tests/fixtures \
  --reports-dir build/reports \
  --output-format all
```

### Step 3: Review Results

```bash
# View event summary
cat inventory.json | jq '.total_events, .total_unique_schemas'

# Check generated fixtures
ls -lR tests/fixtures/wazuh/

# Read optimization summary
cat build/reports/windows-optimization-summary.md
```

## Package API Reference

### Analysis Module

```python
from wazuh_sigma.windows.analysis import *

# Type detection
type_str: str = get_field_type(value: Any) -> str

# Field analysis
structure: Dict[str, str] = analyze_field_structure(data: Dict[str, Any]) -> Dict[str, str]

# Hashing
hash_val: str = schema_hash(structure: Dict[str, str]) -> str

# Event processing
events: List[Dict[str, Any]] = parse_json_files(directory: Path) -> List[Dict[str, Any]]

# Grouping
grouped = group_and_deduplicate(events: List[Dict[str, Any]]) -> Dict[Tuple[str, str, str], List[Dict[str, Any]]]

# Deduplication
by_schema = deduplicate_by_schema(events_with_schema: List[Dict[str, Any]]) -> Dict[Tuple[str, str], List[Dict[str, Any]]]

# Inventory
inventory = build_inventory(grouped_events: Dict) -> List[Dict[str, Any]]
```

### Fixture Generation Module

```python
from wazuh_sigma.windows.fixture_generation import *

# Fixture content
fixture = create_fixture_content(event_group: Dict[str, Any], extracted_at: str) -> Dict[str, Any]

# Provider naming
provider_dir = get_provider_directory_name(provider: str) -> str

# Filename generation
filename = get_channel_filename(channel: str, event_id: str) -> str

# Batch creation
created, updated = create_fixtures(
    event_groups_file: Path,
    fixtures_base: Path,
    extracted_at: str,
) -> Tuple[int, int]

# Inventory building
inventory = build_inventory(event_groups_file: Path, fixtures_base: Path) -> Dict[str, Any]

# Documentation
docs = generate_field_mapping_docs(event_groups_file: Path) -> str
```

### Optimization Module

```python
from wazuh_sigma.windows.optimization import *

# Data loading
catalog = load_field_catalog(fixtures_dir: Path) -> Dict[str, Any]
evidence = load_evidence_classification(reports_dir: Path) -> Dict[str, Any]

# Analysis
usage_data = analyze_mapping_usage(
    mappings: Tuple[FieldMapping, ...],
    catalog: Dict[str, Any],
    evidence: Dict[str, Any],
) -> Dict[str, Any]

# Identification
removed = identify_removed_mappings(current_mappings: Set[str]) -> Dict[str, Any]
added = identify_added_mappings() -> Dict[str, Any]
unused = identify_unused_fixtures(fixtures_dir: Path) -> Dict[str, Any]

# Matrix creation
matrix = create_field_resolution_matrix(
    mappings: Tuple[FieldMapping, ...],
    catalog: Dict[str, Any],
    evidence: Dict[str, Any],
) -> Dict[str, Any]

# Coverage analysis
delta = calculate_coverage_delta() -> Dict[str, Any]

# Reporting
summary = generate_summary_markdown(
    usage_data: Dict[str, Any],
    removed: Dict[str, Any],
    added: Dict[str, Any],
    delta: Dict[str, Any],
) -> str
```

## Troubleshooting

### Issue: "No events found in JSON files"

**Solution**: Ensure JSON files are in Elasticsearch response format with `hits.hits[].\_source.data.win` structure.

### Issue: "Field mapping models not available"

**Solution**: This is expected when field model module is not installed. Optimization reports will be partial but functional.

### Issue: "Invalid JSON in output file"

**Solution**: Check that output directory exists and is writable. Use `--output-dir` with explicit path.

## Best Practices

1. **Version Control**: Store inventory JSON files in git for tracking changes
2. **Fixture Organization**: Use consistent provider/channel naming in fixtures
3. **Report Reviews**: Review optimization reports before making mapping changes
4. **Backup**: Keep backup of original event JSON files
5. **Documentation**: Keep field mapping documentation up-to-date

## Support

For issues or questions:
1. Check `WINDOWS_REFACTORING_SUMMARY.md` for detailed architecture
2. Review test cases in `tests/test_windows_cli.py`
3. Check function docstrings: `help(function_name)`
4. Run with `--help` for command-line options

## Related Documentation

- `docs/PROJECT_STRUCTURE.md` - Package structure overview
- `docs/ARCHITECTURE.md` - System architecture
- `WINDOWS_REFACTORING_SUMMARY.md` - Refactoring details and migration guide
