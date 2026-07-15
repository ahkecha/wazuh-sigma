"""
Windows analysis CLI entry point.

Exposes three commands:
- audit: Analyze Windows events from local JSON files
- build-fixtures: Generate test fixtures from event groups
- optimize: Generate optimization reports for Windows field mappings
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from wazuh_sigma.windows.analysis import (
    build_inventory,
    group_and_deduplicate,
    parse_json_files,
)
from wazuh_sigma.windows.fixture_generation import (
    build_inventory as build_fixture_inventory,
    create_fixtures,
    generate_field_mapping_docs,
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

try:
    from wazuh_sigma.fields.windows import WINDOWS_FIELD_MAPPINGS
    HAS_FIELD_MODELS = True
except ImportError:
    HAS_FIELD_MODELS = False


@click.group()
def cli() -> None:
    """Windows event analysis and fixture generation tools."""
    pass


@cli.command()
@click.option(
    "--input-dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    default="local",
    help="Directory containing JSON event files.",
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Output file for inventory JSON (default: stdout).",
)
def audit(
    input_dir: str,
    output: Optional[str],
) -> int:
    """
    Analyze Windows events from local JSON files.

    Parses JSON files from INPUT_DIR, extracts Windows events,
    groups by provider/channel/eventID, deduplicates by schema,
    and generates structured inventory.
    """
    click.echo("Analyzing Windows events...", err=True)

    input_path = Path(input_dir)
    if not input_path.exists():
        click.echo(f"Error: Directory {input_path} does not exist",
                   err=True)
        return 1

    try:
        # Parse all JSON files
        events = parse_json_files(input_path)

        if not events:
            click.echo("No events found in JSON files", err=True)
            return 1

        # Group and analyze
        grouped_events = group_and_deduplicate(events)
        click.echo(
            f"Grouped into {len(grouped_events)} "
            "(provider, channel, eventID) groups",
            err=True,
        )

        # Build inventory
        inventory_list = build_inventory(grouped_events)

        click.echo(
            f"Final inventory: {len(inventory_list)} event schemas",
            err=True,
        )
        click.echo("\n" + "=" * 80 + "\n", err=True)

        # Output structured inventory
        output_data = {
            "total_events": len(events),
            "total_unique_schemas": len(inventory_list),
            "event_groups": inventory_list,
        }

        output_json = json.dumps(output_data, indent=2)

        if output:
            Path(output).write_text(output_json, encoding="utf-8")
            click.echo(f"Inventory written to {output}", err=True)
        else:
            click.echo(output_json)

        return 0

    except (OSError, json.JSONDecodeError, TypeError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        return 1


@cli.command()
@click.option(
    "--input",
    type=click.Path(exists=True),
    required=True,
    help="JSON file with event groups from audit command.",
)
@click.option(
    "--output-dir",
    type=click.Path(),
    default="tests/fixtures/wazuh",
    help="Base directory for fixture output.",
)
@click.option(
    "--inventory-file",
    type=click.Path(),
    default=None,
    help="Output file for fixture inventory (default: "
    "build/reports/windows_fixture_inventory.json).",
)
@click.option(
    "--docs-file",
    type=click.Path(),
    default=None,
    help="Output file for field mapping docs (default: "
    "docs/windows_field_mapping.md).",
)
def build_fixtures(
    input: str,
    output_dir: str,
    inventory_file: Optional[str],
    docs_file: Optional[str],
) -> int:
    """
    Generate test fixtures from event groups.

    Reads event groups JSON from INPUT and creates fixture files
    in OUTPUT_DIR, generates inventory, and field mapping documentation.
    """
    click.echo("Creating Windows event fixtures...", err=True)

    input_path = Path(input)
    output_path = Path(output_dir)

    # Determine inventory and docs paths
    if not inventory_file:
        inventory_path = (
            Path("build/reports")
            / "windows_fixture_inventory.json"
        )
    else:
        inventory_path = Path(inventory_file)

    if not docs_file:
        docs_path = (
            Path("docs")
            / "windows_field_mapping.md"
        )
    else:
        docs_path = Path(docs_file)

    try:
        # Create directories
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        docs_path.parent.mkdir(parents=True, exist_ok=True)

        # Create fixtures
        from datetime import datetime, timezone
        extracted_at = datetime.now(timezone.utc).isoformat() + "Z"

        created, updated = create_fixtures(
            input_path,
            output_path,
            extracted_at,
        )
        click.echo(
            f"Created: {created}, Updated: {updated}",
            err=True,
        )

        # Build inventory
        click.echo("Building fixture inventory...", err=True)
        inventory = build_fixture_inventory(input_path, output_path)
        inventory_path.write_text(
            json.dumps(inventory, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        click.echo(f"✓ Inventory: {inventory_path}", err=True)

        # Generate documentation
        click.echo(
            "Generating field mapping documentation...",
            err=True,
        )
        mapping_doc = generate_field_mapping_docs(input_path)
        docs_path.write_text(mapping_doc, encoding="utf-8")
        click.echo(f"✓ Documentation: {docs_path}", err=True)

        # Return results
        result = {
            "fixtures_created": created,
            "fixtures_updated": updated,
            "inventory_file": str(inventory_path),
            "docs_file": str(docs_path),
        }

        click.echo("\n" + "=" * 80)
        click.echo(json.dumps(result, indent=2))

        return 0

    except (OSError, json.JSONDecodeError, TypeError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        return 1


@cli.command()
@click.option(
    "--fixtures-dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    default="tests/fixtures",
    help="Path to fixtures directory.",
)
@click.option(
    "--reports-dir",
    type=click.Path(),
    default="build/reports",
    help="Output directory for reports.",
)
@click.option(
    "--output-format",
    type=click.Choice(["json", "markdown", "all"]),
    default="all",
    help="Output format for reports.",
)
def optimize(
    fixtures_dir: str,
    reports_dir: str,
    output_format: str,
) -> int:
    """
    Generate optimization reports for Windows field mappings.

    Analyzes Windows field mappings against the fixture corpus
    and produces comprehensive optimization reports.
    """
    click.echo(
        "Generating Windows mapping optimization reports...",
        err=True,
    )

    fixtures_path = Path(fixtures_dir)
    reports_path = Path(reports_dir)

    try:
        # Create output directory
        reports_path.mkdir(parents=True, exist_ok=True)

        click.echo("Loading data...", err=True)
        catalog = load_field_catalog(fixtures_path)
        evidence = load_evidence_classification(reports_path)

        if not HAS_FIELD_MODELS:
            click.echo(
                "Warning: Field mapping models not available. "
                "Skipping detailed analysis.",
                err=True,
            )
            # Return basic report structure
            click.echo(json.dumps({
                "status": "partial",
                "message": (
                    "Field mapping models not available. "
                    "Please ensure wazuh_sigma.fields is importable."
                ),
            }, indent=2))
            return 0

        click.echo(
            f"Found {len(WINDOWS_FIELD_MAPPINGS)} mappings",
            err=True,
        )
        click.echo(
            f"Fixture catalog has "
            f"{len(catalog.get('eventdata_fields', {}))} "
            "eventdata fields",
            err=True,
        )

        # Generate all reports
        click.echo("Analyzing mapping usage...", err=True)
        usage_data = analyze_mapping_usage(
            WINDOWS_FIELD_MAPPINGS,
            catalog,
            evidence,
        )

        click.echo("Analyzing removed mappings...", err=True)
        current_sigma_fields = set(
            m.sigma_field for m in WINDOWS_FIELD_MAPPINGS
        )
        removed = identify_removed_mappings(current_sigma_fields)

        click.echo("Analyzing added mappings...", err=True)
        added = identify_added_mappings()

        click.echo("Creating field resolution matrix...", err=True)
        resolution_matrix = create_field_resolution_matrix(
            WINDOWS_FIELD_MAPPINGS,
            catalog,
            evidence,
        )

        click.echo("Calculating coverage delta...", err=True)
        delta = calculate_coverage_delta()

        click.echo("Identifying unused fixtures...", err=True)
        unused_fixtures = identify_unused_fixtures(fixtures_path)

        # Write reports
        click.echo("Writing reports...", err=True)

        if output_format in ["json", "all"]:
            # 1. Windows mapping usage
            report_file = reports_path / "windows-mapping-usage.json"
            report_file.write_text(
                json.dumps(usage_data, indent=2),
                encoding="utf-8",
            )

            # 2. Windows mappings removed
            report_file = reports_path / "windows-mappings-removed.json"
            report_file.write_text(
                json.dumps(removed, indent=2),
                encoding="utf-8",
            )

            # 3. Windows mappings added
            report_file = reports_path / "windows-mappings-added.json"
            report_file.write_text(
                json.dumps(added, indent=2),
                encoding="utf-8",
            )

            # 4. Windows field resolution
            report_file = (
                reports_path / "windows-field-resolution.json"
            )
            report_file.write_text(
                json.dumps(resolution_matrix, indent=2),
                encoding="utf-8",
            )

            # 5. Windows coverage delta
            report_file = reports_path / "windows-coverage-delta.json"
            report_file.write_text(
                json.dumps(delta, indent=2),
                encoding="utf-8",
            )

            # 6. Windows unused fixtures
            report_file = reports_path / "windows-unused-fixtures.json"
            report_file.write_text(
                json.dumps(unused_fixtures, indent=2),
                encoding="utf-8",
            )

        if output_format in ["markdown", "all"]:
            # 7. Summary markdown
            summary = generate_summary_markdown(
                usage_data,
                removed,
                added,
                delta,
            )
            report_file = (
                reports_path / "windows-optimization-summary.md"
            )
            report_file.write_text(summary, encoding="utf-8")

        click.echo("Reports generated successfully!", err=True)

        # Print summary
        click.echo("\n" + "=" * 70, err=True)
        click.echo("WINDOWS MAPPING OPTIMIZATION REPORTS", err=True)
        click.echo("=" * 70, err=True)
        click.echo(
            f"\nTotal Mappings Analyzed: {len(usage_data)}",
            err=True,
        )
        click.echo(
            f"  - VERIFIED: "
            f"{sum(1 for m in usage_data.values() if m['confidence'] == 'verified')}",
            err=True,
        )
        click.echo(
            f"  - HIGH: "
            f"{sum(1 for m in usage_data.values() if m['confidence'] == 'high')}",
            err=True,
        )
        click.echo(
            f"  - PROVISIONAL: "
            f"{sum(1 for m in usage_data.values() if m['confidence'] == 'provisional')}",
            err=True,
        )
        click.echo(
            f"\nMappings with Fixture Evidence: "
            f"{sum(1 for m in usage_data.values() if m['corpus_usage_count'] > 0)}",
            err=True,
        )
        click.echo(
            f"Conversion Rate Improvement: "
            f"+{delta['improvements']['conversion_rate_gain']}%",
            err=True,
        )
        click.echo(
            f"Additional Rules Converted: "
            f"+{delta['improvements']['additional_rules_converted']}",
            err=True,
        )
        click.echo(f"\nReports written to: {reports_path}", err=True)

        # Return success
        click.echo(json.dumps({
            "status": "success",
            "reports_dir": str(reports_path),
            "mappings_analyzed": len(usage_data),
            "verified_mappings": sum(
                1 for m in usage_data.values()
                if m["confidence"] == "verified"
            ),
        }, indent=2))

        return 0

    except (OSError, json.JSONDecodeError, TypeError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


def main() -> int:
    """CLI entry point."""
    return cli() or 0  # type: ignore


if __name__ == "__main__":
    sys.exit(main())
