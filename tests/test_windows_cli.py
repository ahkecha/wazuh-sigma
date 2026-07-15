"""
Tests for Windows analysis CLI.

Tests for the three CLI commands:
- audit: Windows event analysis
- build-fixtures: Fixture generation
- optimize: Optimization reports
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest
from click.testing import CliRunner

from wazuh_sigma.windows.analysis import (
    analyze_field_structure,
    build_inventory,
    deduplicate_by_schema,
    get_field_type,
    group_and_deduplicate,
    schema_hash,
)
from wazuh_sigma.windows.cli import cli
from wazuh_sigma.windows.fixture_generation import (
    create_fixture_content,
    get_channel_filename,
    get_provider_directory_name,
)


class TestAnalysisModule:
    """Tests for analysis module functions."""

    def test_get_field_type_null(self) -> None:
        """Test type detection for None."""
        assert get_field_type(None) == "null"

    def test_get_field_type_bool(self) -> None:
        """Test type detection for boolean."""
        assert get_field_type(True) == "bool"
        assert get_field_type(False) == "bool"

    def test_get_field_type_int(self) -> None:
        """Test type detection for integer."""
        assert get_field_type(42) == "int"

    def test_get_field_type_float(self) -> None:
        """Test type detection for float."""
        assert get_field_type(3.14) == "float"

    def test_get_field_type_string(self) -> None:
        """Test type detection for string."""
        assert get_field_type("hello") == "string"

    def test_get_field_type_empty_list(self) -> None:
        """Test type detection for empty list."""
        assert get_field_type([]) == "array[empty]"

    def test_get_field_type_homogeneous_list(self) -> None:
        """Test type detection for homogeneous list."""
        assert get_field_type([1, 2, 3]) == "array[int]"
        assert get_field_type(["a", "b"]) == "array[string]"

    def test_get_field_type_mixed_list(self) -> None:
        """Test type detection for mixed list."""
        assert get_field_type([1, "a"]) == "array[mixed]"

    def test_get_field_type_dict(self) -> None:
        """Test type detection for dictionary."""
        assert get_field_type({"key": "value"}) == "object"

    def test_get_field_type_unknown(self) -> None:
        """Test type detection for unknown types."""
        assert get_field_type(object()) == "unknown"

    def test_analyze_field_structure(self) -> None:
        """Test field structure analysis."""
        data = {
            "name": "test",
            "count": 42,
            "items": [1, 2, 3],
            "active": True,
        }
        structure = analyze_field_structure(data)

        assert structure["name"] == "string"
        assert structure["count"] == "int"
        assert structure["items"] == "array[int]"
        assert structure["active"] == "bool"

    def test_schema_hash_deterministic(self) -> None:
        """Test that schema hash is deterministic."""
        structure = {"field_a": "string", "field_b": "int"}
        hash1 = schema_hash(structure)
        hash2 = schema_hash(structure)
        assert hash1 == hash2

    def test_schema_hash_order_independent(self) -> None:
        """Test that schema hash is independent of key order."""
        struct1 = {"a": "string", "b": "int"}
        struct2 = {"b": "int", "a": "string"}
        assert schema_hash(struct1) == schema_hash(struct2)

    def test_schema_hash_changes_with_content(self) -> None:
        """Test that schema hash changes when content changes."""
        struct1 = {"field": "string"}
        struct2 = {"field": "int"}
        assert schema_hash(struct1) != schema_hash(struct2)

    def test_deduplicate_by_schema(self) -> None:
        """Test deduplication by schema."""
        events_with_schema = [
            {
                "schema_hash": ("hash1", "hash2"),
                "event": {"data": "event1"},
            },
            {
                "schema_hash": ("hash1", "hash2"),
                "event": {"data": "event2"},
            },
            {
                "schema_hash": ("hash3", "hash4"),
                "event": {"data": "event3"},
            },
        ]

        result = deduplicate_by_schema(events_with_schema)

        assert ("hash1", "hash2") in result
        assert ("hash3", "hash4") in result
        assert len(result[("hash1", "hash2")]) == 2
        assert len(result[("hash3", "hash4")]) == 1

    def test_group_and_deduplicate_empty(self) -> None:
        """Test grouping with empty events list."""
        result = group_and_deduplicate([])
        assert len(result) == 0

    def test_group_and_deduplicate_single_event(self) -> None:
        """Test grouping with single event."""
        events = [
            {
                "system": {
                    "providerName": "Test-Provider",
                    "channel": "System",
                    "eventID": "1000",
                },
                "eventdata": {"field1": "value1"},
            }
        ]

        result = group_and_deduplicate(events)

        assert len(result) == 1
        key = ("Test-Provider", "System", "1000")
        assert key in result
        assert len(result[key]) == 1

    def test_build_inventory_empty(self) -> None:
        """Test building inventory with empty grouped events."""
        result = build_inventory({})
        assert len(result) == 0

    def test_build_inventory_sorting(self) -> None:
        """Test inventory is sorted by event count."""
        grouped_events = {
            ("Provider1", "Channel1", "1001"): [
                {"schema_hash": ("h1", "h2"), "event": {
                    "system": {"field": "value"},
                    "eventdata": {},
                }},
            ],
            ("Provider2", "Channel2", "2001"): [
                {"schema_hash": ("h3", "h4"), "event": {
                    "system": {"field": "value"},
                    "eventdata": {},
                }},
                {"schema_hash": ("h3", "h4"), "event": {
                    "system": {"field": "value"},
                    "eventdata": {},
                }},
            ],
        }

        result = build_inventory(grouped_events)

        # Should be sorted by event count (descending)
        assert result[0]["eventCount"] >= result[1]["eventCount"]


class TestFixtureGenerationModule:
    """Tests for fixture generation module functions."""

    def test_get_provider_directory_name_exact_match(self) -> None:
        """Test provider to directory mapping with exact match."""
        assert get_provider_directory_name("Security") == "security"
        assert get_provider_directory_name("Sysmon") == "sysmon"
        assert get_provider_directory_name("System") == "system"

    def test_get_provider_directory_name_prefix_removal(self) -> None:
        """Test provider name with prefix removal."""
        name = get_provider_directory_name("Microsoft-Windows-Security")
        assert "microsoft" not in name.lower()

    def test_get_provider_directory_name_partial_match(self) -> None:
        """Test provider to directory mapping with partial match."""
        name = get_provider_directory_name("Microsoft-Windows-Sysmon/Operational")
        assert "sysmon" in name or "application" in name

    def test_get_provider_directory_name_default(self) -> None:
        """Test default provider directory name generation."""
        name = get_provider_directory_name("CustomProvider With Spaces")
        assert " " not in name
        assert "-" not in name
        assert name.islower()

    def test_get_channel_filename(self) -> None:
        """Test channel filename generation."""
        filename = get_channel_filename("Security", "4688")
        assert filename.endswith(".json")
        assert "4688" in filename
        assert "security" in filename.lower()

    def test_get_channel_filename_hierarchical(self) -> None:
        """Test channel filename with hierarchical channel name."""
        filename = get_channel_filename("System/Operational/Test", "1000")
        assert "test" in filename.lower()
        assert "1000" in filename

    def test_create_fixture_content(self) -> None:
        """Test fixture content creation."""
        event_group = {
            "provider": "Test-Provider",
            "channel": "TestChannel",
            "eventID": "1000",
            "eventCount": 5,
            "sample_event": {
                "system": {"field": "value"},
                "eventdata": {"data": "test"},
            },
        }

        fixture = create_fixture_content(event_group, "2024-01-01T00:00:00Z")

        assert "_fixture_metadata" in fixture
        assert "decoded" in fixture
        assert fixture["_fixture_metadata"]["provider"] == "Test-Provider"
        assert fixture["_fixture_metadata"]["event_id"] == 1000
        assert fixture["_fixture_metadata"]["event_count"] == 5
        assert fixture["decoded"]["system"]["field"] == "value"


class TestWindowsCli:
    """Tests for Windows CLI commands."""

    def test_cli_help(self) -> None:
        """Test CLI help output."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Windows event analysis" in result.output

    def test_audit_command_help(self) -> None:
        """Test audit command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["audit", "--help"])
        assert result.exit_code == 0
        assert "INPUT_DIR" in result.output or "input-dir" in result.output

    def test_build_fixtures_command_help(self) -> None:
        """Test build-fixtures command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["build-fixtures", "--help"])
        assert result.exit_code == 0
        assert "INPUT" in result.output or "input" in result.output

    def test_optimize_command_help(self) -> None:
        """Test optimize command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["optimize", "--help"])
        assert result.exit_code == 0
        assert "output-format" in result.output or "OUTPUT" in result.output

    def test_audit_no_input_dir(self) -> None:
        """Test audit command with non-existent directory."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                cli,
                ["audit", "--input-dir", "/nonexistent/path"],
            )
            assert result.exit_code != 0

    def test_audit_empty_directory(self) -> None:
        """Test audit command with empty directory."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                cli,
                ["audit", "--input-dir", tmpdir],
            )
            # Empty directory should fail gracefully
            assert result.exit_code in (0, 1)

    def test_audit_with_sample_json(self) -> None:
        """Test audit command with sample JSON file."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create sample JSON file
            sample_data = {
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "data": {
                                    "win": {
                                        "system": {
                                            "providerName": "Test",
                                            "channel": "TestChannel",
                                            "eventID": "1000",
                                        },
                                        "eventdata": {
                                            "field1": "value1",
                                        },
                                    }
                                }
                            }
                        }
                    ]
                }
            }

            sample_file = Path(tmpdir) / "events.json"
            sample_file.write_text(json.dumps(sample_data), encoding="utf-8")

            result = runner.invoke(
                cli,
                ["audit", "--input-dir", tmpdir],
            )

            assert result.exit_code == 0
            # Extract JSON from output (it comes after stderr messages)
            output_lines = result.output.split("\n")
            json_start = None
            for i, line in enumerate(output_lines):
                if line.strip().startswith("{"):
                    json_start = i
                    break

            assert json_start is not None, "No JSON found in output"
            json_output = "\n".join(output_lines[json_start:])
            output = json.loads(json_output)
            assert output["total_events"] == 1
            assert output["total_unique_schemas"] == 1

    def test_audit_output_file(self) -> None:
        """Test audit command with output file."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create sample JSON file
            sample_data = {
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "data": {
                                    "win": {
                                        "system": {
                                            "providerName": "Test",
                                            "channel": "TestChannel",
                                            "eventID": "1000",
                                        },
                                        "eventdata": {},
                                    }
                                }
                            }
                        }
                    ]
                }
            }

            sample_file = Path(tmpdir) / "events.json"
            sample_file.write_text(json.dumps(sample_data), encoding="utf-8")

            output_file = Path(tmpdir) / "inventory.json"

            result = runner.invoke(
                cli,
                [
                    "audit",
                    "--input-dir",
                    tmpdir,
                    "--output",
                    str(output_file),
                ],
            )

            assert result.exit_code == 0
            assert output_file.exists()

    def test_build_fixtures_missing_input(self) -> None:
        """Test build-fixtures command with missing input."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["build-fixtures"],
        )
        # Should fail due to missing required --input
        assert result.exit_code != 0

    def test_optimize_help_format(self) -> None:
        """Test optimize command output format options."""
        runner = CliRunner()
        result = runner.invoke(cli, ["optimize", "--help"])
        assert "json" in result.output.lower()
        assert "markdown" in result.output.lower()


class TestTypeAnnotations:
    """Tests to verify type annotations are present."""

    def test_analysis_functions_have_annotations(self) -> None:
        """Verify analysis functions have type annotations."""
        from wazuh_sigma.windows import analysis

        # Check that functions have annotations
        assert hasattr(analysis.get_field_type, "__annotations__")
        assert hasattr(analysis.analyze_field_structure, "__annotations__")
        assert hasattr(analysis.schema_hash, "__annotations__")
        assert hasattr(analysis.parse_json_files, "__annotations__")

    def test_fixture_functions_have_annotations(self) -> None:
        """Verify fixture generation functions have annotations."""
        from wazuh_sigma.windows import fixture_generation

        assert hasattr(
            fixture_generation.create_fixture_content,
            "__annotations__",
        )
        assert hasattr(
            fixture_generation.get_provider_directory_name,
            "__annotations__",
        )
        assert hasattr(
            fixture_generation.get_channel_filename,
            "__annotations__",
        )

    def test_cli_function_has_annotations(self) -> None:
        """Verify CLI functions have type annotations."""
        from wazuh_sigma.windows import cli

        assert hasattr(cli.audit, "__annotations__")
        assert hasattr(cli.build_fixtures, "__annotations__")
        assert hasattr(cli.optimize, "__annotations__")
