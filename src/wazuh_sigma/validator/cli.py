"""Command-line interface for Wazuh rule validation."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from xml.etree import ElementTree as ET

from wazuh_sigma.validator.models import RuleValidationReport
from wazuh_sigma.validator.rule_validator import WazuhRuleValidator


logger = logging.getLogger(__name__)
VALIDATOR_CLI_ERRORS = (ET.ParseError, OSError, UnicodeError, LookupError, ValueError)


def setup_logging(verbose: bool = False) -> None:
    """Configure CLI logging without mutating logging at import time."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the ``sigma-validate`` command-line parser."""
    parser = argparse.ArgumentParser(
        description="Comprehensive Wazuh Rule Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate a single rule file
  sigma-validate -r /path/to/rules.xml

  # Validate all rules in a directory
  sigma-validate -r /path/to/rules/

  # Validate with strict mode
  sigma-validate -r /path/to/rules/ --strict

  # Validate against sample logs
  sigma-validate -r /path/to/rules/ -s /path/to/samples.txt

  # Generate JSON report
  sigma-validate -r /path/to/rules/ -o json > report.json

  # Generate HTML report
  sigma-validate -r /path/to/rules/ -o html > report.html
        """,
    )

    parser.add_argument(
        "-r", "--rules",
        required=True,
        help="Path to Wazuh rules file or directory",
    )
    parser.add_argument(
        "-s", "--samples",
        help="Path to file containing sample log lines for testing",
    )
    parser.add_argument(
        "-o", "--output",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as failures",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    return parser


def validation_exit_code(reports: list[RuleValidationReport], *, strict_mode: bool = False) -> int:
    """Return the CLI exit code for validation results."""
    if not reports:
        return 1
    total_failed = sum(report.failed_checks for report in reports)
    total_warnings = sum(report.warning_checks for report in reports)
    if total_failed > 0:
        return 1
    if strict_mode and total_warnings > 0:
        return 1
    return 0


def load_sample_logs(samples_file: str | Path) -> list[str]:
    """Load non-empty sample log lines from a UTF-8 text file."""
    return [
        line.strip()
        for line in Path(samples_file).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main(argv: list[str] | None = None) -> int:
    """Run the ``sigma-validate`` command."""
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(args.verbose)

    samples: list[str] = []
    if args.samples:
        try:
            samples = load_sample_logs(args.samples)
            logger.info("Loaded %d sample log lines", len(samples))
        except (OSError, UnicodeDecodeError) as error:
            logger.error("Failed to load samples: %s", error)
            return 1

    validator = WazuhRuleValidator(args.rules, strict_mode=args.strict, test_samples=samples)

    try:
        validator.validate_all()
        report = validator.generate_report(args.output)
        print(report)

        return validation_exit_code(validator.all_results, strict_mode=args.strict)

    except VALIDATOR_CLI_ERRORS as error:
        logger.error("Validation failed: %s", error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
