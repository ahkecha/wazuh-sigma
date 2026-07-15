"""Command-line interface for converting Sigma rules to Wazuh XML."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

from wazuh_sigma.backend.wazuh import WazuhRuleIDGenerator
from wazuh_sigma.converter.presentation import format_conversion_summary
from wazuh_sigma.converter.service import SigmaToWazuhConverter
from wazuh_sigma.reporting import write_json_report


LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def positive_int(value: str) -> int:
    """Parse a positive integer for converter CLI options."""
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Configure and return the converter logger."""
    normalized_level = log_level.upper()
    if normalized_level not in LOG_LEVELS:
        raise ValueError(f"log_level must be one of: {', '.join(LOG_LEVELS)}")

    logger = logging.getLogger("SigmaConverter")
    logger.setLevel(getattr(logging, normalized_level))
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    for handler in logger.handlers:
        handler.setLevel(getattr(logging, normalized_level))
    return logger


logger = setup_logging()


def build_parser() -> argparse.ArgumentParser:
    """Build the ``sigma-convert`` command-line parser."""
    parser = argparse.ArgumentParser(
        description="Convert Sigma detection rules to Wazuh format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert a single Sigma rule
  sigma-convert -f rule.yaml -o output.xml

  # Convert all rules in a directory
  sigma-convert -d ./sigma_rules -o wazuh_rules.xml

  # Specify starting rule ID
  sigma-convert -d ./rules -o output.xml --start-id 100500

  # Enable debug logging
  sigma-convert -f rule.yaml -o output.xml -v DEBUG
        """,
    )

    parser.add_argument("-f", "--file", help="Path to single Sigma YAML rule file")
    parser.add_argument("-d", "--directory", help="Path to directory containing Sigma YAML rules")
    parser.add_argument(
        "-o",
        "--output",
        default="wazuh_rules.xml",
        help="Output XML file path (default: wazuh_rules.xml)",
    )
    parser.add_argument(
        "--start-id",
        type=positive_int,
        default=WazuhRuleIDGenerator.START_CUSTOM_ID,
        help=f"Starting Wazuh rule ID (default: {WazuhRuleIDGenerator.START_CUSTOM_ID})",
    )
    parser.add_argument(
        "--end-id",
        type=positive_int,
        default=WazuhRuleIDGenerator.END_CUSTOM_ID,
        help=f"Last owned Wazuh rule ID (default: {WazuhRuleIDGenerator.END_CUSTOM_ID})",
    )
    parser.add_argument("-r", "--report", help="Generate conversion report in JSON format")
    parser.add_argument(
        "-v",
        "--verbose",
        default="INFO",
        choices=LOG_LEVELS,
        type=str.upper,
        help="Logging level",
    )
    parser.add_argument(
        "--allow-pyyaml-fallback",
        action="store_true",
        help="Allow legacy loose PyYAML parsing if pySigma is unavailable or rejects a rule.",
    )
    _add_advisor_options(parser)
    return parser


def _add_advisor_options(parser: argparse.ArgumentParser) -> None:
    """Add advisor flags to sigma-convert. The advisor is NON-AUTHORITATIVE."""
    group = parser.add_argument_group("advisor (non-authoritative; report-only by default)")
    group.add_argument("--advisor", action="store_true", help="Enable the optional OpenAI advisor")
    group.add_argument(
        "--advisor-mode",
        choices=("report-only", "review", "apply"),
        default="report-only",
        help="Advisor mode; report-only never changes generated XML (default)",
    )
    group.add_argument("--advisor-model", help="Override the primary advisor model")
    group.add_argument("--advisor-escalation-model", help="Override the escalation advisor model")
    group.add_argument("--advisor-min-confidence", type=float, help="Minimum confidence for applied recommendations")
    group.add_argument("--advisor-max-level-delta", type=int, help="Maximum accepted level delta from the default")
    group.add_argument("--advisor-cache-dir", help="Advisor cache directory")
    group.add_argument("--advisor-no-cache", action="store_true", help="Disable advisor caching")
    group.add_argument(
        "--advisor-fail-closed",
        action="store_true",
        help="Fail conversion when the advisor fails instead of deterministic fallback",
    )


def _advisor_config_from_args(args: argparse.Namespace) -> Any:
    """Build an AdvisorConfig from sigma-convert flags (advisor enabled only if requested)."""
    from wazuh_sigma.config import AdvisorConfig

    kwargs: dict[str, Any] = {"enabled": True, "mode": args.advisor_mode}
    if args.advisor_model is not None:
        kwargs["primary_model"] = args.advisor_model
    if args.advisor_escalation_model is not None:
        kwargs["escalation_model"] = args.advisor_escalation_model
    if args.advisor_min_confidence is not None:
        kwargs["minimum_confidence"] = args.advisor_min_confidence
    if args.advisor_max_level_delta is not None:
        kwargs["maximum_level_delta"] = args.advisor_max_level_delta
    if args.advisor_cache_dir is not None:
        kwargs["cache_directory"] = Path(args.advisor_cache_dir)
    if args.advisor_no_cache:
        kwargs["cache_enabled"] = False
    if args.advisor_fail_closed:
        kwargs["fail_open"] = False
    return AdvisorConfig(**kwargs)


def cli(argv: list[str] | None = None) -> int:
    """Run the converter command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(args.verbose)

    if not args.file and not args.directory:
        parser.error("Either --file or --directory must be specified")
    if args.start_id > args.end_id:
        parser.error("--start-id must be less than or equal to --end-id")

    advisor_service = None
    advisor_hook = None
    advisor_config = None
    if args.advisor:
        from wazuh_sigma.advisor.runtime import build_advisor_service, make_advisor_hook

        advisor_config = _advisor_config_from_args(args)
        advisor_service = build_advisor_service(advisor_config)
        if advisor_service is not None:
            advisor_hook = make_advisor_hook(advisor_service, advisor_config)

    converter = SigmaToWazuhConverter(
        start_rule_id=args.start_id,
        end_rule_id=args.end_id,
        allow_pyyaml_fallback=args.allow_pyyaml_fallback,
        advisor_hook=advisor_hook,
    )
    logger.info("Sigma to Wazuh converter initialized")

    rules = []
    if args.file:
        logger.info("Converting file: %s", args.file)
        rule = converter.convert_file(args.file)
        if rule is not None:
            rules.append(rule)
    elif args.directory:
        logger.info("Converting directory: %s", args.directory)
        rules = converter.convert_directory(args.directory)

    if rules:
        if converter.generate_xml_output(rules, args.output):
            logger.info("Successfully generated %s", args.output)
    else:
        logger.warning("No rules were successfully converted")

    if advisor_service is not None and advisor_config is not None:
        from wazuh_sigma.advisor.runtime import build_run_advisor_summary

        converter.advisor_summary = build_run_advisor_summary(advisor_service, advisor_config)

    report = converter.generate_report()
    if args.report:
        write_json_report(Path(args.report), report)
        logger.info("Generated conversion report: %s", args.report)

    print(format_conversion_summary(report, args.output))
    return 0 if rules and report["total_errors"] == 0 else 1


def main(argv: list[str] | None = None) -> None:
    """Module entry point."""
    raise SystemExit(cli(argv))


if __name__ == "__main__":
    main()
