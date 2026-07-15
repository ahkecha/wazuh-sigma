"""Conversion service for Sigma YAML rules to Wazuh XML rules.

This module owns conversion orchestration only:

    Sigma YAML -> pySigma-normalized SigmaRule -> WazuhBackend -> Wazuh XML

CLI parsing, presentation, and deployment are intentionally kept elsewhere.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from xml.etree.ElementTree import Element

import yaml

from wazuh_sigma.backend.wazuh import WazuhBackend, WazuhBackendConfig, WazuhRuleIDGenerator
from wazuh_sigma.fields.errors import FieldMappingError
from wazuh_sigma.incremental.integration import (
    extract_cached_xml,
    finalize_incremental_manifest,
    process_rule_with_cache,
    record_conversion_for_cache,
)
from wazuh_sigma.incremental.service import ConversionCacheStatus, IncrementalConverterService
from wazuh_sigma.reporting import write_text_artifact
from wazuh_sigma.ruleset_chunks import DEFAULT_CHUNK_COUNT, write_ruleset_chunks
from wazuh_sigma.sigma import SigmaParseError, SigmaRule, parse_sigma_with_pysigma


logger = logging.getLogger("SigmaConverter")
ConversionReport = dict[str, Any]


@dataclass(frozen=True)
class AdvisorOutcome:
    """Result of running the optional advisor for one rule.

    ``level_override`` is applied to the backend only when the deterministic
    policy accepted a recommendation (never in report-only mode). ``report`` is
    the secret-free per-rule advisor block embedded in the conversion report.
    """

    level_override: int | None
    report: dict[str, Any]


#: A hook the converter calls per rule when the advisor is enabled. Built by the
#: pipeline/CLI so the converter never imports the advisor package directly.
AdvisorHook = Callable[[SigmaRule], AdvisorOutcome]


@dataclass
class ConversionState:
    """Mutable conversion telemetry collected while a converter instance runs."""

    converted_rules: list[dict[str, Any]] = field(default_factory=list)
    conversion_errors: list[str] = field(default_factory=list)
    conversion_error_details: list[dict[str, str | None]] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    failed_files: list[str] = field(default_factory=list)
    parser_backends: set[str] = field(default_factory=set)

    def record_source_file(self, source_file: str | Path) -> None:
        source = str(source_file)
        if source not in self.source_files:
            self.source_files.append(source)

    def record_error(
        self,
        message: str,
        *,
        source_file: str | Path | None = None,
        error_type: str | None = None,
    ) -> None:
        self.conversion_errors.append(message)
        source = str(source_file) if source_file is not None else None
        self.conversion_error_details.append({
            "message": message,
            "source_file": source,
            "error_type": error_type,
        })
        if source_file is None:
            return

        if source not in self.failed_files:
            self.failed_files.append(source)

    def record_converted_rule(
        self,
        *,
        sigma_title: str,
        wazuh_id: str | None,
        source_file: str,
        wazuh_ids: list[str] | None = None,
        advisor: dict[str, Any] | None = None,
        conversion_cache: dict[str, Any] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "sigma_title": sigma_title,
            "wazuh_id": wazuh_id,
            "source_file": source_file,
        }
        if wazuh_ids is not None:
            record["wazuh_ids"] = wazuh_ids
            record["wazuh_rule_count"] = len(wazuh_ids)
        if advisor is not None:
            record["advisor"] = advisor
        if conversion_cache is not None:
            record["conversion_cache"] = conversion_cache
        self.converted_rules.append(record)

    def as_report(
        self,
        *,
        backend: WazuhBackend,
        generated_at: datetime | None = None,
        advisor_summary: dict[str, Any] | None = None,
    ) -> ConversionReport:
        """Return a machine-readable snapshot of conversion state.

        When the advisor was disabled, ``advisor_summary`` is ``None`` and no
        ``advisor`` key is emitted, so the report is byte-identical to the
        pre-advisor pipeline.
        """
        timestamp = generated_at or datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        report: ConversionReport = {
            'timestamp': timestamp.isoformat(),
            'total_discovered': len(self.source_files),
            'total_converted': len(self.converted_rules),
            'total_errors': len(self.conversion_errors),
            'total_failed_files': len(self.failed_files),
            'parser_backends': sorted(self.parser_backends),
            'backend': 'wazuh',
            'field_mapping_version': backend.field_mapper.version,
            'parent_rules': {
                key: list(value)
                for key, value in sorted(backend.rule_generator.parent_rules.items())
            },
            'rule_id_range': [
                backend.id_generator.start_id,
                backend.id_generator.end_id,
            ],
            'source_files': list(self.source_files),
            'failed_files': list(self.failed_files),
            'converted_rules': [dict(rule) for rule in self.converted_rules],
            'errors': list(self.conversion_errors),
            'error_details': [dict(error) for error in self.conversion_error_details],
        }
        if advisor_summary is not None:
            report['advisor'] = advisor_summary
        return report


class SigmaToWazuhConverter:
    """Orchestrate Sigma-to-Wazuh conversion using the configured backend."""

    def __init__(
        self,
        start_rule_id: int = WazuhRuleIDGenerator.START_CUSTOM_ID,
        end_rule_id: int = WazuhRuleIDGenerator.END_CUSTOM_ID,
        allow_pyyaml_fallback: bool = False,
        backend: WazuhBackend | None = None,
        backend_config: WazuhBackendConfig | None = None,
        advisor_hook: AdvisorHook | None = None,
        incremental_service: IncrementalConverterService | None = None,
    ):
        if backend is not None and backend_config is not None:
            raise ValueError("backend and backend_config are mutually exclusive")
        self.backend = backend or WazuhBackend(
            backend_config
            or WazuhBackendConfig(rule_id_start=start_rule_id, rule_id_end=end_rule_id)
        )
        self.id_generator = self.backend.id_generator
        self.rule_generator = self.backend.rule_generator
        self.state = ConversionState()
        self.converted_rules = self.state.converted_rules
        self.conversion_errors = self.state.conversion_errors
        self.conversion_error_details = self.state.conversion_error_details
        self.source_files = self.state.source_files
        self.failed_files = self.state.failed_files
        self.parser_backends = self.state.parser_backends
        self.allow_pyyaml_fallback = allow_pyyaml_fallback
        self.advisor_hook = advisor_hook
        self.advisor_summary: dict[str, Any] | None = None
        self.incremental_service = incremental_service
        self._current_incremental_identities: set[str] = set()
        self.incremental_summary: dict[str, Any] | None = None
        self.chunk_summary: dict[str, Any] | None = None

    def _record_source_file(self, source_file: str | Path) -> None:
        self.state.record_source_file(source_file)

    def _record_error(
        self,
        message: str,
        *,
        source_file: str | Path | None = None,
        error_type: str | None = None,
    ) -> None:
        self.state.record_error(message, source_file=source_file, error_type=error_type)

    def load_sigma_rule(self, yaml_file: str | Path) -> SigmaRule | None:
        """Load and pySigma-normalize a Sigma YAML rule file."""
        self._record_source_file(yaml_file)
        try:
            yaml_path = Path(yaml_file)
            rule_dict = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

            if not rule_dict:
                logger.error("Failed to parse YAML from %s", yaml_path)
                self._record_error(
                    f"Empty YAML file: {yaml_path}",
                    source_file=yaml_path,
                    error_type="EmptyYamlError",
                )
                return None

            rule_dict, parser_backend = parse_sigma_with_pysigma(
                rule_dict,
                allow_pyyaml_fallback=self.allow_pyyaml_fallback,
            )
            self.parser_backends.add(parser_backend)

            sigma_rule = SigmaRule(rule_dict, str(yaml_path))
            logger.info("Loaded Sigma rule: %s", sigma_rule.title)
            return sigma_rule

        except yaml.YAMLError as e:
            logger.error("YAML parsing error in %s: %s", yaml_file, e)
            self._record_error(
                f"YAML error in {yaml_file}: {str(e)}",
                source_file=yaml_file,
                error_type=type(e).__name__,
            )
            return None

        except FileNotFoundError:
            logger.error("File not found: %s", yaml_file)
            self._record_error(
                f"File not found: {yaml_file}",
                source_file=yaml_file,
                error_type="FileNotFoundError",
            )
            return None

        except SigmaParseError as e:
            logger.error("pySigma rejected %s: %s", yaml_file, e)
            self._record_error(
                f"pySigma error in {yaml_file}: {str(e)}",
                source_file=yaml_file,
                error_type=type(e).__name__,
            )
            return None

    def convert_rule_elements(self, sigma_rule: SigmaRule) -> list[Element]:
        """Convert a normalized Sigma rule to one or more Wazuh XML rule elements."""
        is_valid, errors = sigma_rule.validate()
        if not is_valid:
            error_msg = f"Invalid Sigma rule {sigma_rule.title}: {', '.join(errors)}"
            logger.error("%s", error_msg)
            self._record_error(
                error_msg,
                source_file=sigma_rule.source_file or None,
                error_type="SigmaValidationError",
            )
            return []

        advisor_outcome: AdvisorOutcome | None = None
        if self.advisor_hook is not None:
            advisor_outcome = self.advisor_hook(sigma_rule)

        level_override = advisor_outcome.level_override if advisor_outcome else None
        cache_status: ConversionCacheStatus | None = None
        try:
            cache_status, wazuh_rule_id = process_rule_with_cache(
                self.incremental_service,
                sigma_rule,
                source_path=sigma_rule.source_file or None,
                advisor_level_override=level_override,
            )
            if cache_status is not None:
                self._current_incremental_identities.add(cache_status.rule_identity)
                cached_rule = extract_cached_xml(cache_status)
                if cached_rule is not None:
                    self.id_generator.reserve_id(cache_status.wazuh_rule_id)
                    logger.info("Reused cached conversion for rule: %s", sigma_rule.title)
                    self.state.record_converted_rule(
                        sigma_title=sigma_rule.title,
                        wazuh_id=cached_rule.get("id"),
                        wazuh_ids=[cached_rule.get("id")] if cached_rule.get("id") is not None else None,
                        source_file=sigma_rule.source_file,
                        advisor=advisor_outcome.report if advisor_outcome else None,
                        conversion_cache=self._cache_report(cache_status),
                    )
                    return [cached_rule]

            backend_kwargs: dict[str, Any] = {"level_override": level_override}
            if wazuh_rule_id is not None:
                backend_kwargs["wazuh_rule_id"] = wazuh_rule_id
            wazuh_rules = self.backend.convert_rules(sigma_rule, **backend_kwargs)
            if len(wazuh_rules) == 1:
                record_conversion_for_cache(
                    self.incremental_service,
                    cache_status,
                    wazuh_rules[0],
                    sigma_rule.title,
                )
            logger.info("Successfully converted rule: %s", sigma_rule.title)
            wazuh_ids = [rule_id for rule in wazuh_rules if (rule_id := rule.get("id")) is not None]
            self.state.record_converted_rule(
                sigma_title=sigma_rule.title,
                wazuh_id=wazuh_ids[0] if wazuh_ids else None,
                wazuh_ids=wazuh_ids,
                source_file=sigma_rule.source_file,
                advisor=advisor_outcome.report if advisor_outcome else None,
                conversion_cache=self._cache_report(cache_status) if len(wazuh_rules) == 1 else None,
            )
            return wazuh_rules

        except (FieldMappingError, ValueError) as e:
            error_msg = f"Error converting {sigma_rule.title}: {str(e)}"
            logger.error("%s", error_msg)
            self._record_error(
                error_msg,
                source_file=sigma_rule.source_file or None,
                error_type=type(e).__name__,
            )
            return []

    def convert_rule(self, sigma_rule: SigmaRule) -> Element | None:
        """Convert a normalized Sigma rule to the first Wazuh XML rule element."""
        rules = self.convert_rule_elements(sigma_rule)
        if not rules:
            return None
        return rules[0]

    def convert_file(self, yaml_file: str | Path) -> Element | None:
        """Load and convert a Sigma rule file in one step."""
        sigma_rule = self.load_sigma_rule(yaml_file)
        if sigma_rule:
            return self.convert_rule(sigma_rule)
        return None

    def convert_file_elements(self, yaml_file: str | Path) -> list[Element]:
        """Load and convert a Sigma rule file into one or more Wazuh rule elements."""
        sigma_rule = self.load_sigma_rule(yaml_file)
        if sigma_rule:
            return self.convert_rule_elements(sigma_rule)
        return []

    def convert_directory(self, directory: str | Path, recursive: bool = True) -> list[Element]:
        """Convert all Sigma YAML rules in a directory."""
        rules: list[Element] = []
        path = Path(directory)
        self._current_incremental_identities = set()
        self.incremental_summary = None

        if not path.is_dir():
            logger.error("Directory not found: %s", directory)
            self._record_error(f"Directory not found: {directory}", error_type="DirectoryNotFoundError")
            return rules

        globber = path.rglob if recursive else path.glob
        yaml_files = sorted([*globber("*.yaml"), *globber("*.yml")])
        for yaml_file in yaml_files:
            self._record_source_file(yaml_file)
        logger.info("Found %d YAML files in %s", len(yaml_files), directory)

        for yaml_file in yaml_files:
            logger.info("Processing: %s", yaml_file.name)
            rules.extend(self.convert_file_elements(yaml_file))

        logger.info("Converted %d Wazuh rule(s) from %d Sigma file(s)", len(rules), len(yaml_files))
        return rules

    def generate_xml_output(
        self,
        rules: list[Element],
        output_file: str | Path,
        *,
        chunk_count: int = DEFAULT_CHUNK_COUNT,
    ) -> bool:
        """Render converted Wazuh rules into atomic XML artifacts.

        The canonical full ruleset is still written to ``output_file`` for
        compatibility with deployment/reporting flows. Chunk files are emitted
        next to it by default so large Windows corpora do not leave users with
        one giant editor-hostile XML file.
        """
        try:
            xml_str = self.backend.render_ruleset(rules)

            write_text_artifact(Path(output_file), xml_str)
            self.chunk_summary = write_ruleset_chunks(
                backend=self.backend,
                rules=rules,
                output_file=output_file,
                chunk_count=chunk_count,
            ).as_report()
            incremental_summary = finalize_incremental_manifest(
                self.incremental_service,
                self._current_incremental_identities,
            )
            if incremental_summary is not None:
                self.incremental_summary = incremental_summary
            logger.info("Generated Wazuh XML file: %s", output_file)
            return True

        except OSError as e:
            logger.error("Error writing XML output: %s", e)
            self._record_error(f"XML generation error: {str(e)}", error_type=type(e).__name__)
            return False

    @staticmethod
    def _prettify_xml(elem: Element) -> str:
        """Format an XML element as pretty-printed Wazuh XML."""
        return WazuhBackend.prettify(elem)

    def generate_report(self) -> ConversionReport:
        """Generate a machine-readable conversion report."""
        report = self.state.as_report(backend=self.backend, advisor_summary=self.advisor_summary)
        if self.incremental_summary is not None:
            report["incremental_conversion"] = self.incremental_summary
        if self.chunk_summary is not None:
            report["chunks"] = self.chunk_summary
        return report

    @staticmethod
    def _cache_report(status: ConversionCacheStatus | None) -> dict[str, Any] | None:
        if status is None:
            return None
        return {
            "status": "hit" if status.cached else "miss",
            "identity": status.rule_identity,
            "identity_source": status.identity_source,
            "fingerprint": status.fingerprint,
        }
