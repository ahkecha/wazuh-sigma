"""Versioned prompt contract for the advisor.

The prompt frames the model as a non-authoritative detection-engineering
reviewer and encodes the Wazuh 0-15 severity rubric plus the controlled
vocabularies. Every element that can change the model's behavior carries an
independent version so that a change invalidates cache entries deterministically
(see :func:`prompt_cache_signature`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from wazuh_sigma.advisor.models import (
    OUTPUT_SCHEMA_VERSION,
    QUALITY_FLAG_VOCAB_VERSION,
    QUALITY_FLAGS,
    REASON_CODE_VOCAB_VERSION,
    REASON_CODES,
    SanitizedAdvisorRequest,
)

#: Bumped when the instruction text changes.
PROMPT_VERSION = "severity-v1"
#: Bumped when the numeric severity rubric changes.
SEVERITY_RUBRIC_VERSION = "wazuh-severity-v1"

_SEVERITY_RUBRIC = """\
Wazuh severity levels (0-15):
- 0-3: informational / low-signal; expected benign or noisy administrative activity.
- 4-6: low; weak or single-indicator detections needing correlation.
- 7-9: medium; credible suspicious behavior with some false-positive risk.
- 10-12: high; strong indicators of malicious activity with specific matches.
- 13-15: critical; high-confidence, high-impact detections (reserve 15 for
  unambiguous compromise). Do not assign 13-15 to experimental rules.\
"""

_SYSTEM_INSTRUCTIONS = f"""\
You are a detection-engineering advisor reviewing a single normalized Sigma rule
that has already been parsed and validated. Your output is ADVISORY ONLY and is
never applied automatically.

You MUST NOT:
- generate or edit Wazuh XML
- assign or change Wazuh rule IDs
- change field mappings
- rewrite, broaden, or remove detection logic
- give deployment or restart instructions

Guidance:
- Distinguish parser validity (already guaranteed) from detection QUALITY.
- Distinguish malicious specificity from operational noise: a precise match on a
  known-bad artifact is high severity; a broad match on common administrative
  binaries is likely noisy.
- Recommend human review for ambiguous, high-impact, or low-confidence rules.
- confidence reflects how reliable YOUR recommendation is, not the rule's severity.

{_SEVERITY_RUBRIC}

Respond ONLY with the structured schema you are given. Use reason_codes and
quality_flags EXCLUSIVELY from these controlled vocabularies:
reason_codes: {sorted(REASON_CODES)}
quality_flags: {sorted(QUALITY_FLAGS)}
Keep analyst_summary concise (one or two sentences). Do not include chain-of-thought.\
"""


@dataclass(frozen=True)
class PromptBundle:
    """A rendered prompt: system instructions plus the per-rule user payload."""

    system_instructions: str
    user_input: str
    prompt_version: str
    output_schema_version: str


def build_prompt(request: SanitizedAdvisorRequest) -> PromptBundle:
    """Render the prompt for one sanitized rule request."""
    features = request.features
    payload = {
        "title": request.sanitized_title,
        "description": request.sanitized_description,
        "sigma_level": features.sigma_level,
        "sigma_status": features.sigma_status,
        "logsource": {
            "product": features.logsource_product,
            "category": features.logsource_category,
            "service": features.logsource_service,
        },
        "attack_tactics": features.attack_tactics,
        "attack_techniques": features.attack_techniques,
        "field_names": features.field_names,
        "modifier_types": features.modifier_types,
        "selection_count": features.selection_count,
        "filter_count": features.filter_count,
        "condition_depth": features.condition_depth,
        "boolean_operator_count": features.boolean_operator_count,
        "has_negation": features.has_negation,
        "uses_one_of_selection": features.uses_one_of_selection,
        "uses_all_of_selection": features.uses_all_of_selection,
        "uses_wildcard_selection": features.uses_wildcard_selection,
        "has_broad_regex": features.has_broad_regex,
        "has_broad_wildcard": features.has_broad_wildcard,
        "has_admin_binary_reference": features.has_admin_binary_reference,
        "has_suspicious_command_primitive": features.has_suspicious_command_primitive,
        "documented_false_positives": features.documented_false_positives,
        "false_positive_count": features.false_positive_count,
        "likely_requires_telemetry": features.likely_requires_telemetry,
        "telemetry_implied_by_logsource": features.telemetry_implied_by_logsource,
        "is_single_indicator": features.is_single_indicator,
        "current_deterministic_level": features.current_deterministic_level,
        "policy_baseline_level": features.policy_baseline_level,
    }
    user_input = (
        "Review this Sigma rule and recommend a Wazuh severity and quality "
        "assessment.\n\n" + json.dumps(payload, sort_keys=True, indent=2)
    )
    return PromptBundle(
        system_instructions=_SYSTEM_INSTRUCTIONS,
        user_input=user_input,
        prompt_version=PROMPT_VERSION,
        output_schema_version=OUTPUT_SCHEMA_VERSION,
    )


def prompt_cache_signature() -> dict[str, str]:
    """Return the version dict that participates in the advisor cache key.

    Any change to a prompt, schema, rubric, or vocabulary version here forces
    cache misses for previously cached rules.
    """
    return {
        "prompt_version": PROMPT_VERSION,
        "output_schema_version": OUTPUT_SCHEMA_VERSION,
        "severity_rubric_version": SEVERITY_RUBRIC_VERSION,
        "reason_code_vocab_version": REASON_CODE_VOCAB_VERSION,
        "quality_flag_vocab_version": QUALITY_FLAG_VOCAB_VERSION,
    }
