"""Shared fakes and builders for advisor tests.

Not a test module. Provides a deterministic fake provider and small factory
functions so individual test files stay focused on behavior.
"""

from __future__ import annotations

from typing import Any

from wazuh_sigma.advisor.models import (
    AdvisorModelOutput,
    ProviderRequestMetadata,
    ProviderResult,
    SanitizedAdvisorRequest,
)
from wazuh_sigma.sigma import SigmaRule


def make_rule(**overrides: Any) -> SigmaRule:
    """Return a normalized-looking SigmaRule with sensible defaults."""
    raw: dict[str, Any] = {
        "title": "Suspicious cmd.exe spawned by explorer",
        "description": "Detects cmd.exe launched by explorer.exe",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {"Image|endswith": "\\cmd.exe"},
            "condition": "selection",
        },
        "tags": ["attack.execution", "attack.t1059.003"],
        "level": "high",
        "status": "stable",
        "falsepositives": ["Legitimate administrative scripts"],
    }
    raw.update(overrides)
    return SigmaRule(raw, str(overrides.get("source_file", "rule.yml")))


def make_output(**overrides: Any) -> AdvisorModelOutput:
    """Return a valid AdvisorModelOutput with overridable fields."""
    data: dict[str, Any] = {
        "recommended_level": 11,
        "confidence": 0.92,
        "noise_risk": "low",
        "quality_flags": [],
        "reason_codes": ["known_attack_technique_match"],
        "analyst_summary": "Strong, specific technique match.",
        "requires_human_review": False,
        "priority": "deploy",
    }
    data.update(overrides)
    return AdvisorModelOutput(**data)


class FakeProvider:
    """A provider that returns queued outputs or raises queued exceptions.

    Records every call so tests can assert on invocation counts (e.g. cache
    hits skip the provider entirely).
    """

    name = "fake"

    def __init__(self, *results: Any) -> None:
        self._results = list(results)
        self.calls: list[ProviderRequestMetadata] = []

    def analyze(
        self,
        request: SanitizedAdvisorRequest,
        metadata: ProviderRequestMetadata,
    ) -> ProviderResult:
        self.calls.append(metadata)
        result = self._results.pop(0) if self._results else make_output()
        if isinstance(result, Exception):
            raise result
        if isinstance(result, ProviderResult):
            return result
        return ProviderResult(
            output=result,
            request_id=f"fake-req-{len(self.calls)}",
            model=metadata.model,
        )

    @property
    def call_count(self) -> int:
        return len(self.calls)
