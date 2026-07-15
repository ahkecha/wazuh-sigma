"""Advisor usage accounting.

Tracks request counts, cache hits/misses, provider calls, and error categories
for a single conversion run. Records no raw prompts, rules, or secrets — only
counters and category names — so a telemetry snapshot is always safe to embed
in a conversion report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdvisorTelemetry:
    """Mutable per-run counters. Owned by the advisor service."""

    request_count: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    primary_calls: int = 0
    escalation_calls: int = 0
    rate_limit_events: int = 0
    errors_by_category: dict[str, int] = field(default_factory=dict)
    limits_reached: list[str] = field(default_factory=list)

    def record_cache_hit(self) -> None:
        self.cache_hits += 1

    def record_cache_miss(self) -> None:
        self.cache_misses += 1

    def record_primary_call(self) -> None:
        self.request_count += 1
        self.primary_calls += 1

    def record_escalation_call(self) -> None:
        self.request_count += 1
        self.escalation_calls += 1

    def record_rate_limit(self) -> None:
        self.rate_limit_events += 1

    def record_error(self, category: str) -> None:
        self.errors_by_category[category] = self.errors_by_category.get(category, 0) + 1

    def record_limit_reached(self, limit: str) -> None:
        if limit not in self.limits_reached:
            self.limits_reached.append(limit)

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serializable, secret-free summary for run-level reporting."""
        return {
            "request_count": self.request_count,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "primary_calls": self.primary_calls,
            "escalation_calls": self.escalation_calls,
            "rate_limit_events": self.rate_limit_events,
            "errors_by_category": dict(sorted(self.errors_by_category.items())),
            "limits_reached": list(self.limits_reached),
        }
