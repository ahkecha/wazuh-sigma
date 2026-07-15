"""Narrow provider protocol for the advisor.

The rest of the advisor depends only on :class:`AdvisorProvider`, never on any
concrete SDK. This keeps OpenAI (or any future provider) swappable and makes
the service trivial to test with a fake provider.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from wazuh_sigma.advisor.models import (
    ProviderRequestMetadata,
    ProviderResult,
    SanitizedAdvisorRequest,
)


@runtime_checkable
class AdvisorProvider(Protocol):
    """A provider turns a sanitized request into a validated result envelope.

    Implementations MUST:

    * raise the typed exceptions in :mod:`wazuh_sigma.advisor.errors` for every
      expected failure mode (never leak SDK-specific exceptions);
    * return a :class:`ProviderResult` wrapping a strictly validated
      :class:`AdvisorModelOutput` plus the safe request id and model used;
    * never mutate the request;
    * never log raw request payloads or secrets.
    """

    name: str

    def analyze(
        self,
        request: SanitizedAdvisorRequest,
        metadata: ProviderRequestMetadata,
    ) -> ProviderResult:
        """Return a validated result for a single sanitized rule request."""
        ...
