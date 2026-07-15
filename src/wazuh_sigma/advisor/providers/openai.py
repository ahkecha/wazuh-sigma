"""OpenAI advisor provider.

Wraps the official OpenAI SDK's Responses API with structured parsing. All
SDK-specific exceptions are mapped to the typed advisor errors in
:mod:`wazuh_sigma.advisor.errors`; callers never see an ``openai.*`` exception.
Transient failures (timeouts, rate limits, 5xx) are retried with exponential
backoff plus jitter. Authentication, refusal, malformed-output, and schema
failures are never retried.

The OpenAI SDK is imported lazily inside :meth:`OpenAIAdvisorProvider.from_env`
so that importing this module (e.g. for type references) does not require the
optional ``advisor`` extra to be installed.
"""

from __future__ import annotations

import logging
import os
import random
import time
from typing import Any, Callable

from pydantic import ValidationError

from wazuh_sigma.advisor.errors import (
    RETRYABLE_ADVISOR_ERRORS,
    AdvisorAuthenticationError,
    AdvisorConfigurationError,
    AdvisorMalformedOutputError,
    AdvisorRateLimitError,
    AdvisorRefusalError,
    AdvisorSchemaValidationError,
    AdvisorTimeoutError,
    AdvisorUnavailableError,
)
from wazuh_sigma.advisor.models import (
    AdvisorModelOutput,
    ProviderRequestMetadata,
    ProviderResult,
    SanitizedAdvisorRequest,
)
from wazuh_sigma.advisor.prompts import build_prompt

logger = logging.getLogger("SigmaAdvisor.openai")

DEFAULT_API_KEY_ENV = "OPENAI_API_KEY"
_BACKOFF_BASE_SECONDS = 0.5
_BACKOFF_MAX_SECONDS = 30.0

Sleeper = Callable[[float], None]


class OpenAIAdvisorProvider:
    """Structured-output advisor provider backed by the OpenAI Responses API."""

    name = "openai"

    def __init__(
        self,
        client: Any,
        *,
        max_retries: int = 3,
        sleeper: Sleeper = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        if max_retries < 0:
            raise AdvisorConfigurationError("max_retries must be non-negative")
        self._client = client
        self._max_retries = max_retries
        self._sleeper = sleeper
        # Retry-backoff jitter only; not used for any security decision.
        self._rng = rng or random.Random()  # nosec B311

    @classmethod
    def from_env(
        cls,
        *,
        api_key_env: str = DEFAULT_API_KEY_ENV,
        max_retries: int = 3,
        base_url: str | None = None,
    ) -> "OpenAIAdvisorProvider":
        """Build a provider from the environment API key using the real SDK client."""
        api_key = os.getenv(api_key_env)
        if not api_key:
            raise AdvisorConfigurationError(
                f"advisor is enabled but {api_key_env} is not set; export the key or disable the advisor"
            )
        try:
            from openai import OpenAI
        except ImportError as error:  # pragma: no cover - exercised only without the extra
            raise AdvisorConfigurationError(
                "the 'advisor' extra is not installed; install wazuh-sigma-pipeline[advisor]"
            ) from error
        # Disable the SDK's built-in retries: this class owns retry policy
        # (typed classification + testable jitter). Leaving SDK retries on would
        # multiply real HTTP attempts per logical call and undercount telemetry.
        client_kwargs: dict[str, Any] = {"api_key": api_key, "max_retries": 0}
        if base_url:
            client_kwargs["base_url"] = base_url
        client = OpenAI(**client_kwargs)
        return cls(client, max_retries=max_retries)

    def analyze(
        self,
        request: SanitizedAdvisorRequest,
        metadata: ProviderRequestMetadata,
    ) -> ProviderResult:
        """Return a validated recommendation, retrying only transient failures."""
        attempt = 0
        while True:
            try:
                response = self._invoke(request, metadata)
                output = self._validate(response)
                return ProviderResult(
                    output=output,
                    request_id=self._extract_request_id(response),
                    model=metadata.model,
                )
            except RETRYABLE_ADVISOR_ERRORS as error:
                attempt += 1
                if attempt > self._max_retries:
                    raise
                delay = self._backoff_delay(attempt)
                logger.warning(
                    "Transient advisor provider error (%s); retry %d/%d after %.2fs",
                    type(error).__name__,
                    attempt,
                    self._max_retries,
                    delay,
                )
                self._sleeper(delay)

    def _invoke(self, request: SanitizedAdvisorRequest, metadata: ProviderRequestMetadata) -> Any:
        """Call the Responses API and map SDK exceptions to typed advisor errors."""
        import openai

        prompt = build_prompt(request)
        try:
            # temperature is intentionally not set: structured-output
            # classification does not need it, and some model families reject an
            # explicit temperature (which would surface as a bad request).
            return self._client.responses.parse(
                model=metadata.model,
                instructions=prompt.system_instructions,
                input=prompt.user_input,
                text_format=AdvisorModelOutput,
                max_output_tokens=metadata.max_output_tokens,
                store=False,
                timeout=metadata.timeout_seconds,
            )
        except openai.APITimeoutError as error:
            raise AdvisorTimeoutError("advisor provider request timed out") from error
        except openai.RateLimitError as error:
            raise AdvisorRateLimitError("advisor provider rate limit reached") from error
        except openai.AuthenticationError as error:
            raise AdvisorAuthenticationError("advisor provider rejected credentials") from error
        except openai.APIConnectionError as error:
            raise AdvisorUnavailableError("advisor provider connection failed") from error
        except openai.InternalServerError as error:
            raise AdvisorUnavailableError("advisor provider returned a server error") from error
        except openai.BadRequestError as error:
            # A bad request is a configuration/contract bug, not transient.
            raise AdvisorConfigurationError("advisor provider rejected the request") from error
        except openai.APIStatusError as error:
            status = getattr(error, "status_code", None)
            if status is not None and 500 <= status < 600:
                raise AdvisorUnavailableError("advisor provider returned a server error") from error
            raise AdvisorConfigurationError(
                f"advisor provider returned an unexpected status: {status}"
            ) from error

    def _validate(self, response: Any) -> AdvisorModelOutput:
        """Extract and strictly re-validate the parsed structured output."""
        self._reject_incomplete(response)
        parsed = self._extract_parsed(response)
        if isinstance(parsed, AdvisorModelOutput):
            candidate: Any = parsed.model_dump()
        elif isinstance(parsed, dict):
            candidate = parsed
        elif parsed is not None and hasattr(parsed, "model_dump"):
            candidate = parsed.model_dump()
        else:
            raise AdvisorMalformedOutputError(
                "advisor provider returned no parseable structured output"
            )
        try:
            return AdvisorModelOutput.model_validate(candidate)
        except ValidationError as error:
            raise AdvisorSchemaValidationError(
                f"advisor provider output failed strict schema validation: {error.error_count()} error(s)"
            ) from error

    @staticmethod
    def _reject_incomplete(response: Any) -> None:
        status = getattr(response, "status", None)
        if status in ("incomplete", "failed"):
            details = getattr(response, "incomplete_details", None)
            reason = getattr(details, "reason", None)
            raise AdvisorMalformedOutputError(
                f"advisor provider response was {status}" + (f" ({reason})" if reason else "")
            )

    @staticmethod
    def _extract_parsed(response: Any) -> Any:
        """Return the parsed output object, raising on refusals or missing output."""
        direct = getattr(response, "output_parsed", None)
        if direct is not None:
            return direct
        for item in getattr(response, "output", None) or []:
            for content in getattr(item, "content", None) or []:
                if getattr(content, "type", None) == "refusal":
                    refusal = (
                        getattr(content, "refusal", "") or "advisor provider refused the request"
                    )
                    raise AdvisorRefusalError(str(refusal))
                parsed = getattr(content, "parsed", None)
                if parsed is not None:
                    return parsed
        return None

    @staticmethod
    def _extract_request_id(response: Any) -> str | None:
        """Return the provider's safe request/response identifier, if present."""
        rid = getattr(response, "_request_id", None)
        if rid:
            return str(rid)
        resp_id = getattr(response, "id", None)
        return str(resp_id) if resp_id else None

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with full jitter, capped at a bounded ceiling."""
        ceiling = min(_BACKOFF_MAX_SECONDS, _BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))
        return self._rng.uniform(0.0, ceiling)
