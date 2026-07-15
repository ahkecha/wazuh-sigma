"""Explicit exception hierarchy for the optional Sigma rule advisor.

Every expected advisor failure mode has its own exception type so callers can
distinguish retryable provider failures from configuration mistakes, policy
rejections, and sanitizer refusals without catching broad exceptions.
"""

from __future__ import annotations


class AdvisorError(RuntimeError):
    """Base class for all advisor failures."""


class AdvisorDisabledError(AdvisorError):
    """Raised when advisor functionality is invoked while disabled in configuration."""


class AdvisorConfigurationError(AdvisorError):
    """Raised when advisor configuration is invalid or incomplete (e.g. missing API key)."""


class AdvisorAuthenticationError(AdvisorError):
    """Raised when the provider rejects credentials. Never retried."""


class AdvisorRateLimitError(AdvisorError):
    """Raised when the provider reports a rate limit. Retryable."""


class AdvisorTimeoutError(AdvisorError):
    """Raised when a provider request exceeds the configured timeout. Retryable."""


class AdvisorUnavailableError(AdvisorError):
    """Raised for transient provider/connection failures (5xx, connection resets). Retryable."""


class AdvisorRefusalError(AdvisorError):
    """Raised when the provider explicitly refuses to produce a recommendation."""


class AdvisorMalformedOutputError(AdvisorError):
    """Raised when the provider response cannot be parsed as structured output."""


class AdvisorSchemaValidationError(AdvisorError):
    """Raised when structured output fails strict schema validation."""


class AdvisorPolicyRejectionError(AdvisorError):
    """Raised when the deterministic policy engine rejects a recommendation outright."""


class AdvisorCacheError(AdvisorError):
    """Raised when the advisor cache cannot be read or written safely."""


class AdvisorCostLimitError(AdvisorError):
    """Raised when a configured cost ceiling has been reached."""


class AdvisorRequestLimitError(AdvisorError):
    """Raised when a configured request-count ceiling has been reached."""


class AdvisorSanitizationError(AdvisorError):
    """Raised when strict-mode sanitization rejects a request containing high-risk secrets."""


#: Exceptions that represent transient provider failures and may be retried
#: with backoff. Authentication, configuration, schema, and policy failures
#: are deliberately excluded — retrying them cannot change the outcome.
RETRYABLE_ADVISOR_ERRORS: tuple[type[AdvisorError], ...] = (
    AdvisorRateLimitError,
    AdvisorTimeoutError,
    AdvisorUnavailableError,
)
