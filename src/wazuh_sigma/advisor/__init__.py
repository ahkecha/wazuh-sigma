"""Optional OpenAI-powered advisor for the Wazuh Sigma pipeline.

The advisor is a *non-authoritative* semantic reviewer. It may recommend a
Wazuh severity level, assess noise risk, flag weak detection logic, and produce
an analyst summary. It never generates XML, assigns rule IDs, mutates field
mappings, rewrites detection logic, or deploys rules.

The deterministic core pipeline must never import this package at module load
time. Integration points import advisor submodules lazily so that deterministic
conversion works identically whether or not the optional ``advisor`` extra
(``openai``, ``pydantic``) is installed.
"""

from __future__ import annotations

#: Package-level version marker for the advisor feature as a whole. Individual
#: contracts (features, sanitizer, prompt, output schema, policy) carry their
#: own independent versions used for cache invalidation.
ADVISOR_PACKAGE_VERSION = "advisor-1.0.0"
