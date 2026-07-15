"""Content-addressed JSON cache for advisor recommendations.

The cache key is a SHA-256 digest over the sanitized rule plus every version
that could change the recommendation (feature schema, sanitizer, prompt, output
schema, policy, provider, and model names). A change to any version therefore
produces a different key and old entries are simply never read again. Entries
store only validated model output — never secrets, prompts, or raw rule content.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from pydantic import ValidationError

from wazuh_sigma.advisor.errors import AdvisorCacheError
from wazuh_sigma.advisor.models import AdvisorModelOutput, CacheEntry, SanitizedAdvisorRequest
from wazuh_sigma.reporting import write_text_artifact

logger = logging.getLogger("SigmaAdvisor.cache")


def compute_cache_key(
    request: SanitizedAdvisorRequest,
    *,
    prompt_versions: dict[str, str],
    policy_version: str,
    provider: str,
    primary_model: str,
    escalation_model: str | None,
) -> str:
    """Return the deterministic SHA-256 cache key for a sanitized request."""
    key_material = {
        "sanitized_request": request.model_dump(mode="json"),
        "feature_schema_version": request.features.feature_schema_version,
        "sanitizer_version": request.sanitizer_version,
        "prompt_versions": dict(sorted(prompt_versions.items())),
        "policy_version": policy_version,
        "provider": provider,
        "primary_model": primary_model,
        "escalation_model": escalation_model,
    }
    canonical = json.dumps(key_material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AdvisorCache:
    """Filesystem JSON cache. Corruption is treated as a miss, never a crash."""

    def __init__(self, directory: Path | str, *, enabled: bool = True) -> None:
        self.directory = Path(directory)
        self.enabled = enabled

    def _path_for(self, cache_key: str) -> Path:
        return self.directory / f"{cache_key}.json"

    def get(self, cache_key: str) -> CacheEntry | None:
        """Return a cached entry, or ``None`` on miss or safe corruption recovery."""
        if not self.enabled:
            return None
        path = self._path_for(cache_key)
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            logger.warning("Ignoring unreadable advisor cache entry %s: %s", path.name, error)
            return None
        try:
            entry = CacheEntry.model_validate(payload)
        except ValidationError as error:
            logger.warning("Ignoring invalid advisor cache entry %s: %s", path.name, error)
            return None
        if entry.cache_key != cache_key:
            logger.warning("Ignoring advisor cache entry with mismatched key: %s", path.name)
            return None
        return entry

    def put(self, entry: CacheEntry) -> None:
        """Atomically write a cache entry. Raises :class:`AdvisorCacheError` on I/O failure."""
        if not self.enabled:
            return
        payload = entry.model_dump(mode="json")
        serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        try:
            write_text_artifact(self._path_for(entry.cache_key), serialized)
        except (OSError, TypeError, ValueError) as error:
            raise AdvisorCacheError(f"failed to write advisor cache entry: {error}") from error

    def build_entry(
        self,
        *,
        cache_key: str,
        provider: str,
        primary_model: str,
        escalation_model: str | None,
        request: SanitizedAdvisorRequest,
        prompt_versions: dict[str, str],
        policy_version: str,
        primary_response: AdvisorModelOutput,
        escalation_response: AdvisorModelOutput | None,
    ) -> CacheEntry:
        """Construct a :class:`CacheEntry` from a completed advisor run."""
        return CacheEntry(
            cache_key=cache_key,
            provider=provider,
            primary_model=primary_model,
            escalation_model=escalation_model,
            feature_schema_version=request.features.feature_schema_version,
            sanitizer_version=request.sanitizer_version,
            prompt_version=prompt_versions["prompt_version"],
            output_schema_version=prompt_versions["output_schema_version"],
            policy_version=policy_version,
            primary_response=primary_response,
            escalation_response=escalation_response,
        )
