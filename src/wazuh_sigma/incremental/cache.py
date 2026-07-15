"""Content-addressed JSON cache for conversion fragments."""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from pydantic import ValidationError

from wazuh_sigma.incremental.errors import ConversionCacheError
from wazuh_sigma.incremental.models import CacheEntry
from wazuh_sigma.reporting import write_text_artifact

logger = logging.getLogger("SigmaIncremental.cache")


class ConversionCache:
    """Filesystem JSON cache for Wazuh XML rule fragments."""

    def __init__(self, cache_dir: Path | str, *, enabled: bool = True, strict: bool = False):
        self.cache_dir = Path(cache_dir)
        self.enabled = enabled
        self.strict = strict
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.entries_dir = self.cache_dir / "entries"
        self.entries_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, fingerprint: str) -> Path:
        return self.entries_dir / f"{fingerprint}.json"

    def get(self, fingerprint: str) -> CacheEntry | None:
        """Return cached entry, or None on miss or safe corruption."""
        if not self.enabled:
            return None

        path = self._path_for(fingerprint)
        if not path.is_file():
            return None

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            message = f"unreadable cache entry {path.name}: {e}"
            if self.strict:
                raise ConversionCacheError(message) from e
            logger.warning("Ignoring %s", message)
            return None

        try:
            entry = CacheEntry.model_validate(payload)
        except ValidationError as e:
            message = f"invalid cache entry {path.name}: {e}"
            if self.strict:
                raise ConversionCacheError(message) from e
            logger.warning("Ignoring %s", message)
            return None

        if entry.fingerprint != fingerprint:
            message = f"cache entry {path.name} has mismatched fingerprint"
            if self.strict:
                raise ConversionCacheError(message)
            logger.warning("Ignoring %s", message)
            return None

        return entry

    def put(self, entry: CacheEntry) -> None:
        """Atomically write cache entry."""
        if not self.enabled:
            return

        try:
            payload = entry.model_dump(mode="json")
            serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
            write_text_artifact(self._path_for(entry.fingerprint), serialized)
        except (OSError, TypeError, ValueError) as e:
            raise ConversionCacheError(f"failed to write cache entry: {e}") from e

    def validate_fragment(self, entry: CacheEntry, expected_rule_id: int) -> str:
        """Validate and return XML fragment.

        Checks:
        - XML parses correctly
        - Contains exactly one <rule> element
        - Rule ID matches expected
        - Level is within 0-15
        - Required attributes exist

        Returns: XML fragment string
        Raises: ConversionCacheError on validation failure
        """
        try:
            root = ET.fromstring(entry.xml_fragment)
        except ET.ParseError as e:
            raise ConversionCacheError(f"cached XML is malformed: {e}") from e

        if root.tag != "rule":
            raise ConversionCacheError(f"cached fragment root is {root.tag}, expected rule")

        fragment_rule_id = root.get("id")
        if not fragment_rule_id:
            raise ConversionCacheError("cached rule missing 'id' attribute")

        try:
            fragment_id_int = int(fragment_rule_id)
        except ValueError as e:
            raise ConversionCacheError(f"cached rule ID is not an integer: {e}") from e

        if fragment_id_int != expected_rule_id:
            raise ConversionCacheError(
                f"cached rule ID {fragment_id_int} does not match expected {expected_rule_id}"
            )

        level_str = root.get("level")
        if level_str:
            try:
                level = int(level_str)
                if not (0 <= level <= 15):
                    raise ConversionCacheError(
                        f"cached rule level {level} is outside 0-15"
                    )
            except ValueError as e:
                raise ConversionCacheError(f"cached rule level is not an integer: {e}") from e

        return entry.xml_fragment
