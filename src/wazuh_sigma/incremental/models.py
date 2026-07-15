"""Strict schemas for manifest and cache entries."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

MANIFEST_SCHEMA_VERSION = "incremental-manifest-v1"
CACHE_ENTRY_SCHEMA_VERSION = "incremental-cache-entry-v1"
RULE_ID_ALLOCATION_VERSION = "persistent-id-v1"
BACKEND_OUTPUT_VERSION = "wazuh-xml-v1"


class ManifestEntry(BaseModel):
    """Manifest record for a single active rule."""

    model_config = {"extra": "forbid"}

    source_path: str
    fingerprint: str
    wazuh_rule_id: int
    identity_source: Literal["sigma_uuid", "fallback_hash"]

    @field_validator("wazuh_rule_id")
    @classmethod
    def validate_wazuh_id(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("wazuh_rule_id must be positive")
        return v

    @field_validator("fingerprint")
    @classmethod
    def validate_fingerprint(cls, v: str) -> str:
        if not v or len(v) != 64:
            raise ValueError("fingerprint must be 64-character hex (SHA-256)")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("fingerprint must be valid hex")
        return v


class CacheEntry(BaseModel):
    """Single cached Wazuh XML rule fragment."""

    model_config = {"extra": "forbid"}

    schema_version: str = CACHE_ENTRY_SCHEMA_VERSION
    rule_identity: str
    source_path: str
    fingerprint: str
    wazuh_rule_id: int
    sigma_title: str
    xml_fragment: str
    metadata: dict = Field(default_factory=dict)

    @field_validator("wazuh_rule_id")
    @classmethod
    def validate_wazuh_id(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("wazuh_rule_id must be positive")
        return v

    @field_validator("fingerprint")
    @classmethod
    def validate_fingerprint(cls, v: str) -> str:
        if not v or len(v) != 64:
            raise ValueError("fingerprint must be 64-character hex (SHA-256)")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("fingerprint must be valid hex")
        return v


class RetiredRuleEntry(BaseModel):
    """Record of a retired (deleted) rule that previously had a Wazuh ID."""

    model_config = {"extra": "forbid"}

    wazuh_rule_id: int
    retired_at: str


class RuleManifest(BaseModel):
    """Persistent manifest tracking all rule identities, IDs, and status."""

    model_config = {"extra": "forbid"}

    schema_version: str = MANIFEST_SCHEMA_VERSION
    id_allocation_version: str = RULE_ID_ALLOCATION_VERSION
    backend_output_version: str = BACKEND_OUTPUT_VERSION
    field_mapping_version: str
    active: dict[str, ManifestEntry] = Field(default_factory=dict)
    retired: dict[str, RetiredRuleEntry] = Field(default_factory=dict)
    next_id: int

    @field_validator("next_id")
    @classmethod
    def validate_next_id(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("next_id must be positive")
        return v

    @field_validator("field_mapping_version")
    @classmethod
    def validate_field_mapping_version(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("field_mapping_version must not be empty")
        return v

    def retire_identity(self, rule_identity: str, wazuh_rule_id: int) -> None:
        """Move an identity from active to retired."""
        if rule_identity in self.active:
            del self.active[rule_identity]
        self.retired[rule_identity] = RetiredRuleEntry(
            wazuh_rule_id=wazuh_rule_id,
            retired_at=datetime.now(timezone.utc).isoformat(),
        )

    def allocate_id_for_identity(self, rule_identity: str, source_path: str, fingerprint: str, identity_source: Literal["sigma_uuid", "fallback_hash"], end_id: int) -> int:
        """Allocate a stable Wazuh ID for a rule identity."""
        # If already allocated, return existing ID
        if rule_identity in self.active:
            return self.active[rule_identity].wazuh_rule_id

        # Allocate new ID
        if self.next_id > end_id:
            raise ValueError(f"exhausted rule ID range at {self.next_id}")

        new_id = self.next_id
        self.next_id += 1
        self.active[rule_identity] = ManifestEntry(
            source_path=source_path,
            fingerprint=fingerprint,
            wazuh_rule_id=new_id,
            identity_source=identity_source,
        )
        return new_id
