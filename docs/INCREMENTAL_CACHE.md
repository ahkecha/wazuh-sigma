# Incremental Conversion Cache

The incremental cache is an optional optimization that avoids reparsing and reconverting unchanged Sigma rules on repeated pipeline runs. It maintains persistent rule IDs across runs and reuses cached Wazuh XML fragments for rules that haven't changed.

## Overview

On each conversion run, the pipeline:

1. Derives a stable identity for each rule (Sigma UUID or content hash)
2. Allocates or reuses a persistent Wazuh rule ID
3. Computes a deterministic fingerprint of the rule and conversion environment
4. Checks the content-addressed cache for a match
5. Reuses cached XML on hit; converts and caches on miss
6. Tracks deleted rules and removes them from output
7. Validates and publishes the final assembled ruleset

The cache is **entirely opt-in** and **disabled by default**. When disabled, the pipeline behaves exactly as before.

## Configuration

Add to `pipeline.yml`:

```yaml
incremental_cache:
  enabled: true
  directory: build/conversion-cache
  manifest: build/conversion-cache/manifest.json
  strict: false
```

### Options

- `enabled` (default: `false`): Enable incremental caching.
- `directory` (default: `build/conversion-cache`): Cache storage directory.
- `manifest` (default: `build/conversion-cache/manifest.json`): Manifest file tracking rule identities and IDs.
- `strict` (default: `false`): Fail on manifest corruption instead of treating as cache miss.

## Rule Identity

Each rule gets a stable identity that persists across runs:

### Preferred: Sigma UUID

If the rule has an `id` field (Sigma UUID), that becomes the identity:

```yaml
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
title: Suspicious PowerShell Download
```

### Fallback: Content Hash

If no UUID, the identity is `sha256(source_path:title)`:

```yaml
title: Suspicious cmd Execution
# No id field
# identity will be: sha256("rules/windows/process_creation.yml:Suspicious cmd Execution")
```

Renaming a fallback-identity rule (by file or title) produces a new identity and thus a new rule ID.

## Wazuh Rule IDs

Once a rule gets an ID, it keeps that ID across all future runs:

**First run:**
```
uuid-1   → 900000
uuid-2   → 900001
uuid-3   → 900002
```

**Second run (uuid-1 unchanged, uuid-2 modified, uuid-3 deleted, uuid-4 new):**
```
uuid-1   → 900000  (reused)
uuid-2   → 900001  (reused, reconverted)
uuid-3   → retired (deleted, ID never reused)
uuid-4   → 900003  (new)
```

The manifest persists the mapping:

```json
{
  "active": {
    "uuid-1": {"wazuh_rule_id": 900000, "fingerprint": "abc123..."},
    "uuid-2": {"wazuh_rule_id": 900001, "fingerprint": "def456..."}
  },
  "retired": {
    "uuid-3": {"wazuh_rule_id": 900002, "retired_at": "2026-07-13T..."}
  },
  "next_id": 900004
}
```

## Cache Invalidation

The conversion fingerprint includes:

- Normalized Sigma rule content
- Allocated Wazuh rule ID
- Field mapping version
- Backend output version
- Advisor effective level (in `apply` mode only)

A cache entry is invalidated (treated as miss) when:

- Any input rule content changes
- Field mapping version changes
- Backend output version changes
- Rule ID allocation changes
- Advisor mode is not `apply` (cache remains valid in `report-only` and `review`)
- Cached XML is malformed
- Cached XML contains wrong rule ID or invalid level

## Storage

```
build/conversion-cache/
  manifest.json              # Active and retired rule identities
  entries/
    abc123def456...json      # Cached XML fragment for fingerprint abc123def456...
    ghi789jkl012...json
```

Each entry file is named by its SHA-256 fingerprint. Entries contain:

- Wazuh rule ID
- XML fragment
- Sigma title
- Metadata (versions)

The entry is never referenced by name—lookup is always fingerprint-based.

## Deletion and Retirement

When a rule identity is no longer present in the source:

1. It moves from `active` to `retired` in the manifest
2. Its Wazuh rule ID is preserved (never reused automatically)
3. Its XML is removed from the final output
4. The deletion is recorded in the conversion report

To free IDs for reuse after long-term deletions, manually archive old manifest versions or reorganize the ID range—this is not automatic.

## Advisor Interaction

**`report-only` and `review` modes:**
- Advisor recommendations do not change XML
- Conversion cache remains valid even if advisor output changes
- Advisor report metadata may be refreshed independently

**`apply` mode:**
- An accepted effective level change invalidates the affected cache entry
- The rule is reconverted with the new level
- New cache entry is generated

## Atomicity

The pipeline guarantees no partial state:

1. All new/changed rules are converted in memory
2. New cache entries are written (can't corrupt old ones)
3. Final XML is generated and validated in a temporary file
4. Manifest is updated only after final XML validation succeeds
5. Active manifest is atomically replaced

If validation fails:
- The old manifest remains active
- The old XML remains published
- New cache entries become orphaned but don't affect active state

## Reporting

The conversion report includes incremental cache statistics:

```json
{
  "incremental_conversion": {
    "enabled": true,
    "manifest_version": "incremental-manifest-v1",
    "id_allocation_version": "persistent-id-v1",
    "backend_output_version": "wazuh-xml-v1",
    "next_id": 900143,
    "active_rules": 142,
    "retired_rules": 1,
    "cache_hits": 94,
    "cache_misses": 6
  }
}
```

Per-rule data:

```json
{
  "sigma_title": "Suspicious PowerShell Download",
  "wazuh_id": "900142",
  "conversion_cache": {
    "status": "hit",
    "identity": "a1b2c3d4...",
    "identity_source": "sigma_uuid",
    "fingerprint": "abc123def456..."
  }
}
```

Current status values are `hit` and `miss`.

## Running it

Enable incremental caching in `pipeline.yml`:

```yaml
incremental_cache:
  enabled: true
  directory: build/conversion-cache
  manifest: build/conversion-cache/manifest.json
```

Then run the config-driven converter:

```bash
sigma-pipeline convert --config pipeline.yml
```

## Safety Guarantees

- **No silent truncation:** All rejections are logged. Unchanged rules are reused, not silently dropped.
- **Complete validation:** Final XML always passes the standard validator and native Wazuh validation when configured.
- **Deterministic:** Same input always produces identical output (modulo timestamps in reports).
- **Backward compatible:** Disabling the cache preserves existing behavior exactly.
- **Corruption resilient:** Corrupted cache entries become cache misses, not crashes.
- **No hidden behavior:** All caching decisions are recorded in the report.

## Troubleshooting

**Manifest says "next_id is beyond range":**

The allocated ID range is exhausted. Either:
- Increase `wazuh.rule_id_end` in config
- Archive or clean up old manifest to start fresh (loses ID continuity)

**Cache hit rate is low:**

- Check `fingerprint_version` in generated entries—version mismatch indicates stale entries
- Verify field mapping hasn't changed unexpectedly
- Check backend output version hasn't drifted

**Rule ID changed unexpectedly:**

- Check source rule UUID (`id` field) didn't change
- For fallback-identity rules, verify source path and title are stable
- Manifests are not portable—keep cache and manifest together

**Performance didn't improve:**

- Incremental caching mainly benefits rules that are **unchanged**
- Changed rules still incur full conversion cost
- Memory usage for rule loading/normalization is not saved (only reconversion is skipped)
