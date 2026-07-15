"""Write generated Wazuh rulesets as editor- and manager-friendly chunks."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

from wazuh_sigma.backend.wazuh import WazuhBackend
from wazuh_sigma.reporting import write_json_report, write_text_artifact


DEFAULT_CHUNK_COUNT = 4


@dataclass(frozen=True)
class RulesetChunkManifest:
    """Summary of chunk files emitted for one generated ruleset."""

    enabled: bool
    output_dir: Path
    chunk_count: int
    rules_per_chunk: list[int]
    files: list[Path]

    def as_report(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "output_dir": str(self.output_dir),
            "chunk_count": self.chunk_count,
            "rules_per_chunk": list(self.rules_per_chunk),
            "files": [str(path) for path in self.files],
        }


def default_chunk_dir(output_file: str | Path) -> Path:
    """Return the default chunk directory for a generated XML artifact."""

    return Path(output_file).parent / "chunks"


def split_rules_evenly(rules: list[Element], chunk_count: int = DEFAULT_CHUNK_COUNT) -> list[list[Element]]:
    """Split rules into up to ``chunk_count`` balanced non-empty chunks."""

    if chunk_count <= 0:
        raise ValueError("chunk_count must be a positive integer")
    if not rules:
        return []

    actual_chunks = min(chunk_count, len(rules))
    base_size, remainder = divmod(len(rules), actual_chunks)
    chunks: list[list[Element]] = []
    start = 0
    for index in range(actual_chunks):
        size = base_size + (1 if index < remainder else 0)
        chunks.append(rules[start : start + size])
        start += size
    return chunks


def write_ruleset_chunks(
    *,
    backend: WazuhBackend,
    rules: list[Element],
    output_file: str | Path,
    chunk_count: int = DEFAULT_CHUNK_COUNT,
    output_dir: str | Path | None = None,
) -> RulesetChunkManifest:
    """Write chunk XML files and a manifest for a generated Wazuh ruleset."""

    chunk_dir = Path(output_dir) if output_dir is not None else default_chunk_dir(output_file)
    chunk_dir.mkdir(parents=True, exist_ok=True)

    chunks = split_rules_evenly(rules, chunk_count)
    width = max(3, len(str(len(chunks))))
    files: list[Path] = []
    rules_per_chunk: list[int] = []

    for index, chunk in enumerate(chunks, start=1):
        path = chunk_dir / f"sigma_rules_{index:0{width}d}.xml"
        rendered = backend.render_ruleset([copy.deepcopy(rule) for rule in chunk])
        write_text_artifact(path, rendered)
        files.append(path)
        rules_per_chunk.append(len(chunk))

    manifest = RulesetChunkManifest(
        enabled=True,
        output_dir=chunk_dir,
        chunk_count=len(files),
        rules_per_chunk=rules_per_chunk,
        files=files,
    )
    write_json_report(chunk_dir / "manifest.json", manifest.as_report())
    return manifest
