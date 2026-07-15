"""Shared helpers for writing machine-readable pipeline reports."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping


ARTIFACT_WRITE_ERRORS = (OSError, TypeError, ValueError)


def _replace_artifact(temp_path: Path, path: Path, *, attempts: int = 3, delay_seconds: float = 0.05) -> None:
    """Replace ``path`` with ``temp_path``, retrying transient Windows permission races."""
    for attempt in range(1, attempts + 1):
        try:
            temp_path.replace(path)
            return
        except PermissionError:
            if attempt == attempts:
                raise
            time.sleep(delay_seconds)


def _discard_temp_artifact(temp_path: Path | None) -> None:
    """Best-effort cleanup for a temporary artifact created during a failed write."""
    if temp_path is None:
        return
    temp_path.unlink(missing_ok=True)


def write_text_artifact(path: Path, content: str) -> Path:
    """Atomically write a text artifact and return its path.

    Build outputs are operational artifacts. Writing them through a temporary file and
    replacing the destination keeps callers from observing partially written output
    after interruption or disk errors.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(content)
        _replace_artifact(temp_path, path)
        return path
    except ARTIFACT_WRITE_ERRORS:
        _discard_temp_artifact(temp_path)
        raise


def write_bytes_artifact(path: Path, content: bytes) -> Path:
    """Atomically write a binary artifact and return its path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(content)
        _replace_artifact(temp_path, path)
        return path
    except ARTIFACT_WRITE_ERRORS:
        _discard_temp_artifact(temp_path)
        raise


def write_json_report(path: Path, payload: Mapping[str, Any]) -> Path:
    """Atomically write a JSON report and return its path."""
    return write_text_artifact(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
