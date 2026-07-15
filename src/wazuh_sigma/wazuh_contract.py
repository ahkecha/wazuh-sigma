"""Shared validation for Wazuh API deployment contract values."""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar
from urllib.parse import urlparse


ErrorT = TypeVar("ErrorT", bound=Exception)


def validate_wazuh_host(host: str, *, error_type: type[ErrorT] = ValueError) -> str:
    """Return a normalized Wazuh API host after validating it is an HTTP(S) URL."""
    normalized = host.strip().rstrip("/") + "/"
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise error_type("Wazuh host must be an http(s) URL")
    return normalized


def validate_remote_rule_filename(remote_file: str, *, error_type: type[ErrorT] = ValueError) -> str:
    """Return a safe Wazuh custom-rule filename.

    Wazuh custom rule uploads are intentionally scoped to one managed file. Rejecting
    path-like values keeps the deployer from becoming a remote file manager.
    """
    normalized = remote_file.strip()
    if not normalized:
        raise error_type("Remote rule filename must not be empty")
    parts = normalized.replace("\\", "/").split("/")
    if Path(normalized).is_absolute() or ".." in parts:
        raise error_type("Remote rule filename must be a filename, not a path")
    if len(parts) != 1:
        raise error_type("Remote rule filename must not contain path separators")
    if Path(normalized).suffix.lower() != ".xml":
        raise error_type("Remote rule filename must end with .xml")
    return normalized
