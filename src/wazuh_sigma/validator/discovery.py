"""Rule-file discovery helpers for Wazuh validation."""

from __future__ import annotations

from pathlib import Path


def discover_rule_files(rules_path: str | Path) -> list[Path]:
    """Return XML rule files for a file or directory input path."""
    path = Path(rules_path)
    rule_files: list[Path] = []

    if path.is_file():
        if path.suffix.lower() == ".xml":
            rule_files.append(path)
    elif path.is_dir():
        rule_files.extend(path.glob("*.xml"))
        rule_files.extend(path.glob("**/*.xml"))

    return sorted(set(rule_files))
