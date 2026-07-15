"""Repository-level quality gates for maintainability invariants."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_PATHS = [ROOT / "src", ROOT / "tests"]
PLACEHOLDER_MARKERS = tuple(
    "".join(parts)
    for parts in (
        ("TO", "DO"),
        ("FIX", "ME"),
        ("HA", "CK"),
        ("XX", "X"),
        ("Not", "Implemented"),
    )
)


def iter_python_files() -> list[Path]:
    """Return project Python files that should satisfy source-quality invariants."""
    return sorted(
        path
        for base_path in PYTHON_PATHS
        for path in base_path.rglob("*.py")
        if "__pycache__" not in path.parts
    )


def test_no_broad_exception_handlers_in_source_or_tests():
    """Overly broad exception handlers hide bugs and must stay out of the codebase."""
    offenders: list[str] = []
    for path in iter_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name):
                if node.type.id == "Exception":
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert offenders == []


def test_no_placeholder_markers_in_source_or_tests():
    """Placeholder work markers should be tracked in real planning docs, not code."""
    offenders: list[str] = []
    this_file = Path(__file__).resolve()
    for path in iter_python_files():
        if path == this_file:
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if any(marker in line for marker in PLACEHOLDER_MARKERS):
                offenders.append(f"{path.relative_to(ROOT)}:{line_number}: {line.strip()}")

    assert offenders == []
