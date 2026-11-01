"""Reference data shipped with the project.

Files live in the top-level ``data/`` folder so they can be edited without
touching code. Every loader falls back to a built-in default, which keeps the
application working when it is installed without the repository (for example
from a wheel or a frozen build).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load_lines(name: str, fallback: Iterable[str]) -> list[str]:
    path = DATA_DIR / name
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return list(fallback)
    values = [line.strip() for line in text.splitlines()]
    values = [line for line in values if line and not line.startswith("#")]
    return values or list(fallback)


def load_json(name: str, fallback: Any) -> Any:
    path = DATA_DIR / name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fallback


def reloadable() -> list[str]:
    """Names currently present on disk, used by the Toolkit module."""
    try:
        return sorted(p.name for p in DATA_DIR.iterdir() if p.is_file())
    except OSError:
        return []
