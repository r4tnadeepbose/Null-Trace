"""Open links in the user's browser, preferring Brave when it is installed."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

from .config import CONFIG

BRAVE_RELATIVE = Path("BraveSoftware") / "Brave-Browser" / "Application" / "brave.exe"


def brave_path() -> str | None:
    """Find brave.exe on PATH or in the usual Windows install locations."""
    found = shutil.which("brave") or shutil.which("brave.exe")
    if found:
        return found
    roots = []
    for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        value = os.environ.get(env)
        if value:
            roots.append(Path(value))
    for root in roots:
        candidate = root / BRAVE_RELATIVE
        if candidate.is_file():
            return str(candidate)
    return None


def _launch(executable: str, url: str) -> bool:
    try:
        flags = 0
        if sys.platform == "win32":
            flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        subprocess.Popen([executable, url], close_fds=True, creationflags=flags)
        return True
    except OSError:
        return False


def open_url(url: str) -> bool:
    """Open a URL. Order: configured browser, Brave, system default."""
    if not url:
        return False
    configured = str(CONFIG.get("network", "browser", "") or "").strip()
    if configured and _launch(configured, url):
        return True
    brave = brave_path()
    if brave and _launch(brave, url):
        return True
    try:
        return bool(webbrowser.open(url))
    except Exception:
        return False
