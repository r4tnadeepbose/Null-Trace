"""Persistent configuration and API key storage."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any


def _migrate_legacy(legacy: Path, path: Path) -> Path:
    """Move the pre-rename data directory once, keeping keys and history."""
    if path.exists() or not legacy.exists():
        return path
    try:
        legacy.rename(path)
        return path
    except OSError:
        # a running instance may hold the sqlite file; keep using the old folder
        return legacy


def data_dir() -> Path:
    base = os.environ.get("NULLTRACE_HOME")
    if base:
        path = Path(base)
    else:
        appdata = os.environ.get("APPDATA")
        if appdata:
            path = _migrate_legacy(Path(appdata) / "NullTrace", Path(appdata) / "Null-Trace")
        else:
            path = _migrate_legacy(Path.home() / ".nulltrace", Path.home() / ".null-trace")
    path.mkdir(parents=True, exist_ok=True)
    return path


CONFIG_PATH = data_dir() / "config.json"

DEFAULTS: dict[str, Any] = {
    "api_keys": {
        "hunter": "",
        "numverify": "",
        "ipqualityscore": "",
        "newsapi": "",
        "google_cse_key": "",
        "google_cse_cx": "",
        "hibp": "",
        "opencage": "",
        "github": "",
        "shodan": "",
        "virustotal": "",
    },
    "network": {
        "timeout": 12,
        "tor_proxy": "socks5h://127.0.0.1:9050",
        "browser": "",
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
    },
    "ui": {"keep_history": True, "font_scale": 1.15},
}


class Config:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or CONFIG_PATH
        self._lock = threading.Lock()
        self._data = self._load()

    def _load(self) -> dict[str, Any]:
        data = json.loads(json.dumps(DEFAULTS))
        try:
            stored = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return data
        for section, values in stored.items():
            if isinstance(values, dict) and isinstance(data.get(section), dict):
                data[section].update(values)
            else:
                data[section] = values
        return data

    def save(self) -> None:
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            tmp.replace(self.path)

    def key(self, name: str) -> str:
        return str(self._data.get("api_keys", {}).get(name, "") or "").strip()

    def set_key(self, name: str, value: str) -> None:
        self._data.setdefault("api_keys", {})[name] = value.strip()
        self.save()

    def get(self, section: str, name: str, default: Any = None) -> Any:
        return self._data.get(section, {}).get(name, default)

    def set(self, section: str, name: str, value: Any) -> None:
        self._data.setdefault(section, {})[name] = value
        self.save()

    @property
    def timeout(self) -> float:
        try:
            return float(self.get("network", "timeout", 12))
        except (TypeError, ValueError):
            return 12.0

    @property
    def user_agent(self) -> str:
        return str(self.get("network", "user_agent", DEFAULTS["network"]["user_agent"]))

    @property
    def tor_proxy(self) -> str:
        return str(self.get("network", "tor_proxy", DEFAULTS["network"]["tor_proxy"]))


CONFIG = Config()

KEY_LABELS: list[tuple[str, str, str]] = [
    ("hunter", "Hunter.io", "Email finder / verification. Free tier: 25 searches/mo"),
    ("numverify", "Numverify (APILayer)", "Phone carrier + line type. Free tier available"),
    ("ipqualityscore", "IPQualityScore", "Phone / IP fraud scoring. Free tier available"),
    ("newsapi", "NewsAPI.org", "News search. Free developer key"),
    ("google_cse_key", "Google CSE key", "Reverse image + dork programmatic search"),
    ("google_cse_cx", "Google CSE engine ID", "The cx value paired with the key above"),
    ("hibp", "HaveIBeenPwned", "Breach lookup by email"),
    ("opencage", "OpenCage", "Reverse geocoding for coordinates"),
    ("github", "GitHub token", "Raises API rate limit from 60 to 5000 req/h"),
    ("shodan", "Shodan", "Optional; host data falls back to free InternetDB"),
    ("virustotal", "VirusTotal", "File-hash reputation. Free tier: 4 lookups/min"),
]
