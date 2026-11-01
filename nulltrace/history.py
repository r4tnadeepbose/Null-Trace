"""Scan history backed by sqlite (stdlib)."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from typing import Any

from .config import data_dir

DB_PATH = data_dir() / "history.db"
_LOCK = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS scans (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               module TEXT NOT NULL,
               title TEXT NOT NULL,
               target TEXT,
               started TEXT NOT NULL,
               finished TEXT,
               status TEXT,
               lines TEXT NOT NULL DEFAULT '[]'
           )"""
    )
    return conn


def add_scan(module: str, title: str, target: str, started: datetime,
             status: str, lines: list[tuple[str, str]]) -> int:
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO scans (module, title, target, started, finished, status, lines)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (module, title, target, started.isoformat(timespec="seconds"),
             datetime.now().isoformat(timespec="seconds"), status,
             json.dumps(lines)),
        )
        return int(cursor.lastrowid)


def list_scans(limit: int = 500) -> list[dict[str, Any]]:
    with _LOCK, _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, module, title, target, started, status FROM scans"
            " ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def load_scan(scan_id: int) -> dict[str, Any] | None:
    with _LOCK, _connect() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    record = dict(row)
    record["lines"] = json.loads(record["lines"] or "[]")
    return record


def delete_scan(scan_id: int) -> None:
    with _LOCK, _connect() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


def clear_history() -> None:
    with _LOCK, _connect() as conn:
        conn.execute("DELETE FROM scans")
