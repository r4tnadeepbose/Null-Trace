"""Black-and-white terminal palette with a hacker-red accent.

Sharp corners, monospace type, dim greys and one signal colour. Everything the
interface draws comes from here, so the whole app changes with one edit.
"""

from __future__ import annotations

# ------------------------------------------------------------------ palette
BG = "#08080a"
PANEL = "#0d0d0f"
CARD = "#101012"
ELEV = "#16161a"
ELEV_HOVER = "#1e1e23"
BORDER = "#2a2a2f"
BORDER_SOFT = "#1b1b1f"

TEXT = "#eae8e4"
MUTED = "#9a9791"
FAINT = "#6a6762"

RED = "#e23b3b"
RED_BRIGHT = "#ff5252"
RED_DIM = "#3a1416"

ACCENT = RED
ACCENT_HOVER = RED_BRIGHT
ACCENT_DIM = RED_DIM

OK = "#eae8e4"
WARN = "#d98a8a"
ERR = "#ff4d4d"
LINK = "#ff6b6b"
NOTE = "#cfccc6"

OUTPUT_BG = "#060607"
OUTPUT_TEXT = "#f2f0ec"

# ------------------------------------------------------------------ type
UI_FAMILY = "Consolas"
MONO_FAMILY = "Consolas"


def font(size: int, weight: str | None = None) -> tuple:
    return (UI_FAMILY, size, weight) if weight else (UI_FAMILY, size)


def mono(size: int, weight: str | None = None) -> tuple:
    return (MONO_FAMILY, size, weight) if weight else (MONO_FAMILY, size)


OUTPUT_FONT = mono(12)
OUTPUT_FONT_TITLE = mono(14, "bold")
OUTPUT_FONT_BOLD = mono(12, "bold")

# ------------------------------------------------------------------ geometry
RADIUS = 0
RADIUS_SMALL = 2
BORDER_WIDTH = 1

CATEGORY_COLORS = {
    "Network": "#d8d5cf",
    "Web": "#c4c1bb",
    "Identity": "#b0ada7",
    "Vulnerability": RED,
    "Media": "#9c9993",
    "System": "#88857f",
}

TAG_COLORS = {
    "title": (TEXT, OUTPUT_FONT_TITLE),
    "section": (RED, OUTPUT_FONT_BOLD),
    "kv": (TEXT, None),
    "kv_label": (MUTED, None),
    "kv_value": (TEXT, None),
    "table": (NOTE, None),
    "table_head": (RED, None),  # bold would break column alignment
    "table_rule": (BORDER, None),
    "text": (TEXT, None),
    "ok": (OK, None),
    "warn": (WARN, None),
    "err": (ERR, None),
    "link": (LINK, None),
    "muted": (FAINT, None),
    "note": (NOTE, None),
}

# (spacing above, spacing below) in pixels, applied as Tk tag options
TAG_SPACING = {
    "title": (10, 10),
    "section": (18, 4),
    "kv": (0, 2),
    "kv_label": (0, 2),
    "kv_value": (0, 2),
    "text": (0, 2),
    "ok": (0, 2),
    "warn": (0, 2),
    "err": (0, 2),
    "link": (0, 2),
    "muted": (0, 2),
    "note": (0, 2),
    "table": (0, 0),
    "table_head": (6, 1),
    "table_rule": (0, 3),
}
