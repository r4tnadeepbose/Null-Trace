"""Terminal palette: black, white and one signal red.

Sharp corners, monospace type, bright text and a single accent. Everything the
interface draws comes from this module, so the whole app changes with one edit.
"""

from __future__ import annotations

BG = "#08080a"
PANEL = "#0d0d0f"
CARD = "#101012"
ELEV = "#17171b"
ELEV_HOVER = "#232329"
BORDER = "#9a2f34"
BORDER_SOFT = "#5f2024"

TEXT = "#ffffff"
MUTED = "#d4d2ce"
FAINT = "#a3a09a"

ACCENT = "#e23b3b"
ACCENT_HOVER = "#ff5252"
ACCENT_DIM = "#3a1416"
ON_ACCENT = "#0b0b0d"

OK = "#ffffff"
WARN = "#ff8f8f"
ERR = "#ff4d4d"
LINK = "#ff6b6b"
NOTE = "#e8e5e0"

OUTPUT_BG = "#060607"
OUTPUT_TEXT = "#ffffff"
CHIP_TEXT = "#ffffff"

UI_FAMILY = "Consolas"
MONO_FAMILY = "Consolas"


def font(size: int, weight: str | None = None) -> tuple:
    return (UI_FAMILY, size, weight) if weight else (UI_FAMILY, size)


def mono(size: int, weight: str | None = None) -> tuple:
    return (MONO_FAMILY, size, weight) if weight else (MONO_FAMILY, size)


OUTPUT_FONT = mono(12)
OUTPUT_FONT_TITLE = mono(14, "bold")
OUTPUT_FONT_BOLD = mono(12, "bold")

RADIUS = 0
RADIUS_SMALL = 2
BORDER_WIDTH = 1

CATEGORY_COLORS = {
    "Recon": TEXT,
    "Network": TEXT,
    "Web": MUTED,
    "Identity": MUTED,
    "Vulnerability": ACCENT,
    "Media": MUTED,
    "System": FAINT,
}

TAG_COLORS = {
    "title": (TEXT, OUTPUT_FONT_TITLE),
    "section": (ACCENT, OUTPUT_FONT_BOLD),
    "kv": (TEXT, None),
    "kv_label": (MUTED, None),
    "kv_value": (TEXT, None),
    "table": (NOTE, None),
    "table_head": (ACCENT, None),  # bold would break column alignment
    "table_rule": (BORDER_SOFT, None),
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
