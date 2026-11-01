"""Dark, muted palette shared by every widget."""

from __future__ import annotations

BG = "#111318"
PANEL = "#171a21"
CARD = "#1b1f27"
ELEV = "#232833"
ELEV_HOVER = "#2a303c"
BORDER = "#2d333f"
BORDER_SOFT = "#242a34"

TEXT = "#e7e2d8"      # parchment
OUTPUT_BG = "#0c0f14"  # darker well behind scan output
OUTPUT_TEXT = "#f0ece3"  # higher contrast for dense monospace text
MUTED = "#9ba2af"
FAINT = "#6b7280"
ACCENT = "#7fa0c4"     # muted blue
ACCENT_HOVER = "#93b4d6"
ACCENT_DIM = "#2f4256"

OK = "#8fb59a"
WARN = "#d7b26a"
ERR = "#cd8383"
LINK = "#93b4d6"
NOTE = "#c9c3b6"

FONT_UI = ("Segoe UI", 13)
FONT_UI_SMALL = ("Segoe UI", 11)
FONT_TITLE = ("Segoe UI", 24, "bold")
FONT_SECTION = ("Segoe UI", 12, "bold")
FONT_MONO = ("Consolas", 11)

OUTPUT_FONT = ("Consolas", 12)
OUTPUT_FONT_TITLE = ("Consolas", 15, "bold")
OUTPUT_FONT_BOLD = ("Consolas", 12, "bold")

TAG_COLORS = {
    "title": (TEXT, OUTPUT_FONT_TITLE),
    "section": (ACCENT, OUTPUT_FONT_BOLD),
    "kv": (TEXT, None),
    "kv_label": (MUTED, None),
    "kv_value": (TEXT, None),
    "table": (NOTE, None),
    "table_head": (ACCENT, None),  # bold would break column alignment
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
