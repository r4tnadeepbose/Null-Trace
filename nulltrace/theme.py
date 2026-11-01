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
BORDER = "#a8333a"        # every visible edge
BORDER_SOFT = "#6b2226"   # hairline separators only

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


# 1.0 is the original sizing; the app starts slightly larger than that.
SCALE = 1.15
SCALE_MIN = 1.0
SCALE_MAX = 1.4
SCALE_STEP = 0.1


def px(value: float) -> int:
    """Scale a pixel dimension alongside the fonts."""
    return int(round(value * SCALE))


def _px(size: float) -> int:
    return max(7, round(size * SCALE))


def font(size: int, weight: str | None = None) -> tuple:
    px = _px(size)
    return (UI_FAMILY, px, weight) if weight else (UI_FAMILY, px)


def mono(size: int, weight: str | None = None) -> tuple:
    px = _px(size)
    return (MONO_FAMILY, px, weight) if weight else (MONO_FAMILY, px)


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
    "Utility": MUTED,
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


def set_scale(value: float) -> float:
    """Resize every font. Call before building widgets, then rebuild the UI."""
    global SCALE, OUTPUT_FONT, OUTPUT_FONT_TITLE, OUTPUT_FONT_BOLD
    try:
        value = float(value)
    except (TypeError, ValueError):
        value = 1.15
    SCALE = min(SCALE_MAX, max(SCALE_MIN, round(value, 2)))
    OUTPUT_FONT = mono(12)
    OUTPUT_FONT_TITLE = mono(14, "bold")
    OUTPUT_FONT_BOLD = mono(12, "bold")
    TAG_COLORS.update({
        "title": (TEXT, OUTPUT_FONT_TITLE),
        "section": (ACCENT, OUTPUT_FONT_BOLD),
        "table_head": (ACCENT, None),
    })
    return SCALE
