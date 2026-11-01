"""Two palettes behind one switch: terminal black and full white.

Brightness matters here. Text is pure white on black and pure black on white;
muted tones stay readable instead of fading into the background. Every colour,
font and radius the interface draws comes from this module, so switching themes
only means calling :func:`apply` and rebuilding the widgets.
"""

from __future__ import annotations

MODE = "dark"

DARK = {
    "BG": "#08080a",
    "PANEL": "#0d0d0f",
    "CARD": "#101012",
    "ELEV": "#17171b",
    "ELEV_HOVER": "#232329",
    "BORDER": "#9a2f34",
    "BORDER_SOFT": "#5f2024",
    "TEXT": "#ffffff",
    "MUTED": "#d4d2ce",
    "FAINT": "#a3a09a",
    "ACCENT": "#e23b3b",
    "ACCENT_HOVER": "#ff5252",
    "ACCENT_DIM": "#3a1416",
    "ON_ACCENT": "#0b0b0d",
    "OK": "#ffffff",
    "WARN": "#ff8f8f",
    "ERR": "#ff4d4d",
    "LINK": "#ff6b6b",
    "NOTE": "#e8e5e0",
    "OUTPUT_BG": "#060607",
    "OUTPUT_TEXT": "#ffffff",
    "CHIP_TEXT": "#ffffff",
}

LIGHT = {
    "BG": "#ffffff",
    "PANEL": "#fafafa",
    "CARD": "#ffffff",
    "ELEV": "#f0f0f0",
    "ELEV_HOVER": "#e4e4e4",
    "BORDER": "#000000",
    "BORDER_SOFT": "#8a8a8a",
    "TEXT": "#000000",
    "MUTED": "#2b2b2b",
    "FAINT": "#555555",
    "ACCENT": "#c62828",
    "ACCENT_HOVER": "#e23b3b",
    "ACCENT_DIM": "#fde7e7",
    "ON_ACCENT": "#ffffff",
    "OK": "#000000",
    "WARN": "#b3261e",
    "ERR": "#c62828",
    "LINK": "#b3261e",
    "NOTE": "#1d1d1d",
    "OUTPUT_BG": "#ffffff",
    "OUTPUT_TEXT": "#000000",
    "CHIP_TEXT": "#000000",
}

BG = PANEL = CARD = ELEV = ELEV_HOVER = ""
BORDER = BORDER_SOFT = TEXT = MUTED = FAINT = ""
ACCENT = ACCENT_HOVER = ACCENT_DIM = ON_ACCENT = ""
OK = WARN = ERR = LINK = NOTE = ""
OUTPUT_BG = OUTPUT_TEXT = CHIP_TEXT = ""

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

CATEGORY_COLORS: dict[str, str] = {}
TAG_COLORS: dict[str, tuple] = {}
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


def apply(mode: str) -> None:
    """Switch palette. Call before building widgets."""
    global MODE
    MODE = "light" if mode == "light" else "dark"
    globals().update(LIGHT if MODE == "light" else DARK)

    CATEGORY_COLORS.clear()
    CATEGORY_COLORS.update({
        "Network": TEXT,
        "Web": MUTED,
        "Identity": MUTED,
        "Vulnerability": ACCENT,
        "Media": MUTED,
        "System": FAINT,
    })
    TAG_COLORS.clear()
    TAG_COLORS.update({
        "title": (TEXT, OUTPUT_FONT_TITLE),
        "section": (ACCENT, OUTPUT_FONT_BOLD),
        "kv": (TEXT, None),
        "kv_label": (MUTED, None),
        "kv_value": (TEXT, None),
        "table": (NOTE, None),
        "table_head": (ACCENT, None),
        "table_rule": (BORDER_SOFT, None),
        "text": (TEXT, None),
        "ok": (OK, None),
        "warn": (WARN, None),
        "err": (ERR, None),
        "link": (LINK, None),
        "muted": (FAINT, None),
        "note": (NOTE, None),
    })


def is_light() -> bool:
    return MODE == "light"


apply("dark")
