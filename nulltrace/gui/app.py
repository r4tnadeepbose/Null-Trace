"""Null-Trace desktop application: dashboard shell, module views and local history."""

from __future__ import annotations

import gc
import platform
import queue
import shutil
import sys
import time
import tkinter as tk
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from .. import theme
from ..config import CONFIG, CONFIG_PATH, KEY_LABELS
from ..history import add_scan, clear_history, delete_scan, list_scans, load_scan
from ..job import Event, Field, JobRunner, Module
from ..modules import all_modules, grouped
from ..version import APP_NAME, AUTHOR, GITHUB, TAGLINE, VERSION

QUICK_MODULES = ("ip_info", "exposure_audit", "port_scan", "username_scan",
                 "metadata", "cve_research")
CATEGORY_COLORS = theme.CATEGORY_COLORS


class FieldWidget:
    def __init__(self, field: Field, getter, setter) -> None:
        self.field = field
        self._get = getter
        self._set = setter

    def read(self):
        return self._get()

    def write(self, value) -> None:
        self._set(value)


class NullTraceApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__(fg_color=theme.BG)
        self._set_window_icon()
        self.title(f"{APP_NAME.upper()}  //  OSINT WORKBENCH")
        self.geometry("1380x880")
        self.minsize(1160, 760)
        self.configure(fg_color=theme.BG)
        ctk.set_appearance_mode("dark")

        self.modules = all_modules()
        self.groups = grouped()
        self.current: Module | None = None
        self.view = "dashboard"
        self.nav_buttons: dict[str, ctk.CTkButton] = {}
        self.form_widgets: dict[str, FieldWidget] = {}
        self.form_state: dict[str, dict[str, object]] = {}
        self.runner = JobRunner()
        self.current_lines: list[tuple[str, str]] = []
        self.output: ctk.CTkTextbox | None = None
        self.output_status: ctk.CTkLabel | None = None
        self.link_map: dict[int, str] = {}
        self.started = 0.0
        self._tick_job = None
        self._flush_job = None
        self._pending: list[tuple[str, str]] = []
        self._toast_widget = None

        self._build_shell()
        self._render_nav()
        self._show_dashboard()
        self.focus_set()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<Control-Return>", lambda _e: self._run())
        self.bind("<Control-s>", lambda _e: self._export())
        self.bind("<Control-f>", lambda _e: self.search_entry.focus_set())
        self.after(200, self._poll_queue)

    # ------------------------------------------------------------------ shell
    def _build_shell(self) -> None:
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, width=248, corner_radius=0, fg_color=theme.PANEL)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_rowconfigure(2, weight=1)
        sidebar.grid_columnconfigure(0, weight=1)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 10))
        ctk.CTkFrame(brand, height=2, fg_color=theme.RED).pack(fill="x", pady=(0, 12))
        mark = ctk.CTkFrame(brand, fg_color="transparent")
        mark.pack(fill="x")
        ctk.CTkLabel(mark, text="▌", font=theme.font(22, "bold"), text_color=theme.RED,
                     anchor="w").pack(side="left")
        ctk.CTkLabel(mark, text=APP_NAME.upper(), font=theme.font(22, "bold"),
                     text_color=theme.TEXT, anchor="w").pack(side="left", padx=(2, 0))
        ctk.CTkLabel(brand, text=TAGLINE.upper(), font=theme.font(9),
                     text_color=theme.FAINT, anchor="w").pack(fill="x", pady=(2, 0))
        meta = ctk.CTkFrame(brand, fg_color="transparent")
        meta.pack(fill="x", pady=(8, 0))
        ctk.CTkLabel(meta, text=f"v{VERSION}", font=theme.font(9),
                     text_color=theme.ACCENT).pack(side="left")
        credit = ctk.CTkLabel(meta, text=f"·  by {AUTHOR}", font=theme.font(9),
                              text_color=theme.FAINT)
        credit.pack(side="left", padx=(6, 0))
        credit.bind("<Button-1>", lambda _e: webbrowser.open(GITHUB))
        credit.configure(cursor="hand2")

        self.search_entry = ctk.CTkEntry(
            sidebar, placeholder_text="Filter modules  (Ctrl+F)", height=32, corner_radius=theme.RADIUS,
            fg_color=theme.BG, border_color=theme.BORDER, text_color=theme.TEXT,
            placeholder_text_color=theme.FAINT, font=theme.font(11))
        self.search_entry.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))
        self.search_entry.bind("<KeyRelease>",
                               lambda _e: self._render_nav(self.search_entry.get()))
        self.search_entry.bind(
            "<Escape>",
            lambda _e: (self.search_entry.delete(0, "end"), self._render_nav()))

        self.nav_scroll = ctk.CTkScrollableFrame(
            sidebar, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=theme.ELEV, scrollbar_button_hover_color=theme.BORDER)
        self.nav_scroll.grid(row=2, column=0, sticky="nsew", padx=(10, 4), pady=(0, 4))
        self.nav_scroll.grid_columnconfigure(0, weight=1)

        ctk.CTkFrame(sidebar, height=1, fg_color=theme.BORDER).grid(
            row=3, column=0, sticky="ew", padx=14, pady=(2, 0))

        footer = ctk.CTkFrame(sidebar, fg_color=theme.BG, corner_radius=0)
        footer.grid(row=4, column=0, sticky="ew", padx=0, pady=(0, 0))
        inner_footer = ctk.CTkFrame(footer, fg_color="transparent")
        inner_footer.pack(fill="x", padx=12, pady=(8, 12))
        ctk.CTkLabel(inner_footer, text="WORKSPACE", anchor="w",
                     font=theme.font(9, "bold"),
                     text_color=theme.FAINT).pack(fill="x", padx=6, pady=(0, 4))
        for label, target in (("Dashboard", "dashboard"), ("History", "history"),
                              ("Settings", "settings")):
            ctk.CTkButton(inner_footer, text=label.upper(), height=32, corner_radius=theme.RADIUS, anchor="w",
                          fg_color="transparent", hover_color=theme.ELEV,
                          text_color=theme.MUTED, font=theme.font(12),
                          command=lambda t=target: self._navigate(t)).pack(fill="x", pady=1)
        ctk.CTkLabel(inner_footer, text="LOCAL ONLY · REQUESTS GO UPSTREAM",
                     font=theme.font(9), text_color=theme.FAINT,
                     anchor="w").pack(fill="x", padx=6, pady=(8, 0))

        self.body = ctk.CTkFrame(self, fg_color=theme.BG, corner_radius=0)
        self.body.grid(row=0, column=1, sticky="nsew")
        self.body.grid_columnconfigure(0, weight=1)

    # ------------------------------------------------------------------ nav
    def _render_nav(self, needle: str = "") -> None:
        for child in self.nav_scroll.winfo_children():
            child.destroy()
        self.nav_buttons.clear()
        needle = needle.strip().lower()
        shown = 0
        for category, modules in self.groups.items():
            matches = [
                m for m in modules
                if not needle or needle in m.title.lower() or needle in m.id.lower()
                or needle in category.lower() or needle in m.summary.lower()
            ]
            if not matches:
                continue
            ctk.CTkLabel(self.nav_scroll, text=f"[ {category.upper()} ]",
                         font=theme.font(9, "bold"), text_color=theme.FAINT,
                         anchor="w").pack(fill="x", padx=8, pady=(12, 3))
            for module in matches:
                button = ctk.CTkButton(
                    self.nav_scroll, text=module.title.upper(), anchor="w", height=30,
                    corner_radius=theme.RADIUS, fg_color="transparent", hover_color=theme.ELEV,
                    text_color=theme.MUTED, font=theme.font(12),
                    command=lambda m=module: self._select_module(m.id))
                button.pack(fill="x", padx=2, pady=1)
                self.nav_buttons[module.id] = button
                shown += 1
        if not shown:
            ctk.CTkLabel(self.nav_scroll, text="No module matches that filter.",
                         font=theme.font(10), text_color=theme.FAINT,
                         anchor="w", wraplength=190).pack(fill="x", padx=8, pady=12)
        self._highlight_nav()

    def _highlight_nav(self) -> None:
        for module_id, button in self.nav_buttons.items():
            if module_id == (self.current.id if self.current and self.view == "module" else None):
                button.configure(fg_color=theme.ACCENT_DIM, text_color=theme.RED_BRIGHT,
                                 hover_color=theme.ELEV)
            else:
                button.configure(fg_color="transparent", text_color=theme.MUTED,
                                 hover_color=theme.ELEV)

    def _navigate(self, target: str) -> None:
        if self.runner.running:
            self._toast("Stop the running job before switching views", "warn")
            return
        if target == "dashboard":
            self._show_dashboard()
        elif target == "history":
            self._show_history()
        elif target == "settings":
            self._show_settings()

    # ------------------------------------------------------------------ helpers
    def _grid_rows(self, weights: dict[int, int]) -> None:
        for row in range(4):
            self.body.grid_rowconfigure(row, weight=weights.get(row, 0))

    def _clear_body(self) -> None:
        for child in self.body.winfo_children():
            child.destroy()
        self.form_widgets.clear()
        self.output = None
        self.output_status = None
        # keep focus off auto-focused entries so placeholders stay visible
        self.after(1, self.focus_set)

    def _page_header(self, title: str, subtitle: str, chip: str | None = None) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.body, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="new", padx=30, pady=(24, 10))
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text=title.upper(), anchor="w",
                     font=theme.font(24, "bold"),
                     text_color=theme.TEXT).grid(row=0, column=0, sticky="w")
        if chip:
            ctk.CTkLabel(frame, text=f"[ {chip.upper()} ]", anchor="e",
                         font=theme.font(9, "bold"),
                         text_color=CATEGORY_COLORS.get(chip, theme.ACCENT),
                         fg_color=theme.CARD, corner_radius=theme.RADIUS, padx=10, pady=3
                         ).grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(frame, text=subtitle, anchor="w", justify="left", wraplength=980,
                     font=theme.font(11),
                     text_color=theme.MUTED).grid(row=1, column=0, columnspan=2,
                                                  sticky="w", pady=(4, 0))
        return frame

    def _card(self, parent, **kwargs) -> ctk.CTkFrame:
        return ctk.CTkFrame(parent, fg_color=theme.PANEL, corner_radius=theme.RADIUS,
                            border_width=1, border_color=theme.BORDER_SOFT, **kwargs)

    def _toast(self, text: str, kind: str = "ok") -> None:
        if self._toast_widget is not None:
            try:
                self._toast_widget.destroy()
            except Exception:
                pass
        color = {"ok": theme.OK, "warn": theme.WARN, "err": theme.ERR}.get(kind, theme.TEXT)
        self._toast_widget = ctk.CTkLabel(
            self.body, text=text, font=theme.font(11), text_color=color,
            fg_color=theme.CARD, corner_radius=theme.RADIUS, padx=14, pady=8,
            border_width=1, border_color=theme.BORDER)
        self._toast_widget.place(relx=0.985, rely=0.975, anchor="se")
        label = self._toast_widget

        def dismiss() -> None:
            try:
                label.destroy()
            except Exception:
                pass

        self.after(2800, dismiss)

    # ------------------------------------------------------------------ dashboard
    # ------------------------------------------------------------------ dashboard
    def _set_window_icon(self) -> None:
        root = Path(__file__).resolve().parents[2]
        ico, png = root / "assets" / "app.ico", root / "assets" / "app.png"
        try:
            if ico.exists():
                self.iconbitmap(str(ico))
                return
            if png.exists():
                from PIL import Image, ImageTk
                self.iconphoto(True, ImageTk.PhotoImage(Image.open(png)))
        except Exception:
            pass

    def _show_dashboard(self) -> None:
        self.view = "dashboard"
        self.current = None
        self._clear_body()
        self._grid_rows({0: 0, 1: 0, 2: 1})
        self._highlight_nav()

        records = list_scans(limit=1000)
        now = datetime.now()
        week_ago = now - timedelta(days=7)
        recent_week = 0
        for record in records:
            try:
                if datetime.fromisoformat(record["started"]) >= week_ago:
                    recent_week += 1
            except ValueError:
                continue
        keys_set = sum(1 for name, _label, _hint in KEY_LABELS if CONFIG.key(name))

        header = ctk.CTkFrame(self.body, fg_color="transparent")
        header.grid(row=0, column=0, sticky="new", padx=30, pady=(24, 12))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="DASHBOARD", anchor="w",
                     font=theme.font(24, "bold"),
                     text_color=theme.TEXT).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text=f"{now:%A, %d %B %Y}  ·  {len(self.modules)} modules ready",
                     anchor="w", font=theme.font(11),
                     text_color=theme.MUTED).grid(row=1, column=0, sticky="w", pady=(4, 0))

        stats = ctk.CTkFrame(self.body, fg_color="transparent")
        stats.grid(row=1, column=0, sticky="ew", padx=30)
        for column in range(4):
            stats.grid_columnconfigure(column, weight=1, uniform="stat")
        for column, (label, value, hint, color) in enumerate((
            ("Total runs", str(len(records)), "stored locally", theme.ACCENT),
            ("Last 7 days", str(recent_week), "scans", theme.OK),
            ("API keys", f"{keys_set}/{len(KEY_LABELS)}", "configured", theme.WARN),
            ("Modules", str(len(self.modules)), "across 6 categories", theme.TEXT),
        )):
            card = self._card(stats)
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=16, pady=14)
            ctk.CTkLabel(inner, text=label.upper(), anchor="w",
                         font=theme.font(9, "bold"),
                         text_color=theme.FAINT).pack(fill="x")
            ctk.CTkLabel(inner, text=value, anchor="w",
                         font=theme.font(26, "bold"),
                         text_color=color).pack(fill="x", pady=(2, 0))
            ctk.CTkLabel(inner, text=hint, anchor="w", font=theme.font(9),
                         text_color=theme.MUTED).pack(fill="x")

        lower = ctk.CTkFrame(self.body, fg_color="transparent")
        lower.grid(row=2, column=0, sticky="nsew", padx=30, pady=(14, 18))
        lower.grid_columnconfigure(0, weight=3)
        lower.grid_columnconfigure(1, weight=2)
        lower.grid_rowconfigure(0, weight=1)

        left = self._card(lower)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.grid_columnconfigure(0, weight=1)
        left.grid_rowconfigure(5, weight=1)

        ctk.CTkLabel(left, text="QUICK START", anchor="w",
                     font=theme.font(9, "bold"),
                     text_color=theme.FAINT).grid(row=0, column=0, sticky="w",
                                                  padx=18, pady=(14, 6))
        quick = ctk.CTkFrame(left, fg_color="transparent")
        quick.grid(row=1, column=0, sticky="ew", padx=14)
        for column in range(3):
            quick.grid_columnconfigure(column, weight=1)
        by_id = {m.id: m for m in self.modules}
        for index, module_id in enumerate(QUICK_MODULES):
            module = by_id.get(module_id)
            if not module:
                continue
            ctk.CTkButton(
                quick, text=module.title.upper(), height=34, corner_radius=theme.RADIUS,
                fg_color=theme.ELEV, hover_color=theme.ELEV_HOVER, text_color=theme.TEXT,
                font=theme.font(11), anchor="w",
                command=lambda m=module: self._select_module(m.id)
            ).grid(row=index // 3, column=index % 3, sticky="ew", padx=4, pady=4)

        ctk.CTkLabel(left, text="RECENT RUNS", anchor="w",
                     font=theme.font(9, "bold"),
                     text_color=theme.FAINT).grid(row=2, column=0, sticky="w",
                                                  padx=18, pady=(14, 4))
        recent = ctk.CTkFrame(left, fg_color="transparent")
        recent.grid(row=3, column=0, sticky="ew", padx=18)
        recent.grid_columnconfigure(1, weight=1)
        if records:
            for index, record in enumerate(records[:5]):
                ctk.CTkLabel(recent, text=record["started"].replace("T", " ")[5:16],
                             width=78, anchor="w", font=theme.mono(10),
                             text_color=theme.FAINT).grid(row=index, column=0, sticky="w",
                                                          pady=1)
                link = ctk.CTkLabel(recent, anchor="w", cursor="hand2",
                                    text=f"{record['title']}  ·  {record['target'] or '—'}"[:68],
                                    font=theme.font(11), text_color=theme.TEXT)
                link.grid(row=index, column=1, sticky="w")
                link.bind("<Button-1>",
                          lambda _e, r=record: self._open_history(int(r["id"])))
                status_color = {"ok": theme.OK, "error": theme.ERR,
                                "cancelled": theme.WARN}.get(record["status"], theme.MUTED)
                ctk.CTkLabel(recent, text=record["status"].upper(), width=60, anchor="e",
                             font=theme.font(9),
                             text_color=status_color).grid(row=index, column=2, sticky="e")
        else:
            ctk.CTkLabel(recent, text="Nothing yet — run your first scan.",
                         anchor="w", font=theme.font(11),
                         text_color=theme.FAINT).grid(row=0, column=0, columnspan=3,
                                                      sticky="w")

        ctk.CTkLabel(left, text="ALL MODULES", anchor="w",
                     font=theme.font(9, "bold"),
                     text_color=theme.FAINT).grid(row=4, column=0, sticky="w",
                                                  padx=18, pady=(16, 4))
        browser = ctk.CTkScrollableFrame(left, fg_color="transparent", corner_radius=0,
                                         scrollbar_button_color=theme.ELEV,
                                         scrollbar_button_hover_color=theme.BORDER)
        browser.grid(row=5, column=0, sticky="nsew", padx=14, pady=(0, 4))
        for column in range(2):
            browser.grid_columnconfigure(column, weight=1)
        for index, module in enumerate(self.modules):
            ctk.CTkButton(
                browser, text=module.title.upper(), anchor="w", height=26, corner_radius=theme.RADIUS,
                fg_color="transparent", hover_color=theme.ELEV, text_color=theme.MUTED,
                font=theme.font(10),
                command=lambda m=module: self._select_module(m.id)
            ).grid(row=index // 2, column=index % 2, sticky="ew", padx=2, pady=1)
        ctk.CTkButton(left, text="OPEN FULL HISTORY", height=30, corner_radius=theme.RADIUS,
                      fg_color="transparent", border_width=1, border_color=theme.BORDER,
                      text_color=theme.MUTED, hover_color=theme.ELEV,
                      command=self._show_history).grid(row=6, column=0, sticky="ew",
                                                       padx=18, pady=(4, 16))

        right = self._card(lower)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        ctk.CTkLabel(right, text="ENVIRONMENT", anchor="w",
                     font=theme.font(9, "bold"),
                     text_color=theme.FAINT).pack(fill="x", padx=18, pady=(14, 8))
        for label, value, good in (
            ("Python", sys.version.split()[0], True),
            ("Platform", f"{platform.system()} {platform.release()}", True),
            ("ExifTool", "found" if shutil.which("exiftool") else "not installed",
             bool(shutil.which("exiftool"))),
            ("Tor SOCKS", "found" if shutil.which("tor") else "not installed",
             bool(shutil.which("tor"))),
        ):
            row = ctk.CTkFrame(right, fg_color="transparent", height=20)
            row.pack(fill="x", padx=18)
            ctk.CTkLabel(row, text=label, width=86, height=20, anchor="w",
                         font=theme.font(10),
                         text_color=theme.MUTED).pack(side="left")
            ctk.CTkLabel(row, text=value[:32], height=20, anchor="w",
                         font=theme.mono(10),
                         text_color=theme.TEXT if good else theme.WARN).pack(side="left")

        ctk.CTkLabel(right, text="KEYS", anchor="w",
                     font=theme.font(9, "bold"),
                     text_color=theme.FAINT).pack(fill="x", padx=18, pady=(16, 6))
        keys = ctk.CTkFrame(right, fg_color="transparent")
        keys.pack(fill="x", padx=14)
        keys.grid_columnconfigure(0, weight=1)
        keys.grid_columnconfigure(1, weight=1)
        for index, (name, label, _hint) in enumerate(KEY_LABELS):
            cell = ctk.CTkFrame(keys, fg_color="transparent", height=18)
            cell.grid(row=index // 2, column=index % 2, sticky="w", padx=4)
            ok = bool(CONFIG.key(name))
            ctk.CTkLabel(cell, text="●", width=12, height=18, anchor="w",
                         font=theme.font(9),
                         text_color=theme.OK if ok else theme.FAINT).pack(side="left")
            ctk.CTkLabel(cell, text=label, height=18, anchor="w",
                         font=theme.font(9),
                         text_color=theme.TEXT if ok else theme.MUTED).pack(side="left")

        ctk.CTkLabel(right, text="COVERAGE", anchor="w",
                     font=theme.font(9, "bold"),
                     text_color=theme.FAINT).pack(fill="x", padx=18, pady=(18, 6))
        largest = max(len(items) for items in self.groups.values()) or 1
        for category, items in self.groups.items():
            row = ctk.CTkFrame(right, fg_color="transparent", height=20)
            row.pack(fill="x", padx=18, pady=1)
            ctk.CTkLabel(row, text=category, width=96, height=20, anchor="w",
                         font=theme.font(9),
                         text_color=theme.MUTED).pack(side="left")
            bar = ctk.CTkProgressBar(row, width=96, height=4, corner_radius=0,
                                     progress_color=CATEGORY_COLORS.get(category, theme.ACCENT),
                                     fg_color=theme.ELEV)
            bar.set(len(items) / largest)
            bar.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(row, text=str(len(items)), height=20, anchor="w",
                         font=theme.mono(9),
                         text_color=theme.TEXT).pack(side="left")
        keyed = sum(1 for m in self.modules if m.keys)
        ctk.CTkLabel(right, text=f"{keyed} modules accept an API key · {len(self.modules)} total",
                     anchor="w", font=theme.font(9), text_color=theme.FAINT
                     ).pack(fill="x", padx=18, pady=(8, 0))

        ctk.CTkLabel(right, text=f"{CONFIG_PATH}\nhistory.db · kev.json · rdap_dns.json",
                     anchor="w", justify="left", wraplength=260,
                     font=theme.mono(9), text_color=theme.MUTED
                     ).pack(side="bottom", fill="x", padx=18, pady=(0, 14))
        ctk.CTkLabel(right, text="LOCAL PATHS", anchor="w",
                     font=theme.font(9, "bold"),
                     text_color=theme.FAINT).pack(side="bottom", fill="x", padx=18,
                                                  pady=(0, 2))
        ctk.CTkButton(right, text="MANAGE KEYS", height=30, corner_radius=theme.RADIUS,
                      fg_color="transparent", border_width=1, border_color=theme.BORDER,
                      text_color=theme.MUTED, hover_color=theme.ELEV,
                      command=self._show_settings).pack(side="bottom", fill="x", padx=18,
                                                        pady=(10, 8))

    # ------------------------------------------------------------------ module view
    def _select_module(self, module_id: str) -> None:
        if self.runner.running:
            self._toast("Stop the running job first", "warn")
            return
        module = next((m for m in self.modules if m.id == module_id), None)
        if not module:
            return
        self.current = module
        self.view = "module"
        self._clear_body()
        self._grid_rows({0: 0, 1: 0, 2: 1})
        self._highlight_nav()

        ctk.CTkLabel(self.body, text="").grid(row=0, column=0)
        header = self._page_header(module.title, module.summary, module.category)
        if module.keys:
            configured = [k for k in module.keys if CONFIG.key(k)]
            missing = [k for k in module.keys if not CONFIG.key(k)]
            text = "Keys: " + (", ".join(configured) if configured else "none configured")
            if missing:
                text += f"   ·   not set: {', '.join(missing)}"
            ctk.CTkLabel(header, text=text, anchor="w",
                         font=theme.font(9), text_color=theme.FAINT
                         ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(3, 0))

        card = self._card(self.body)
        card.grid(row=1, column=0, sticky="ew", padx=30)
        card.grid_columnconfigure(0, weight=1)
        self.form = ctk.CTkFrame(card, fg_color="transparent")
        self.form.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 8))
        self._build_form(module)
        if not module.fields:
            ctk.CTkLabel(self.form, text="This module has no inputs — press Run scan.",
                         anchor="w", font=theme.font(10),
                         text_color=theme.FAINT).grid(row=0, column=0, sticky="w")

        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.grid(row=1, column=0, sticky="ew", padx=20, pady=(4, 16))
        self.run_button = ctk.CTkButton(
            actions, text="RUN SCAN", width=132, height=34, corner_radius=theme.RADIUS,
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            text_color="#0f1318", font=theme.font(12, "bold"),
            command=self._run)
        self.run_button.pack(side="left")
        self.stop_button = ctk.CTkButton(
            actions, text="STOP", width=76, height=34, corner_radius=theme.RADIUS,
            fg_color="transparent", border_width=1, border_color=theme.BORDER,
            text_color=theme.MUTED, hover_color=theme.ELEV, state="disabled",
            command=self._stop)
        self.stop_button.pack(side="left", padx=(8, 0))
        ctk.CTkLabel(actions, text="Ctrl+Enter runs  ·  Ctrl+S exports",
                     font=theme.font(9), text_color=theme.FAINT
                     ).pack(side="right")

        output_card = self._card(self.body)
        output_card.grid(row=2, column=0, sticky="nsew", padx=30, pady=(10, 18))
        output_card.grid_rowconfigure(1, weight=1)
        output_card.grid_columnconfigure(0, weight=1)
        self.body.grid_rowconfigure(2, weight=1)
        self._build_output(output_card)
        self._show_hint(module)

    def _show_hint(self, module: Module) -> None:
        self._emit_line("muted", f"{module.summary}")
        self._emit_line("muted",
                        "Results stream here. Click any underlined link to open it.")
        self._flush_pending()

    def _build_output(self, card) -> None:
        bar = ctk.CTkFrame(card, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 6))
        bar.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(bar, text="OUTPUT", font=theme.font(9, "bold"),
                     text_color=theme.FAINT).grid(row=0, column=0, sticky="w")
        self.output_status = ctk.CTkLabel(bar, text="idle", anchor="w",
                                          font=theme.font(9),
                                          text_color=theme.FAINT)
        self.output_status.grid(row=0, column=1, sticky="w", padx=(10, 0))

        buttons = ctk.CTkFrame(bar, fg_color="transparent")
        buttons.grid(row=0, column=2, sticky="e")
        for label, command in (("COPY", self._copy_output), ("EXPORT", self._export),
                               ("CLEAR", self._clear_output)):
            ctk.CTkButton(buttons, text=label, width=64, height=26, corner_radius=theme.RADIUS,
                          fg_color="transparent", border_width=1, border_color=theme.BORDER,
                          text_color=theme.MUTED, hover_color=theme.ELEV,
                          font=theme.font(10), command=command
                          ).pack(side="left", padx=(6, 0))

        self.output = ctk.CTkTextbox(
            card, fg_color=theme.OUTPUT_BG, text_color=theme.OUTPUT_TEXT,
            font=ctk.CTkFont(*theme.OUTPUT_FONT), corner_radius=theme.RADIUS, wrap="word",
            border_width=0, scrollbar_button_color=theme.ELEV,
            scrollbar_button_hover_color=theme.BORDER)
        self.output.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self._attach_tags(self.output)
        self.output.configure(state="disabled")

    def _attach_tags(self, textbox) -> None:
        raw = getattr(textbox, "_textbox", textbox)
        for name, (color, font) in theme.TAG_COLORS.items():
            config = {"foreground": color}
            if font:
                config["font"] = font
            spacing = theme.TAG_SPACING.get(name)
            if spacing:
                config["spacing1"] = spacing[0]
                config["spacing3"] = spacing[1]
            raw.tag_config(name, **config)
        raw.tag_config("link", foreground=theme.LINK, underline=True)
        raw.tag_bind("link", "<Button-1>", self._open_link)
        raw.tag_bind("link", "<Enter>", lambda _e: raw.configure(cursor="hand2"))
        raw.tag_bind("link", "<Leave>", lambda _e: raw.configure(cursor=""))
        textbox._link_map = {}

    def _open_link(self, event) -> None:
        widget = event.widget
        try:
            line = int(widget.index(f"@{event.x},{event.y}").split(".")[0])
        except Exception:
            return
        owner = self.output
        mapping = getattr(owner, "_link_map", {}) if owner is not None else {}
        url = mapping.get(line)
        if url:
            webbrowser.open(url)

    # ------------------------------------------------------------------ forms
    def _build_form(self, module: Module) -> None:
        state = self.form_state.setdefault(module.id, {})
        self.form.grid_columnconfigure(0, weight=1, uniform="form")
        self.form.grid_columnconfigure(1, weight=1, uniform="form")
        cursor = [0, 0]

        def place(span: int, builder) -> None:
            row, col = cursor
            if col + span > 2:
                cursor[0] += 1
                cursor[1] = 0
                row, col = cursor
            cell = ctk.CTkFrame(self.form, fg_color="transparent")
            cell.grid(row=row, column=col, columnspan=span, sticky="new",
                      padx=(0 if col == 0 else 12, 0), pady=(2, 10))
            cell.grid_columnconfigure(0, weight=1)
            builder(cell)
            cursor[1] += span
            if cursor[1] >= 2:
                cursor[0] += 1
                cursor[1] = 0

        def label_for(cell, field: Field, row: int) -> None:
            ctk.CTkLabel(cell, text=field.label + (" *" if field.required else ""),
                         anchor="w", font=theme.font(11),
                         text_color=theme.TEXT if field.required else theme.MUTED
                         ).grid(row=row, column=0, sticky="w", pady=(0, 3))

        def hint_for(cell, field: Field, row: int) -> None:
            if field.help:
                ctk.CTkLabel(cell, text=field.help, anchor="w", justify="left",
                             wraplength=520, font=theme.font(9),
                             text_color=theme.FAINT).grid(row=row, column=0, sticky="w",
                                                          pady=(3, 0))

        for field in module.fields:
            default = state.get(field.name, field.default)

            if field.kind == "checkbox":
                def build_checkbox(cell, f=field, d=default) -> None:
                    variable = tk.BooleanVar(value=str(d) in ("1", "True", "true"))
                    ctk.CTkCheckBox(
                        cell, text=f.label, variable=variable,
                        font=theme.font(11), text_color=theme.MUTED,
                        checkbox_width=18, checkbox_height=18, corner_radius=4,
                        border_width=2, border_color=theme.BORDER,
                        fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
                        checkmark_color="#101418",
                    ).grid(row=0, column=0, sticky="w", pady=(4, 0))
                    self.form_widgets[f.name] = FieldWidget(
                        f, lambda v=variable: bool(v.get()),
                        lambda val, v=variable: v.set(bool(val)))
                    hint_for(cell, f, 1)
                place(1, build_checkbox)
                continue

            if field.kind == "multiline":
                def build_multiline(cell, f=field, d=default) -> None:
                    label_for(cell, f, 0)
                    widget = ctk.CTkTextbox(
                        cell, height=92, corner_radius=theme.RADIUS, fg_color=theme.BG,
                        border_width=1, border_color=theme.BORDER, text_color=theme.TEXT,
                        font=theme.mono(11), wrap="word")
                    widget.grid(row=1, column=0, sticky="ew")
                    widget.insert("1.0", str(d))
                    self.form_widgets[f.name] = FieldWidget(
                        f, lambda w=widget: w.get("1.0", "end-1c"),
                        lambda val, w=widget: (w.delete("1.0", "end"),
                                              w.insert("1.0", str(val))))
                    hint_for(cell, f, 2)
                place(2, build_multiline)
                continue

            if field.kind == "choice":
                def build_choice(cell, f=field, d=default) -> None:
                    label_for(cell, f, 0)
                    variable = tk.StringVar(value=str(d) if d else
                                            (f.choices[0] if f.choices else ""))
                    ctk.CTkOptionMenu(
                        cell, values=list(f.choices), variable=variable, height=32,
                        corner_radius=theme.RADIUS, fg_color=theme.ELEV, button_color=theme.ELEV,
                        button_hover_color=theme.BORDER, text_color=theme.TEXT,
                        dropdown_fg_color=theme.PANEL, dropdown_hover_color=theme.ELEV,
                        dropdown_text_color=theme.TEXT,
                        font=theme.font(11),
                    ).grid(row=1, column=0, sticky="ew")
                    self.form_widgets[f.name] = FieldWidget(
                        f, lambda v=variable: v.get(),
                        lambda val, v=variable: v.set(str(val)))
                    hint_for(cell, f, 2)
                place(1, build_choice)
                continue

            def build_text(cell, f=field, d=default) -> None:
                label_for(cell, f, 0)
                wrapper = ctk.CTkFrame(cell, fg_color="transparent")
                wrapper.grid(row=1, column=0, sticky="ew")
                wrapper.grid_columnconfigure(0, weight=1)
                entry = ctk.CTkEntry(
                    wrapper, height=32, corner_radius=theme.RADIUS, fg_color=theme.BG,
                    border_width=1, border_color=theme.BORDER, text_color=theme.TEXT,
                    placeholder_text=f.placeholder,
                    font=theme.mono(11))
                entry.grid(row=0, column=0, sticky="ew")
                if d:
                    entry.insert(0, str(d))
                if f.kind == "file":
                    ctk.CTkButton(
                        wrapper, text="BROWSE", width=84, height=32, corner_radius=theme.RADIUS,
                        fg_color=theme.ELEV, hover_color=theme.BORDER, text_color=theme.TEXT,
                        font=theme.font(11),
                        command=lambda e=entry: self._browse(e),
                    ).grid(row=0, column=1, padx=(8, 0))
                self.form_widgets[f.name] = FieldWidget(
                    f, lambda e=entry: e.get(),
                    lambda val, e=entry: (e.delete(0, "end"), e.insert(0, str(val))))
                hint_for(cell, f, 2)
            place(1, build_text)
    def _browse(self, entry) -> None:
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def _collect(self, module: Module) -> dict:
        values = {}
        state = self.form_state.setdefault(module.id, {})
        for field in module.fields:
            widget = self.form_widgets.get(field.name)
            value = widget.read() if widget else field.default
            if field.kind == "checkbox":
                value = bool(value)
            elif field.kind == "text" and isinstance(value, str):
                value = value.strip()
            state[field.name] = value
            values[field.name] = value
        return values

    # ------------------------------------------------------------------ output
    def _set_output_status(self, text: str, color: str = theme.FAINT) -> None:
        if self.output_status is not None and self.output_status.winfo_exists():
            self.output_status.configure(text=f"[ {text.upper()} ]", text_color=color)

    def _emit_line(self, kind: str, text: str) -> None:
        """Queue a line; the widget is updated in batches to keep the UI smooth."""
        self._pending.append((kind, text))
        if self._flush_job is None:
            self._flush_job = self.after(60, self._flush_pending)

    def _flush_pending(self) -> None:
        if self._flush_job is not None:
            try:
                self.after_cancel(self._flush_job)
            except Exception:
                pass
            self._flush_job = None
        if not self._pending:
            return
        batch, self._pending = self._pending, []
        box = self.output
        if box is None:
            return
        raw = getattr(box, "_textbox", box)
        at_bottom = raw.yview()[1] >= 0.995
        line = int(box.index("end-1c").split(".")[0]) + 1
        box.configure(state="normal")
        for kind, text in batch:
            if kind == "kv":
                label, _, value = text.partition("\t")
                pad = max(2, 26 - len(label))
                box.insert("end", label + " " * pad, "kv_label")
                box.insert("end", value + "\n", "kv_value")
                line += 1
            elif kind == "link":
                label, _, url = text.partition("\t")
                box.insert("end", f"  {label}  {url}\n", "link")
                if url:
                    box._link_map[line] = url
                line += 1
            else:
                box.insert("end", (text.upper() if kind == "title" else text) + "\n", kind)
                line += 1
                if kind == "section":
                    box.insert("end", "\n", "text")
                    line += 1
        box.configure(state="disabled")
        if at_bottom:
            box.see("end")

    def _record(self, kind: str, text: str) -> None:
        self.current_lines.append((kind, text))

    def _clear_output(self) -> None:
        self.current_lines.clear()
        self._pending.clear()
        if self._flush_job is not None:
            try:
                self.after_cancel(self._flush_job)
            except Exception:
                pass
            self._flush_job = None
        if self.output is None:
            return
        self.output._link_map.clear()
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self._set_output_status("idle")

    def _copy_output(self) -> None:
        text = "\n".join(
            (t.split("\t", 1)[1] if k == "link" and "\t" in t else t)
            for k, t in self.current_lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._toast("Output copied to clipboard")

    def _export(self) -> None:
        if not self.current_lines:
            self._toast("Nothing to export yet", "warn")
            return
        default = f"nulltrace-{self.current.id if self.current else 'scan'}-" \
                  f"{datetime.now():%Y%m%d-%H%M%S}.txt"
        path = filedialog.asksaveasfilename(
            title="Export results", defaultextension=".txt",
            initialfile=default, filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        header = (f"{APP_NAME} {VERSION}\nModule: {self.current.title if self.current else '?'}\n"
                  f"Exported: {datetime.now():%Y-%m-%d %H:%M:%S}\n" + "-" * 72 + "\n")
        body = "\n".join(
            (t.split("\t", 1)[1] if k == "link" and "\t" in t else t)
            for k, t in self.current_lines)
        Path(path).write_text(header + body + "\n", encoding="utf-8")
        self._toast(f"Saved to {Path(path).name}")

    # ------------------------------------------------------------------ run control
    def _run(self) -> None:
        if not self.current or self.runner.running or self.view != "module":
            return
        values = self._collect(self.current)
        for field in self.current.fields:
            if field.required and not str(values.get(field.name) or "").strip():
                self._toast(f"'{field.label}' is required", "warn")
                messagebox.showwarning(APP_NAME, f"'{field.label}' is required.")
                return
        self._clear_output()
        stamp = f"run started {datetime.now():%Y-%m-%d %H:%M:%S}"
        self._emit_line("muted", stamp)
        self._record("muted", stamp)
        self.run_button.configure(state="disabled", text="Running ...")
        self.stop_button.configure(state="normal")
        self.started = time.time()
        self._set_output_status("starting", theme.WARN)
        self.runner.start(self.current, values)
        self._start_tick()

    def _stop(self) -> None:
        self.runner.stop()
        self._set_output_status("stopping", theme.WARN)

    def _start_tick(self) -> None:
        if self._tick_job:
            self.after_cancel(self._tick_job)

        def tick() -> None:
            if self.runner.running:
                self._set_output_status(f"running · {time.time() - self.started:0.1f}s",
                                        theme.WARN)
                # the worker disables automatic GC so Tk finalisers never run
                # off-thread; reclaim garbage here instead
                gc.collect()
                self._tick_job = self.after(1000, tick)
        self._tick_job = self.after(400, tick)

    def _poll_queue(self) -> None:
        try:
            while True:
                self._handle_event(self.runner.events.get_nowait())
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    def _handle_event(self, event: Event) -> None:
        if event.kind == "emit":
            kind = event.payload.get("kind", "text")
            text = event.payload.get("text", "")
            self._record(kind, text)
            self._emit_line(kind, text)
        elif event.kind == "status":
            self._set_output_status(event.payload.get("text", ""), theme.MUTED)
        elif event.kind == "done":
            self._flush_pending()
            self._finish(event.payload.get("status", "ok"))

    def _finish(self, status: str) -> None:
        gc.enable()
        gc.collect()
        self.run_button.configure(state="normal", text="RUN SCAN")
        self.stop_button.configure(state="disabled")
        if self._tick_job:
            self.after_cancel(self._tick_job)
            self._tick_job = None
        elapsed = time.time() - self.started if self.started else 0
        label = {"ok": "Completed", "error": "Failed", "cancelled": "Stopped"}.get(status, status)
        color = {"ok": theme.OK, "error": theme.ERR, "cancelled": theme.WARN}.get(status, theme.MUTED)
        self._set_output_status(f"{label.lower()} · {elapsed:0.1f}s · "
                                f"{len(self.current_lines)} lines", color)
        if self.current and CONFIG.get("ui", "keep_history", True):
            target = next((str(v) for v in self._collect(self.current).values()
                           if isinstance(v, str) and v), "")
            try:
                add_scan(self.current.id, self.current.title, target[:200],
                         self.runner.started_at, status, self.current_lines)
            except Exception as exc:
                print(f"history write failed: {exc}")
        if status == "error":
            self._toast("Scan failed — see the output for details", "err")
        elif status == "cancelled":
            self._toast("Scan stopped")

    # ------------------------------------------------------------------ settings
    def _show_settings(self) -> None:
        self.view = "settings"
        self.current = None
        self._clear_body()
        self._highlight_nav()
        self._grid_rows({0: 0, 1: 1})
        self._page_header("Settings", f"Stored locally at {CONFIG_PATH}. "
                                      "Keys are only sent to the provider that issued them.")

        holder = ctk.CTkFrame(self.body, fg_color="transparent")
        holder.grid(row=1, column=0, sticky="nsew", padx=30, pady=(0, 20))
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)
        self.body.grid_rowconfigure(1, weight=1)

        scroll = ctk.CTkScrollableFrame(holder, fg_color="transparent", corner_radius=0,
                                        scrollbar_button_color=theme.ELEV)
        scroll.grid(row=0, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)

        card = self._card(scroll)
        card.grid(row=0, column=0, sticky="ew")
        card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(card, text="[ API KEYS ]", anchor="w",
                     font=theme.font(9, "bold"), text_color=theme.RED
                     ).grid(row=0, column=0, columnspan=3, sticky="w", padx=20, pady=(16, 8))

        reveal = tk.BooleanVar(value=False)
        entries: dict[str, ctk.CTkEntry] = {}
        row = 1
        for name, label, hint in KEY_LABELS:
            ctk.CTkLabel(card, text=label, width=150, anchor="w",
                         font=theme.font(11), text_color=theme.TEXT
                         ).grid(row=row, column=0, sticky="w", padx=(20, 10), pady=3)
            entry = ctk.CTkEntry(card, height=30, corner_radius=theme.RADIUS, fg_color=theme.BG,
                                 border_color=theme.BORDER, text_color=theme.TEXT,
                                 show="•", font=theme.mono(10))
            entry.grid(row=row, column=1, sticky="ew", pady=3)
            entry.insert(0, CONFIG.key(name))
            entries[name] = entry
            ctk.CTkLabel(card, text=hint, anchor="w", font=theme.font(9),
                         text_color=theme.FAINT).grid(row=row, column=2, sticky="w",
                                                      padx=(12, 20))
            row += 1

        ctk.CTkLabel(card, text="[ NETWORK ]", anchor="w",
                     font=theme.font(9, "bold"), text_color=theme.RED
                     ).grid(row=row, column=0, columnspan=3, sticky="w", padx=20,
                            pady=(20, 8))
        row += 1
        network_entries: dict[str, ctk.CTkEntry] = {}
        for key, label, default in (
            ("timeout", "Request timeout (s)", str(CONFIG.timeout)),
            ("tor_proxy", "Tor SOCKS proxy", CONFIG.tor_proxy),
            ("user_agent", "User agent", CONFIG.user_agent),
        ):
            ctk.CTkLabel(card, text=label, width=150, anchor="w",
                         font=theme.font(11), text_color=theme.TEXT
                         ).grid(row=row, column=0, sticky="w", padx=(20, 10), pady=3)
            entry = ctk.CTkEntry(card, height=30, corner_radius=theme.RADIUS, fg_color=theme.BG,
                                 border_color=theme.BORDER, text_color=theme.TEXT,
                                 font=theme.mono(10))
            entry.grid(row=row, column=1, sticky="ew", pady=3)
            entry.insert(0, str(CONFIG.get("network", key, default)))
            network_entries[key] = entry
            row += 1

        footer = ctk.CTkFrame(card, fg_color="transparent")
        footer.grid(row=row, column=0, columnspan=3, sticky="ew", padx=20, pady=(18, 18))
        footer.grid_columnconfigure(1, weight=1)

        def toggle_reveal() -> None:
            show = "" if reveal.get() else "•"
            for entry in entries.values():
                entry.configure(show=show)

        def save() -> None:
            for name, entry in entries.items():
                CONFIG.set_key(name, entry.get())
            for key, entry in network_entries.items():
                CONFIG.set("network", key, entry.get().strip())
            self._toast("Settings saved")

        ctk.CTkButton(footer, text="SAVE SETTINGS", width=150, height=34, corner_radius=theme.RADIUS,
                      fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
                      text_color="#0f1318", font=theme.font(12, "bold"),
                      command=save).grid(row=0, column=0, sticky="w")
        ctk.CTkCheckBox(footer, text="SHOW KEYS", variable=reveal, command=toggle_reveal,
                        font=theme.font(11), text_color=theme.MUTED,
                        checkbox_width=18, checkbox_height=18, corner_radius=4,
                        border_width=2, border_color=theme.BORDER, fg_color=theme.ACCENT,
                        hover_color=theme.ACCENT_HOVER, checkmark_color="#0b0b0d"
                        ).grid(row=0, column=1, sticky="w", padx=(16, 0))
        ctk.CTkButton(footer, text="CONFIG FOLDER", width=150, height=34,
                      corner_radius=theme.RADIUS, fg_color="transparent", border_width=1,
                      border_color=theme.BORDER, text_color=theme.MUTED,
                      hover_color=theme.ELEV,
                      command=lambda: webbrowser.open(str(CONFIG_PATH.parent))
                      ).grid(row=0, column=2, sticky="e")

    # ------------------------------------------------------------------ history
    def _show_history(self, needle: str = "") -> None:
        self.view = "history"
        self.current = None
        self._clear_body()
        self._highlight_nav()
        self._grid_rows({0: 0, 1: 0, 2: 1})
        header = self._page_header("History", "Completed runs are stored locally in sqlite.")

        bar = ctk.CTkFrame(self.body, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", padx=30, pady=(0, 8))
        bar.grid_columnconfigure(0, weight=1)
        entry = ctk.CTkEntry(bar, placeholder_text="Filter by module or target", height=32,
                             corner_radius=theme.RADIUS, fg_color=theme.BG, border_color=theme.BORDER,
                             text_color=theme.TEXT, font=theme.font(11))
        entry.grid(row=0, column=0, sticky="ew")
        if needle:
            entry.insert(0, needle)
        ctk.CTkButton(bar, text="CLEAR ALL", width=96, height=32, corner_radius=theme.RADIUS,
                      fg_color="transparent", border_width=1, border_color=theme.BORDER,
                      text_color=theme.ERR, hover_color=theme.ELEV,
                      command=self._clear_history).grid(row=0, column=1, padx=(8, 0))

        holder = ctk.CTkFrame(self.body, fg_color="transparent")
        holder.grid(row=2, column=0, sticky="nsew", padx=30, pady=(0, 20))
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)
        self.body.grid_rowconfigure(2, weight=1)

        scroll = ctk.CTkScrollableFrame(holder, fg_color="transparent", corner_radius=0,
                                        scrollbar_button_color=theme.ELEV)
        scroll.grid(row=0, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)

        def render(filter_text: str = "") -> None:
            for child in scroll.winfo_children():
                child.destroy()
            records = list_scans(limit=500)
            filter_text = filter_text.lower()
            matches = [r for r in records
                       if not filter_text or filter_text in r["title"].lower()
                       or filter_text in (r["target"] or "").lower()
                       or filter_text in r["module"].lower()]
            if not matches:
                ctk.CTkLabel(scroll, text="No runs match.", anchor="w",
                             font=theme.font(11), text_color=theme.FAINT
                             ).grid(row=0, column=0, sticky="w", padx=6, pady=8)
                return
            for index, record in enumerate(matches):
                row_card = ctk.CTkFrame(scroll, fg_color=theme.PANEL, corner_radius=theme.RADIUS,
                                        border_width=1, border_color=theme.BORDER_SOFT)
                row_card.grid(row=index, column=0, sticky="ew", pady=2)
                row_card.grid_columnconfigure(1, weight=1)
                ctk.CTkLabel(row_card, text=record["started"].replace("T", " ")[5:16],
                             width=84, anchor="w", font=theme.mono(10),
                             text_color=theme.FAINT).grid(row=0, column=0, padx=(12, 6), pady=8)
                ctk.CTkLabel(row_card, text=f"{record['title']}  ·  {record['target'] or '—'}",
                             anchor="w", font=theme.font(11),
                             text_color=theme.TEXT).grid(row=0, column=1, sticky="w")
                color = {"ok": theme.OK, "error": theme.ERR,
                         "cancelled": theme.WARN}.get(record["status"], theme.MUTED)
                ctk.CTkLabel(row_card, text=record["status"].upper(), width=66,
                             font=theme.font(9), text_color=color
                             ).grid(row=0, column=2)
                ctk.CTkButton(row_card, text="OPEN", width=58, height=26, corner_radius=theme.RADIUS,
                              fg_color=theme.ELEV, hover_color=theme.BORDER,
                              text_color=theme.TEXT, font=theme.font(10),
                              command=lambda r=record: self._open_history(int(r["id"]))
                              ).grid(row=0, column=3, padx=(0, 4))
                ctk.CTkButton(row_card, text="DELETE", width=62, height=26, corner_radius=theme.RADIUS,
                              fg_color="transparent", hover_color=theme.ELEV,
                              text_color=theme.ERR, font=theme.font(10),
                              command=lambda r=record: self._delete_history(int(r["id"]))
                              ).grid(row=0, column=4, padx=(0, 10))

        entry.bind("<KeyRelease>", lambda _e: render(entry.get()))
        render(needle)
        self._toast(f"{len(list_scans(limit=500))} runs in history")

    def _open_history(self, scan_id: int) -> None:
        record = load_scan(scan_id)
        if not record:
            return
        self.view = "history"
        self.current = None
        self._clear_body()
        self._grid_rows({0: 0, 1: 1})
        header = self._page_header(record["title"],
                                   f"{record['target'] or '—'}  ·  "
                                   f"{record['started'].replace('T', ' ')}  ·  {record['status']}")
        ctk.CTkButton(header, text="← BACK", width=140, height=28,
                      corner_radius=theme.RADIUS, fg_color="transparent", text_color=theme.MUTED,
                      hover_color=theme.ELEV, command=self._show_history,
                      anchor="w").grid(row=3, column=0, sticky="w", pady=(8, 0))

        card = self._card(self.body)
        card.grid(row=1, column=0, sticky="nsew", padx=30, pady=(8, 20))
        card.grid_rowconfigure(1, weight=1)
        card.grid_columnconfigure(0, weight=1)
        self.body.grid_rowconfigure(1, weight=1)
        self._build_output(card)
        self._set_output_status(f"{record['status']} · {len(record['lines'])} lines")
        for kind, text in record["lines"]:
            self._record(kind, text)
            self._emit_line(kind, text)
        self._flush_pending()

    def _delete_history(self, scan_id: int) -> None:
        delete_scan(scan_id)
        self._show_history()

    def _clear_history(self) -> None:
        if not messagebox.askyesno(APP_NAME, "Delete every stored scan?"):
            return
        clear_history()
        self._show_history()

    # ------------------------------------------------------------------ lifecycle
    def report_callback_exception(self, exc_type, exc_value, exc_tb) -> None:
        """Keep the app alive when a widget callback raises, and log the reason."""
        import traceback

        from ..crashlog import write

        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        write(f"UI callback error:\n{text}")
        try:
            self._toast("Something went wrong — details saved to crash.log", "err")
        except Exception:
            pass
        try:
            sys.stderr.write(text)
        except Exception:
            pass

    def _on_close(self) -> None:
        if self.runner.running:
            if not messagebox.askyesno(APP_NAME, "A scan is running. Quit anyway?"):
                return
            self.runner.stop()
        self.destroy()


def main() -> None:
    NullTraceApp().mainloop()
