"""Build every view once. Catches unsupported widget arguments early."""

from __future__ import annotations

import unittest


def _display_available() -> bool:
    try:
        import tkinter as tk
        root = tk.Tk()
        root.destroy()
        return True
    except Exception:
        return False


@unittest.skipUnless(_display_available(), "no display available")
class GuiSmokeTests(unittest.TestCase):
    def test_every_module_view_builds_and_closes(self) -> None:
        from nulltrace.gui.app import NullTraceApp
        from nulltrace.modules import all_modules

        app = NullTraceApp()
        try:
            app.update()
            for module in all_modules():
                app._select_module(module.id)
                app.update()
            for view in (app._show_settings, app._show_help, app._show_history,
                         app._show_dashboard):
                view()
                app.update()
            app._select_module("dns_lookup")
            app.update()
        finally:
            app._on_close()

    def test_nav_survives_filtering_and_theme(self) -> None:
        from nulltrace.gui.app import NullTraceApp

        app = NullTraceApp()
        try:
            app.update()
            for needle in ("dns", "ip", "zzz", ""):
                app._render_nav(needle)
                app.update()
            app._change_font(0.1)
            app.update()
            app._change_font(-0.1)
            app.update()
        finally:
            app._on_close()


if __name__ == "__main__":
    unittest.main()
