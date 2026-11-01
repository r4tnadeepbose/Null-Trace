"""Link rendering and browser selection."""

from __future__ import annotations

import unittest


class BrowserTests(unittest.TestCase):
    def test_brave_path_type(self) -> None:
        from nulltrace.browser import brave_path
        value = brave_path()
        self.assertTrue(value is None or isinstance(value, str))

    def test_open_url_rejects_empty(self) -> None:
        from nulltrace.browser import open_url
        self.assertFalse(open_url(""))

    def test_config_has_browser_key(self) -> None:
        from nulltrace.config import DEFAULTS
        self.assertIn("browser", DEFAULTS["network"])


def _display_available() -> bool:
    try:
        import tkinter as tk
        root = tk.Tk()
        root.destroy()
        return True
    except Exception:
        return False


@unittest.skipUnless(_display_available(), "no display available")
class LinkMappingTests(unittest.TestCase):
    def test_clicked_line_maps_to_its_url(self) -> None:
        from nulltrace.gui import app as appmod
        app = appmod.NullTraceApp()
        try:
            app.update()
            app._select_module("ip_info")
            app.update()
            app._clear_output()
            app._emit_line("link", "Map\thttps://example.com/map")
            app._flush_pending()
            app.update()
            raw = app.output._textbox
            ranges = raw.tag_ranges("link")
            self.assertTrue(ranges)
            line = int(str(ranges[0]).split(".")[0])
            self.assertEqual(app.output._link_map.get(line), "https://example.com/map")
            url_ranges = raw.tag_ranges("link_url")
            url_line = int(str(url_ranges[0]).split(".")[0])
            self.assertEqual(app.output._link_map.get(url_line), "https://example.com/map")
        finally:
            app._on_close()


if __name__ == "__main__":
    unittest.main()
