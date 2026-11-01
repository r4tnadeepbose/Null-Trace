"""Quick Recon type detection and the theme switch."""

from __future__ import annotations

import unittest

from nulltrace import theme
from nulltrace.modules.auto_recon import detect, _inputs_for, PLANS


class DetectTests(unittest.TestCase):
    def test_ip(self) -> None:
        self.assertEqual(detect("1.1.1.1"), ("ip", "1.1.1.1"))
        self.assertEqual(detect(" 2606:4700::1111 ")[0], "ip")

    def test_domain(self) -> None:
        self.assertEqual(detect("Example.COM"), ("domain", "example.com"))
        self.assertEqual(detect("https://example.org/path"), ("domain", "example.org"))

    def test_email(self) -> None:
        self.assertEqual(detect("Someone@Example.com"), ("email", "someone@example.com"))

    def test_phone(self) -> None:
        self.assertEqual(detect("+1 415 555 2671")[0], "phone")

    def test_vin(self) -> None:
        self.assertEqual(detect("1hgcm82633a004352"), ("vin", "1HGCM82633A004352"))

    def test_hash(self) -> None:
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(detect(sha256), ("hash", sha256))

    def test_username(self) -> None:
        self.assertEqual(detect("@r4tnadeepbose"), ("username", "r4tnadeepbose"))

    def test_every_kind_has_a_plan_and_inputs(self) -> None:
        samples = {
            "ip": "1.1.1.1", "domain": "example.com", "email": "a@b.co",
            "phone": "+14155552671", "vin": "1HGCM82633A004352",
            "hash": "d41d8cd98f00b204e9800998ecf8427e", "username": "someone",
        }
        for kind, value in samples.items():
            self.assertIn(kind, PLANS)
            inputs = _inputs_for(kind, value)
            self.assertEqual(set(inputs), set(PLANS[kind]), kind)


class ThemeTests(unittest.TestCase):
    def test_text_is_bright(self) -> None:
        self.assertEqual(theme.TEXT, "#ffffff")
        self.assertEqual(theme.OUTPUT_TEXT, "#ffffff")

    def test_single_accent(self) -> None:
        for name in ("ACCENT", "LINK", "ERR"):
            colour = getattr(theme, name)
            self.assertTrue(colour.startswith("#") and len(colour) == 7, name)

    def test_tag_colours_defined(self) -> None:
        for tag in ("title", "section", "kv_label", "kv_value", "table_head"):
            self.assertIn(tag, theme.TAG_COLORS)
        self.assertEqual(theme.TAG_COLORS["title"][0], "#ffffff")

    def test_every_category_has_a_colour(self) -> None:
        from nulltrace.modules import CATEGORY_ORDER
        for category in CATEGORY_ORDER:
            self.assertIn(category, theme.CATEGORY_COLORS)


if __name__ == "__main__":
    unittest.main()
