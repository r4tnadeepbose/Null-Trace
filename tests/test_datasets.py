"""Reference-data loaders: comment stripping, fallbacks and JSON parsing."""

from __future__ import annotations

import unittest

from nulltrace.datasets import load_json, load_lines, reloadable


class DatasetTests(unittest.TestCase):
    def test_lines_skip_comments_and_blanks(self) -> None:
        values = load_lines("disposable_domains.txt", [])
        self.assertIn("mailinator.com", values)
        self.assertFalse(any(line.startswith("#") for line in values))
        self.assertTrue(all(line.strip() for line in values))

    def test_missing_file_uses_fallback(self) -> None:
        self.assertEqual(load_lines("does-not-exist.txt", ["a", "b"]), ["a", "b"])

    def test_json_catalog(self) -> None:
        catalog = load_json("dorks.json", {})
        self.assertIn("Config & secrets", catalog)
        for category, dorks in catalog.items():
            self.assertTrue(dorks, category)
            self.assertTrue(all(isinstance(dork, str) and dork.strip() for dork in dorks))
        scoped = [d for dorks in catalog.values() for d in dorks if d.startswith("site:")]
        self.assertTrue(any("{d}" in dork for dork in scoped))

    def test_json_fallback(self) -> None:
        self.assertEqual(load_json("missing.json", {"k": 1}), {"k": 1})

    def test_reloadable_lists_files(self) -> None:
        self.assertIn("dorks.json", reloadable())


if __name__ == "__main__":
    unittest.main()
