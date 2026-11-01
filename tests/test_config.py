"""Config storage under a temporary home directory."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="nulltrace-test-")
os.environ["NULLTRACE_HOME"] = _TMP

from nulltrace.config import Config, data_dir  # noqa: E402


class ConfigTests(unittest.TestCase):
    def test_data_dir_uses_env(self) -> None:
        self.assertEqual(data_dir(), Path(_TMP))

    def test_defaults(self) -> None:
        config = Config(Path(_TMP) / "a.json")
        self.assertEqual(config.timeout, 12.0)
        self.assertTrue(config.user_agent)
        self.assertEqual(config.key("hunter"), "")

    def test_keys_persist(self) -> None:
        path = Path(_TMP) / "b.json"
        config = Config(path)
        config.set_key("hunter", "  abc123  ")
        self.assertEqual(config.key("hunter"), "abc123")
        self.assertEqual(Config(path).key("hunter"), "abc123")

    def test_network_values(self) -> None:
        path = Path(_TMP) / "c.json"
        config = Config(path)
        config.set("network", "timeout", "30")
        self.assertEqual(Config(path).timeout, 30.0)
        config.set("network", "timeout", "not-a-number")
        self.assertEqual(Config(path).timeout, 12.0)

    def test_corrupt_file_falls_back(self) -> None:
        path = Path(_TMP) / "d.json"
        path.write_text("{not json", encoding="utf-8")
        self.assertEqual(Config(path).key("hunter"), "")


if __name__ == "__main__":
    unittest.main()
