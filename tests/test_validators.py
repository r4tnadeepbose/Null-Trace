"""Value validators used across modules."""

from __future__ import annotations

import unittest

from nulltrace.modules.dorks import _clean_domain
from nulltrace.modules.email_headers import _domain
from nulltrace.modules.metadata import _dms_to_decimal
from nulltrace.modules.vin import _check_digit
from nulltrace.net import EMAIL_RE, DOMAIN_RE, is_ip, normalize_target


class ValidatorTests(unittest.TestCase):
    def test_is_ip(self) -> None:
        self.assertTrue(is_ip("1.1.1.1"))
        self.assertTrue(is_ip("2001:4860:4860::8888"))
        self.assertFalse(is_ip("example.com"))
        self.assertFalse(is_ip("999.1.1.1"))

    def test_email_regex(self) -> None:
        for good in ("a@b.co", "first.last+tag@sub.example.org"):
            self.assertRegex(good, EMAIL_RE)
        for bad in ("a@b", "a b@c.com", "@example.com", "a@.com"):
            self.assertIsNone(EMAIL_RE.match(bad), bad)

    def test_domain_regex(self) -> None:
        self.assertRegex("example.com", DOMAIN_RE)
        self.assertRegex("a.b.c.example.co.uk", DOMAIN_RE)
        self.assertIsNone(DOMAIN_RE.match("-bad.com"))
        self.assertIsNone(DOMAIN_RE.match("nodot"))

    def test_normalize_target(self) -> None:
        self.assertEqual(normalize_target("https://example.com/path?q=1"), "example.com")
        self.assertEqual(normalize_target("example.com/x"), "example.com")
        self.assertEqual(normalize_target("  example.com  "), "example.com")

    def test_vin_check_digit(self) -> None:
        _, valid = _check_digit("1HGCM82633A004352")
        self.assertTrue(valid)
        _, invalid = _check_digit("1HGCM82633A004353")
        self.assertFalse(invalid)

    def test_dms_to_decimal(self) -> None:
        self.assertAlmostEqual(_dms_to_decimal(((37, 1), (46, 1), (3000, 100))), 37.775)
        self.assertAlmostEqual(_dms_to_decimal([10, 30, 0]), 10.5)
        self.assertIsNone(_dms_to_decimal("nonsense"))

    def test_header_domain(self) -> None:
        self.assertEqual(_domain("Bank <alerts@example.com>"), "example.com")
        self.assertEqual(_domain("no-at-sign"), "")

    def test_clean_domain(self) -> None:
        self.assertEqual(_clean_domain("https://Example.COM/x"), "example.com")
        self.assertEqual(_clean_domain("www.example.com"), "www.example.com")
        self.assertEqual(_clean_domain(""), "example.com")


if __name__ == "__main__":
    unittest.main()
