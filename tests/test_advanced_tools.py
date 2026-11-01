"""Offline checks for the utility and web-audit modules."""

from __future__ import annotations

import threading
import unittest

from nulltrace.job import Context, Event
from nulltrace.modules import all_modules
from nulltrace.modules import cookie_audit, hash_identify, jwt_inspector

SAMPLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0IiwibmFtZSI6IkpvaG4iLCJleHAiOjE5MDAwMDAwMDB9."
    "c2lnbmF0dXJl"
)


def run(module, values: dict) -> str:
    events: list[Event] = []
    module.run(Context(values, events.append, threading.Event()))
    return "\n".join(e.payload.get("text", "") for e in events if e.kind == "emit")


class JwtTests(unittest.TestCase):
    def test_decodes_header_and_claims(self) -> None:
        header, payload, segments, signed = jwt_inspector.inspect(SAMPLE_JWT)
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(payload["sub"], "1234")
        self.assertEqual(segments, 3)
        self.assertTrue(signed)

    def test_rejects_garbage(self) -> None:
        header, payload, _segments, _signed = jwt_inspector.inspect("not-a-token")
        self.assertIsNone(header)
        self.assertIsNone(payload)

    def test_flags_none_algorithm(self) -> None:
        token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
        text = run(jwt_inspector.MODULE, {"token": token})
        self.assertIn("alg=none", text)

    def test_bearer_prefix_is_stripped(self) -> None:
        text = run(jwt_inspector.MODULE, {"token": "Bearer " + SAMPLE_JWT})
        self.assertIn("HS256", text)


class HashTests(unittest.TestCase):
    def test_md5(self) -> None:
        self.assertEqual(hash_identify.identify("5f4dcc3b5aa765d61d8327deb882cf99"),
                         [("MD5", "128-bit hex")])

    def test_sha256(self) -> None:
        value = "a" * 64
        self.assertIn("SHA-256", [name for name, _ in hash_identify.identify(value)])

    def test_bcrypt(self) -> None:
        value = "$2b$12$" + "a" * 53
        self.assertIn("bcrypt", [name for name, _ in hash_identify.identify(value)])

    def test_unknown(self) -> None:
        self.assertEqual(hash_identify.identify("hello"), [])


class CookieTests(unittest.TestCase):
    def test_flags_detected(self) -> None:
        cookies = cookie_audit.parse_cookies([
            "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
            "tracker=1; Path=/; Max-Age=63072000",
        ])
        self.assertEqual(len(cookies), 2)
        self.assertFalse(cookie_audit._issues(cookies[0]))
        issues = cookie_audit._issues(cookies[1])
        self.assertIn("no Secure", issues)
        self.assertIn("no HttpOnly", issues)
        self.assertIn("no SameSite", issues)
        self.assertIn("lifetime over a year", issues)

    def test_samesite_none_without_secure(self) -> None:
        cookies = cookie_audit.parse_cookies(["x=1; SameSite=None"])
        self.assertIn("SameSite=None without Secure", cookie_audit._issues(cookies[0]))


class RegistryTests(unittest.TestCase):
    def test_new_web_and_utility_modules(self) -> None:
        ids = {m.id for m in all_modules()}
        for expected in ("cors_check", "cookie_audit", "subdomain_takeover", "bulk_urls",
                         "tls_versions", "jwt_inspector", "hash_identify", "my_connection"):
            self.assertIn(expected, ids)

    def test_utility_category_exists(self) -> None:
        categories = {m.category for m in all_modules()}
        self.assertIn("Utility", categories)
        self.assertGreaterEqual(len(all_modules()), 48)


if __name__ == "__main__":
    unittest.main()
