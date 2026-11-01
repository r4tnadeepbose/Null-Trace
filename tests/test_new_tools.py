"""Offline checks for the newer modules."""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from nulltrace.job import Context, Event
from nulltrace.modules import all_modules, find
from nulltrace.modules import bgp_asn, file_triage, tls_inspector


def run_module(module, values: dict) -> list[Event]:
    events: list[Event] = []
    context = Context(values, events.append, threading.Event())
    module.run(context)
    return events


def text_of(events: list[Event]) -> str:
    return "\n".join(e.payload.get("text", "") for e in events if e.kind == "emit")


class RegistryGrowthTests(unittest.TestCase):
    def test_new_modules_registered(self) -> None:
        ids = {m.id for m in all_modules()}
        for expected in ("tls_inspector", "wayback", "bgp_asn", "reverse_ip",
                         "site_files", "dnsbl", "file_triage", "dns_propagation"):
            self.assertIn(expected, ids)
            self.assertIsNotNone(find(expected))

    def test_module_count(self) -> None:
        self.assertGreaterEqual(len(all_modules()), 40)


class TlsParsingTests(unittest.TestCase):
    def test_nested_subject(self) -> None:
        nested = ((("commonName", "example.com"),), (("organizationName", "Example Inc"),))
        fields = tls_inspector._fields(nested)
        self.assertEqual(fields["commonName"], "example.com")
        self.assertEqual(tls_inspector._name(nested), "Example Inc")

    def test_flat_subject(self) -> None:
        flat = (("commonName", "a.test"),)
        self.assertEqual(tls_inspector._fields(flat)["commonName"], "a.test")

    def test_empty(self) -> None:
        self.assertEqual(tls_inspector._name(None), "—")


class AsnTests(unittest.TestCase):
    def test_parse(self) -> None:
        self.assertEqual(bgp_asn._asn("AS13335"), 13335)
        self.assertEqual(bgp_asn._asn("as13335"), 13335)
        self.assertEqual(bgp_asn._asn("13335"), 13335)

    def test_invalid(self) -> None:
        self.assertIsNone(bgp_asn._asn("cloudflare"))


class FileTriageTests(unittest.TestCase):
    def test_entropy_and_indicators(self) -> None:
        payload = (b"MZ" + b"http://bad.example/dl " + b"user@example.org " +
                   b"10.9.8.7 " + b"powershell -enc " + b"A" * 200)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as handle:
            handle.write(payload)
            path = handle.name
        try:
            events = run_module(file_triage.MODULE, {"path": path})
            text = text_of(events)
            self.assertIn("PE executable", text)
            self.assertIn("http://bad.example/dl", text)
            self.assertIn("user@example.org", text)
            self.assertIn("powershell", text.lower())
            self.assertIn("SHA256", text)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_missing_file(self) -> None:
        events = run_module(file_triage.MODULE, {"path": "C:/nope/none.bin"})
        kinds = [e.payload.get("kind") for e in events if e.kind == "emit"]
        self.assertIn("err", kinds)

    def test_entropy_bounds(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b"\x00" * 4096)
            path = handle.name
        try:
            self.assertLess(file_triage._entropy(Path(path)), 0.5)
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
