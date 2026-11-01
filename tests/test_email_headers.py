"""End-to-end email header analysis against the shipped sample."""

from __future__ import annotations

import threading
import unittest
from pathlib import Path

from nulltrace.job import Context, Event
from nulltrace.modules import email_headers

SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "sample_email_headers.txt"


class EmailHeaderTests(unittest.TestCase):
    def analyse(self, raw: str) -> list[Event]:
        events: list[Event] = []
        context = Context({"raw": raw, "geo": False}, events.append, threading.Event())
        email_headers.MODULE.run(context)
        return events

    def test_sample_header_is_flagged(self) -> None:
        events = self.analyse(SAMPLE.read_text(encoding="utf-8"))
        text = "\n".join(event.payload.get("text", "") for event in events
                         if event.kind == "emit")
        self.assertIn("SPF: fail", text.replace("\t", " "))
        self.assertIn("high risk", text.lower())
        self.assertIn("Reply-To", text)

    def test_plain_headers_are_consistent(self) -> None:
        raw = (
            "From: Someone <someone@example.com>\n"
            "To: you@example.org\n"
            "Subject: Hello\n"
            "Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass\n"
            "Received: from mail.example.com (mail.example.com [203.0.113.5])\n"
            "\tby mx.example.org; Sun, 01 Nov 2026 10:00:00 +0000\n"
        )
        events = self.analyse(raw)
        text = "\n".join(event.payload.get("text", "") for event in events
                         if event.kind == "emit").lower()
        self.assertIn("consistent", text)

    def test_empty_input_errors(self) -> None:
        events = self.analyse("   ")
        kinds = [event.payload.get("kind") for event in events if event.kind == "emit"]
        self.assertIn("err", kinds)


if __name__ == "__main__":
    unittest.main()
