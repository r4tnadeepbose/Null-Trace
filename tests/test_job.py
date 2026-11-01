"""Job context output formatting and cancellation."""

from __future__ import annotations

import threading
import unittest

from nulltrace.job import Context, Event
from nulltrace.net import Cancelled


class JobContextTests(unittest.TestCase):
    def make(self) -> tuple[Context, list[Event]]:
        events: list[Event] = []
        context = Context({"target": " 1.1.1.1 "}, events.append, threading.Event())
        return context, events

    def test_value_is_stripped(self) -> None:
        context, _ = self.make()
        self.assertEqual(context.value("target"), "1.1.1.1")
        self.assertEqual(context.value("missing"), "")

    def test_kinds_emitted(self) -> None:
        context, events = self.make()
        context.title("x")
        context.section("s")
        context.ok("done")
        context.warn("careful")
        context.error("bad")
        self.assertEqual([event.payload["kind"] for event in events],
                         ["title", "section", "ok", "warn", "err"])

    def test_kv_uses_tab(self) -> None:
        context, events = self.make()
        context.kv("Label", "Value")
        self.assertEqual(events[0].payload["text"], "Label\tValue")

    def test_table_alignment(self) -> None:
        context, events = self.make()
        context.table(("A", "Bee"), (("1", "two"), ("three", "4")))
        lines = [event.payload["text"] for event in events]
        self.assertTrue(lines[0].startswith("A"))
        self.assertTrue(set(lines[1]) <= {"-", " "})
        column = lines[0].index("Bee")
        self.assertEqual(lines[2].index("two"), column)
        self.assertEqual(lines[3].index("4"), column)

    def test_empty_table(self) -> None:
        context, events = self.make()
        context.table(("A",), ())
        self.assertEqual(events[0].payload["kind"], "muted")

    def test_cancel_raises(self) -> None:
        events: list[Event] = []
        cancel = threading.Event()
        cancel.set()
        context = Context({}, events.append, cancel)
        with self.assertRaises(Cancelled):
            context.check_cancel()

    def test_sleep_respects_cancel(self) -> None:
        cancel = threading.Event()
        context = Context({}, lambda _e: None, cancel)
        cancel.set()
        with self.assertRaises(Cancelled):
            context.sleep(5)


if __name__ == "__main__":
    unittest.main()
