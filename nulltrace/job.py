"""Job model: module contracts, execution context and background runner."""

from __future__ import annotations

import gc
import queue
import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

from .config import CONFIG
from .net import Cancelled


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    kind: str = "text"  # text | multiline | choice | checkbox
    placeholder: str = ""
    default: str = ""
    choices: tuple[str, ...] = ()
    required: bool = False
    help: str = ""


@dataclass(frozen=True)
class Module:
    id: str
    title: str
    category: str
    summary: str
    fields: tuple[Field, ...]
    run: Callable[["Context"], None]
    keys: tuple[str, ...] = ()
    order: int = 100


@dataclass
class Event:
    kind: str  # emit | done | error | status | started
    payload: dict[str, Any] = field(default_factory=dict)


class Context:
    """Everything a module needs while running."""

    def __init__(self, inputs: dict[str, Any], emitter: Callable[[Event], None],
                 cancel: threading.Event) -> None:
        self.inputs = inputs
        self._emit = emitter
        self.cancel_event = cancel
        self.warnings = 0

    # ---- input access -------------------------------------------------
    def value(self, name: str) -> str:
        return str(self.inputs.get(name, "") or "").strip()

    def checked(self, name: str) -> bool:
        return bool(self.inputs.get(name))

    # ---- output primitives -------------------------------------------
    def _out(self, kind: str, text: str) -> None:
        self._emit(Event("emit", {"kind": kind, "text": text}))

    def title(self, text: str) -> None:
        self._out("title", text)

    def section(self, text: str) -> None:
        self._out("section", text)

    def kv(self, label: str, value: Any) -> None:
        self._out("kv", f"{label}\t{'' if value is None else value}")

    def table(self, headers: Iterable[str], rows: Iterable[Iterable[Any]]) -> None:
        header = list(headers)
        body = [["" if cell is None else str(cell) for cell in row] for row in rows]
        if not body:
            self._out("muted", "  (no rows)")
            return
        widths = [len(str(h)) for h in header]
        for row in body:
            for index, cell in enumerate(row[: len(widths)]):
                widths[index] = max(widths[index], len(cell))
        self._out("table_head",
                  "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(header)).rstrip())
        self._out("table_rule", "  ".join("─" * widths[i] for i in range(len(header))))
        for row in body:
            cells = [row[i].ljust(widths[i]) if i < len(row) else "" for i in range(len(widths))]
            self._out("table", "  ".join(cells).rstrip())

    def text(self, text: str) -> None:
        for line in str(text).splitlines() or [""]:
            self._out("text", line)

    def link(self, label: str, url: str) -> None:
        self._out("link", f"{label}\t{url}")

    def ok(self, text: str) -> None:
        self._out("ok", text)

    def warn(self, text: str) -> None:
        self.warnings += 1
        self._out("warn", text)

    def error(self, text: str) -> None:
        self._out("err", text)

    def muted(self, text: str) -> None:
        self._out("muted", text)

    def note(self, text: str) -> None:
        for line in str(text).splitlines():
            self._out("note", line)

    # ---- helpers ------------------------------------------------------
    def key(self, name: str) -> str:
        return CONFIG.key(name)

    def require_key(self, name: str, human: str) -> str | None:
        value = CONFIG.key(name)
        if not value:
            self.warn(f"No {human} API key configured — this step is skipped.")
            self.muted("Add it in Settings to unlock this part of the module.")
            return None
        return value

    def status(self, text: str) -> None:
        self._emit(Event("status", {"text": text}))

    def check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise Cancelled()

    def sleep(self, seconds: float) -> None:
        if self.cancel_event.wait(seconds):
            raise Cancelled()


class JobRunner:
    def __init__(self) -> None:
        self.events: queue.Queue[Event] = queue.Queue()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None
        self.module: Module | None = None
        self.target = ""
        self.started_at = datetime.now()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self, module: Module, inputs: dict[str, Any]) -> None:
        if self.running:
            raise RuntimeError("A job is already running")
        self._cancel.clear()
        self.module = module
        self.target = next((str(v) for v in inputs.values() if v), "")
        self.started_at = datetime.now()
        self.events.put(Event("started", {"module": module.id}))
        context = Context(inputs, self.events.put, self._cancel)

        def _work() -> None:
            # Tk objects must only be finalised on the UI thread. A garbage
            # collection here can run tkinter.font.Font.__del__, which issues a
            # Tcl call and deadlocks against the main loop. Automatic GC stays
            # off while the job runs; the UI thread collects instead.
            gc_was_enabled = gc.isenabled()
            if gc_was_enabled:
                gc.disable()
            try:
                module.run(context)
            except Cancelled:
                self.events.put(Event("emit", {"kind": "warn", "text": "Stopped by user."}))
                self.events.put(Event("done", {"status": "cancelled"}))
                return
            except BaseException as exc:  # never let the worker die silently
                self.events.put(Event("emit", {
                    "kind": "err",
                    "text": f"{type(exc).__name__}: {exc}",
                }))
                tb = traceback.format_exc(limit=6)
                for line in tb.splitlines():
                    self.events.put(Event("emit", {"kind": "muted", "text": line}))
                try:
                    from .crashlog import write
                    write(f"Module {module.id} crashed:\n{tb}")
                except Exception:
                    pass
                self.events.put(Event("done", {"status": "error"}))
                return
            self.events.put(Event("done", {"status": "ok", "warnings": context.warnings}))

        self._thread = threading.Thread(target=_work, name=f"job-{module.id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._cancel.set()
