"""Local crash log.

If the application ever closes unexpectedly, the reason lands in
``%APPDATA%\\Null-Trace\\crash.log``: uncaught exceptions from the UI thread,
from worker threads and, through faulthandler, hard faults such as access
violations. The file is rotated once it grows past a megabyte.
"""

from __future__ import annotations

import faulthandler
import sys
import traceback
from datetime import datetime
from typing import IO

from .config import data_dir

MAX_BYTES = 1_000_000
_handle: IO[str] | None = None


def log_path():
    return data_dir() / "crash.log"


def write(text: str) -> None:
    path = log_path()
    try:
        if path.exists() and path.stat().st_size > MAX_BYTES:
            path.replace(path.with_suffix(".log.1"))
    except OSError:
        pass
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"\n[{datetime.now():%Y-%m-%d %H:%M:%S}]\n{text.rstrip()}\n")
    except OSError:
        pass


def enable_faulthandler() -> None:
    """Capture segfaults and fatal interpreter errors, which bypass excepthook."""
    global _handle
    try:
        _handle = log_path().open("a", encoding="utf-8")
        _handle.write(f"\n[{datetime.now():%Y-%m-%d %H:%M:%S}] session start\n")
        _handle.flush()
        faulthandler.enable(file=_handle, all_threads=True)
    except (OSError, ValueError):
        _handle = None


def install_excepthook() -> None:
    def hook(exc_type, exc, tb) -> None:
        write("".join(traceback.format_exception(exc_type, exc, tb)))
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = hook


def record(exception: BaseException) -> str:
    text = "".join(traceback.format_exception(type(exception), exception,
                                              exception.__traceback__))
    write(text)
    return text
