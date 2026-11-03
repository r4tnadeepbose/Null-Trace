#!/usr/bin/env python3
"""Null-Trace entry point.

    python scan.py                     launch the desktop application
    python scan.py --list              list every module
    python scan.py --run ip_info -a target=1.1.1.1    run one module headlessly
    python scan.py --probe-cli user123 --csv          vendored probe engine CLI

The username-probe engine keeps its own flag set: everything after
--probe-cli is handed to the vendored CLI unchanged.
"""

from __future__ import annotations

import argparse
import sys
import threading

REQUIRED = [
    ("requests", "requests"),
    ("customtkinter", "customtkinter"),
    ("dns", "dnspython"),
    ("PIL", "Pillow"),
    ("phonenumbers", "phonenumbers"),
    ("piexif", "piexif"),
    ("qrcode", "qrcode"),
    ("bs4", "beautifulsoup4"),
    ("speedtest", "speedtest-cli"),
    ("requests_futures", "requests-futures"),
]


def _missing_packages() -> list[str]:
    import importlib.util
    return [package for module, package in REQUIRED
            if importlib.util.find_spec(module) is None]


def _bootstrap() -> None:
    missing = _missing_packages()
    if not missing:
        return
    print("Null-Trace is missing required Python packages:", file=sys.stderr)
    for package in missing:
        print(f"  - {package}", file=sys.stderr)
    print("\nInstall them with:\n  python -m pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


def _list_modules() -> None:
    from nulltrace.modules import all_modules
    print(f"{'ID':<16} {'CATEGORY':<14} TITLE")
    print("-" * 64)
    for module in all_modules():
        print(f"{module.id:<16} {module.category:<14} {module.title}")
        print(f"{'':<16} {module.summary}")


def _run_headless(module_id: str, assignments: list[str]) -> int:
    from nulltrace.job import Context
    from nulltrace.modules import find
    from nulltrace.net import Cancelled

    module = find(module_id)
    if not module:
        print(f"Unknown module: {module_id}", file=sys.stderr)
        return 2

    values = {field.name: field.default for field in module.fields}
    for field in module.fields:
        if field.kind == "checkbox":
            values[field.name] = str(field.default) in ("1", "True", "true")
    for item in assignments:
        if "=" not in item:
            print(f"Ignoring malformed -a value: {item}", file=sys.stderr)
            continue
        key, _, value = item.partition("=")
        key, value = key.strip(), value.strip()
        field = next((f for f in module.fields if f.name == key), None)
        if field and field.kind == "checkbox":
            values[key] = value.lower() in ("1", "true", "yes", "on")
        else:
            values[key] = value

    def emit(event) -> None:
        if event.kind == "emit":
            kind = event.payload.get("kind", "text")
            text = event.payload.get("text", "")
            if kind == "kv":
                label, _, val = text.partition("\t")
                text = f"{label}: {val}"
            elif kind == "link":
                label, _, url = text.partition("\t")
                text = f"{label} -> {url}"
            print(text, flush=True)
        elif event.kind == "status":
            print(f".. {event.payload.get('text', '')}", flush=True)

    print(f"== {module.title} ==")
    context = Context(values, emit, threading.Event())
    try:
        module.run(context)
    except Cancelled:
        print("cancelled")
        return 130
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scan.py", description="Null-Trace OSINT workbench")
    parser.add_argument("--list", action="store_true", help="list available modules")
    parser.add_argument("--run", metavar="MODULE", help="run a module without the GUI")
    parser.add_argument("-a", "--arg", action="append", default=[], metavar="KEY=VALUE",
                        help="input for --run, repeatable")
    parser.add_argument("--probe-cli", action="store_true",
                        help="run the vendored username-probe CLI; its own flags follow")
    parser.add_argument("--version", action="store_true", help="print version")
    args, extra = parser.parse_known_args(argv)

    if args.probe_cli:
        _bootstrap()
        sys.argv = ["probe", *extra]
        from username_probe.probe import main as probe_main
        probe_main()
        return 0

    if args.version:
        from nulltrace.version import APP_NAME, VERSION
        print(f"{APP_NAME} {VERSION}")
        return 0

    _bootstrap()

    if args.list:
        _list_modules()
        return 0

    if args.run:
        return _run_headless(args.run, args.arg)

    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("tkinter is not available in this Python build.\n"
              "Windows/macOS: reinstall Python from python.org with tcl/tk enabled.\n"
              "Debian/Ubuntu: sudo apt install python3-tk", file=sys.stderr)
        return 1

    from nulltrace.crashlog import enable_faulthandler, install_excepthook
    enable_faulthandler()
    install_excepthook()

    from nulltrace.gui.app import main as gui_main
    gui_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
