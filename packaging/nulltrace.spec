# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for a portable Null-Trace build.

    python -m pip install pyinstaller
    pyinstaller --noconfirm --clean packaging/nulltrace.spec

Output: dist/Null-Trace/Null-Trace.exe (no console window).
"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent

datas = [(str(ROOT / "data"), "data"),
         (str(ROOT / "assets" / "app.ico"), "assets"),
         (str(ROOT / "assets" / "app.png"), "assets"),
         (str(ROOT / "username_probe" / "resources" / "data.json"),
          "username_probe/resources"),
         (str(ROOT / "username_probe" / "resources" / "data.schema.json"),
          "username_probe/resources"),
         (str(ROOT / "username_probe" / "LICENSE"), "username_probe")]
datas += collect_data_files("customtkinter")
hiddenimports = collect_submodules("customtkinter") + [
    "dns.resolver",
    "dns.reversename",
    "phonenumbers",
    "piexif",
    "qrcode",
    "bs4",
    "speedtest",
    "requests_futures",
    "requests_futures.sessions",
    "openpyxl",
    "socks",
]
# The probe engine is imported lazily, so PyInstaller cannot see it from
# scan.py; collect it explicitly.
hiddenimports += collect_submodules("username_probe")

a = Analysis(
    [str(ROOT / "scan.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter.test", "test", "unittest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Null-Trace",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    name="Null-Trace",
    strip=False,
    upx=False,
    upx_exclude=[],
)
