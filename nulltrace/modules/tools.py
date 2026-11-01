"""Environment diagnostics and external tool management."""

from __future__ import annotations

import importlib.util
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from ..config import CONFIG, CONFIG_PATH, KEY_LABELS, data_dir
from ..job import Field, Module
from ..version import VERSION

MODES = ("Environment check", "Install ExifTool", "Check for updates")

REQUIRED = [
    ("requests", "requests"), ("dns", "dnspython"), ("customtkinter", "customtkinter"),
    ("PIL", "Pillow"), ("phonenumbers", "phonenumbers"), ("piexif", "piexif"),
    ("qrcode", "qrcode"), ("bs4", "beautifulsoup4"), ("speedtest", "speedtest-cli"),
]
OPTIONAL = [
    ("socks", "PySocks (Tor support)"), ("yaml", "PyYAML"),
]


def _version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def _environment(ctx) -> None:
    ctx.section("Runtime")
    ctx.kv("Python", f"{_version()} ({platform.architecture()[0]})")
    ctx.kv("Executable", sys.executable)
    ctx.kv("Platform", f"{platform.system()} {platform.release()}")
    ctx.kv("NullTrace", VERSION)
    ctx.kv("Config file", CONFIG_PATH)
    ctx.kv("Data directory", data_dir())

    ctx.section("Python packages")
    missing = 0
    for module, package in REQUIRED:
        found = importlib.util.find_spec(module) is not None
        (ctx.ok if found else ctx.warn)(f"  {package:<20} {'present' if found else 'MISSING'}")
        missing += 0 if found else 1
    for module, label in OPTIONAL:
        found = importlib.util.find_spec(module) is not None
        (ctx.ok if found else ctx.muted)(f"  {label:<20} {'present' if found else 'optional, missing'}")

    ctx.section("External tools")
    for tool, hint in (
        ("exiftool", "full metadata extraction"),
        ("git", "update checks and tool installs"),
        ("tor", "dark web module via SOCKS"),
        ("go", "external Go tooling"),
        ("node", "JS-based helpers"),
        ("winget", "package installation on Windows"),
    ):
        path = shutil.which(tool)
        (ctx.ok if path else ctx.muted)(f"  {tool:<10} {path or 'not found'}   ({hint})")

    ctx.section("API keys")
    for name, label, _hint in KEY_LABELS:
        configured = bool(CONFIG.key(name))
        (ctx.ok if configured else ctx.muted)(
            f"  {label:<24} {'configured' if configured else 'not set'}")

    if missing:
        ctx.warn(f"{missing} required package(s) missing — run: pip install -r requirements.txt")
    else:
        ctx.ok("All required Python packages are installed.")


def _install_exiftool(ctx) -> None:
    if shutil.which("exiftool"):
        ctx.ok("ExifTool is already installed.")
        return
    ctx.note("ExifTool is optional but needed for non-image formats and full tag coverage.")
    if platform.system().lower() != "windows":
        ctx.note("On Linux: sudo apt install libimage-exiftool-perl")
        ctx.note("On macOS: brew install exiftool")
        return
    installer = shutil.which("winget")
    if not installer:
        ctx.error("winget is unavailable. Download ExifTool from https://exiftool.org and add")
        ctx.error("the folder to PATH, or run: choco install exiftool -y")
        return
    ctx.status("Installing ExifTool via winget ...")
    result = subprocess.run(
        [installer, "install", "--id", "OliverBetz.ExifTool", "-e",
         "--accept-source-agreements", "--accept-package-agreements"],
        capture_output=True, text=True, timeout=300, check=False,
    )
    tail = (result.stdout or "") + (result.stderr or "")
    for line in tail.strip().splitlines()[-12:]:
        ctx.muted(f"  {line}")
    if result.returncode == 0 and shutil.which("exiftool"):
        ctx.ok("ExifTool installed. Restart NullTrace so PATH is refreshed.")
    elif result.returncode == 0:
        ctx.ok("Install reported success — open a new terminal so PATH refreshes.")
    else:
        ctx.warn("winget install did not succeed. Manual download: https://exiftool.org")


def _updates(ctx) -> None:
    ctx.kv("Installed version", VERSION)
    root = Path(__file__).resolve().parents[2]
    if not (root / ".git").exists():
        ctx.muted("This copy is not a git checkout, so there is nothing to fetch.")
        ctx.note("To update, replace the project folder with a newer release.")
        return
    ctx.status("Fetching git metadata ...")
    result = subprocess.run(["git", "-C", str(root), "fetch", "--quiet"], capture_output=True,
                            text=True, timeout=90, check=False)
    if result.returncode != 0:
        ctx.error(f"git fetch failed: {(result.stderr or '').strip()[:200]}")
        return
    local = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                           capture_output=True, text=True, check=False).stdout.strip()
    remote = subprocess.run(["git", "-C", str(root), "rev-parse", "@{u}"],
                            capture_output=True, text=True, check=False).stdout.strip()
    ctx.kv("Local commit", local[:12])
    ctx.kv("Remote commit", remote[:12] or "no upstream")
    if remote and local != remote:
        ctx.warn("A newer commit exists — run: git pull")
    else:
        ctx.ok("Already up to date.")


def run(ctx) -> None:
    mode = ctx.value("mode") or MODES[0]
    ctx.title(f"Toolkit — {mode}")
    if mode == "Environment check":
        _environment(ctx)
    elif mode == "Install ExifTool":
        _install_exiftool(ctx)
    else:
        _updates(ctx)


MODULE = Module(
    id="tools",
    title="Toolkit",
    category="System",
    summary="Check the runtime, Python packages, external tools and API keys; install ExifTool; check updates.",
    fields=(
        Field("mode", "Action", kind="choice", choices=MODES, default=MODES[0]),
    ),
    run=run,
    order=230,
)
