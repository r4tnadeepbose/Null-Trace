"""Wi-Fi reconnaissance using native OS tooling (netsh on Windows, nmcli on Linux)."""

from __future__ import annotations

import platform
import re
import subprocess

from ..config import data_dir
from ..job import Field, Module

MODES = ("Scan nearby networks", "List saved profiles", "Reveal saved password")


def _run(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=40,
                            encoding="utf-8", errors="replace", check=False)
    return result.stdout or result.stderr


def _scan_windows() -> list[dict]:
    output = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    networks: list[dict] = []
    current: dict | None = None
    for line in output.splitlines():
        stripped = line.strip()
        match = re.match(r"SSID\s+(\d+)\s*:\s*(.*)", stripped)
        if match:
            current = {"ssid": match.group(2).strip() or "(hidden)", "bssids": []}
            networks.append(current)
            continue
        if current is None:
            continue
        for key, pattern in (
            ("auth", r"Authentication\s*:\s*(.*)"),
            ("cipher", r"Encryption\s*:\s*(.*)"),
            ("signal", r"Signal\s*:\s*(.*)"),
            ("channel", r"Channel\s*:\s*(.*)"),
            ("band", r"Band\s*:\s*(.*)"),
        ):
            match = re.match(pattern, stripped)
            if match:
                current[key] = match.group(1).strip()
        match = re.match(r"BSSID\s+\d+\s*:\s*(.*)", stripped)
        if match:
            current["bssids"].append(match.group(1).strip())
    return networks


def _scan_linux() -> list[dict]:
    output = _run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,CHAN", "device", "wifi", "list"])
    rows = []
    for line in output.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) < 4:
            continue
        rows.append({"ssid": parts[0] or "(hidden)", "signal": parts[1],
                     "auth": parts[2] or "open", "channel": parts[3]})
    return rows


def _profiles_windows() -> list[str]:
    output = _run(["netsh", "wlan", "show", "profiles"])
    return re.findall(r"All User Profile\s*:\s*(.+)", output)


def _profile_details_windows(name: str) -> dict:
    output = _run(["netsh", "wlan", "show", "profile", f"name={name}", "key=clear"])
    details: dict = {}
    for label, pattern in (
        ("SSID", r"SSID name\s*:\s*\"?(.*?)\"?\s*$"),
        ("Authentication", r"Authentication\s*:\s*(.*)"),
        ("Cipher", r"Cipher\s*:\s*(.*)"),
        ("Key", r"Key Content\s*:\s*(.*)"),
        ("Security key", r"Security key\s*:\s*(Present|Absent)"),
    ):
        match = re.search(pattern, output, re.M)
        if match:
            details[label] = match.group(1).strip()
    return details


def _qr(ssid: str, password: str) -> str | None:
    try:
        import qrcode
    except ImportError:
        return None
    text = f"WIFI:T:{'WPA' if password else 'nopass'};S:{ssid};P:{password};;"
    image = qrcode.make(text)
    target = data_dir() / "wifi_qr.png"
    image.save(target)
    return str(target)


def run(ctx) -> None:
    mode = ctx.value("mode") or MODES[0]
    system = platform.system().lower()
    ctx.title("Wi-Fi reconnaissance")

    if mode == "Scan nearby networks":
        if system == "windows":
            ctx.status("Running netsh wlan show networks ...")
            networks = _scan_windows()
        elif system == "linux":
            ctx.status("Running nmcli ...")
            networks = _scan_linux()
        else:
            ctx.error("Only Windows and Linux are supported for Wi-Fi scanning.")
            return
        if not networks:
            ctx.error("No networks returned. Is the Wi-Fi adapter enabled?")
            return
        ctx.kv("Networks in range", len(networks))
        ctx.table(
            ("SSID", "Auth", "Cipher", "Signal", "Channel"),
            ((n.get("ssid", "?"), n.get("auth", "?"), n.get("cipher", ""),
              n.get("signal", ""), n.get("channel", "")) for n in networks),
        )
        open_nets = [n for n in networks if "open" in str(n.get("auth", "")).lower()]
        if open_nets:
            ctx.warn(f"{len(open_nets)} open network(s) — traffic on those is unencrypted.")
        return

    if system != "windows":
        ctx.error("Saved-profile inspection is implemented for Windows only.")
        return

    if mode == "List saved profiles":
        profiles = _profiles_windows()
        if not profiles:
            ctx.error("No saved Wi-Fi profiles.")
            return
        ctx.kv("Profiles", len(profiles))
        for name in profiles:
            ctx.text(f"  {name}")
        return

    name = ctx.value("profile").strip()
    if not name:
        ctx.error("Enter a saved profile name (see 'List saved profiles').")
        return
    details = _profile_details_windows(name)
    if not details:
        ctx.error(f"Profile not found: {name}")
        return
    ctx.section(name)
    for key, value in details.items():
        ctx.kv(key, value or "—")
    password = details.get("Key", "")
    if password:
        ctx.warn("Password recovered — only do this on a machine you own.")
        qr = _qr(details.get("SSID", name), password)
        if qr:
            ctx.ok(f"QR code written to {qr}")
    else:
        ctx.muted("No stored key (open network or key not cached).")


MODULE = Module(
    id="wifi",
    title="Wi-Fi",
    category="System",
    summary="Enumerate nearby networks, list saved profiles, or reveal a saved password and generate a QR code.",
    fields=(
        Field("mode", "Mode", kind="choice", choices=MODES, default=MODES[0]),
        Field("profile", "Profile name", placeholder="MyHomeNetwork",
              help="Only needed for 'Reveal saved password'."),
    ),
    run=run,
    order=160,
)
