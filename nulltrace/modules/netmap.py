"""Network path mapping: traceroute with per-hop geolocation."""

from __future__ import annotations

import platform
import re
import subprocess

from ..job import Field, Module
from ..net import HttpError, get_json, resolve

HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")


def _traceroute(host: str, max_hops: int) -> list[str]:
    system = platform.system().lower()
    if system == "windows":
        args = ["tracert", "-d", "-h", str(max_hops), "-w", "1500", host]
    else:
        args = ["traceroute", "-n", "-m", str(max_hops), "-w", "2", host]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=180,
                                encoding="utf-8", errors="replace", check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(str(exc)) from exc
    return (result.stdout or result.stderr).splitlines()


def _geo(ip: str) -> dict:
    try:
        data = get_json(f"https://ipinfo.io/{ip}/json", timeout=6)
    except HttpError:
        return {}
    if data.get("bogon"):
        return {}
    return data


def run(ctx) -> None:
    host = ctx.value("host").strip()
    if not host:
        ctx.error("Enter a host or IP.")
        return
    try:
        max_hops = max(3, min(40, int(ctx.value("hops") or "15")))
    except ValueError:
        max_hops = 15

    addresses = resolve(host) if not host.replace(".", "").isdigit() else [host]
    if not addresses:
        ctx.error(f"Could not resolve {host}")
        return
    target = addresses[0]

    ctx.title(f"Network map — {host} ({target})")
    ctx.status("Running traceroute ...")
    try:
        lines = _traceroute(target, max_hops)
    except RuntimeError as exc:
        ctx.error(f"traceroute unavailable: {exc}")
        return

    hops: list[tuple[int, str, str]] = []
    for line in lines:
        match = HOP_RE.match(line)
        if not match:
            continue
        hop = int(match.group(1))
        rest = match.group(2).strip()
        tokens = [t for t in rest.split() if t not in ("*", "ms", "<1")]
        ips = [t for t in tokens if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", t.strip("[]"))]
        ips = [t.strip("[]") for t in ips]
        if not ips:
            hops.append((hop, "*", "no reply"))
            continue
        hops.append((hop, ips[0], ""))

    if not hops:
        ctx.warn("No hops parsed.")
        for line in lines[:20]:
            ctx.text(line)
        return

    ctx.section("Path")
    rows = []
    for hop, ip, note in hops:
        ctx.check_cancel()
        label = note
        if ip != "*" and ctx.checked("geo"):
            info = _geo(ip)
            parts = [info.get("city"), info.get("region"), info.get("country"),
                     info.get("org")]
            label = " · ".join(p for p in parts if p) or "—"
        rows.append((hop, ip, label))
    ctx.table(("Hop", "Address", "Location / network"), rows)

    ctx.kv("Hops", len(hops))
    ctx.note("Timeouts (*) usually mean ICMP is filtered, not that the hop is down.")


MODULE = Module(
    id="netmap",
    title="Network Map",
    category="Network",
    summary="Traceroute to a target with city/country/ASN lookup for every responding hop.",
    fields=(
        Field("host", "Host or IP", placeholder="1.1.1.1", required=True),
        Field("hops", "Max hops", default="15"),
        Field("geo", "Geolocate each hop", kind="checkbox", default="1"),
    ),
    run=run,
    order=180,
)
