"""MAC address vendor lookup via the macvendors API (offline-free, no key)."""

from __future__ import annotations

import re
import time

from ..job import Field, Module
from ..net import HttpError, http

HEX_RE = re.compile(r"[^0-9A-Fa-f]")


def _normalize(value: str) -> str | None:
    cleaned = HEX_RE.sub("", value)
    if len(cleaned) not in (12, 16):
        return None
    return cleaned.upper()


def _colon(mac: str) -> str:
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2))


def _lookup(mac: str) -> tuple[str, str]:
    try:
        response = http(f"https://api.macvendors.com/{mac}", timeout=15,
                        allow_status=(404, 429, 403))
    except HttpError as exc:
        return "lookup failed", str(exc)[:80]
    if response.status_code == 404:
        return "unknown", "no vendor registered for this OUI"
    if response.status_code == 429:
        return "rate limited", "the free API allows one request per second"
    if response.status_code in (403, 401):
        return "blocked", "the API refused the request"
    return "ok", response.text.strip()[:80]


def run(ctx) -> None:
    raw = ctx.value("macs")
    if not raw.strip():
        ctx.error("Enter one or more MAC addresses.")
        return
    entries = [item.strip() for item in re.split(r"[\n,;]+", raw) if item.strip()]
    if not entries:
        ctx.error("No MAC addresses found in the input.")
        return

    ctx.title("MAC vendor lookup")
    rows = []
    previous_request = 0.0
    for entry in entries:
        ctx.check_cancel()
        mac = _normalize(entry)
        if not mac:
            rows.append((entry, "invalid", "—", "—"))
            continue
        first_octet = int(mac[0:2], 16)
        flags = []
        if first_octet & 0x02:
            flags.append("locally administered")
        if first_octet & 0x01:
            flags.append("multicast")
        # macvendors rate-limits to one query per second
        wait = 1.1 - (time.time() - previous_request)
        if wait > 0:
            ctx.sleep(wait)
        previous_request = time.time()
        ctx.status(f"Looking up {_colon(mac)} ...")
        status, vendor = _lookup(mac)
        rows.append((_colon(mac), status, vendor, ", ".join(flags) or "unicast / global"))

    ctx.section("Results")
    ctx.table(("MAC", "Status", "Vendor", "Flags"), rows)

    unknown = [r[0] for r in rows if r[1] == "unknown"]
    if unknown:
        ctx.muted(f"No OUI record: {', '.join(unknown[:10])}")
    if any(r[1] == "rate limited" for r in rows):
        ctx.warn("Free API rate limit hit — try fewer addresses at a time.")

    ctx.section("OUI notes")
    ctx.note("The first three octets identify the manufacturer, not the device model.")
    ctx.note("Locally administered addresses (bit 1 set) are randomised — common on phones,")
    ctx.note("Windows Wi-Fi randomisation and virtual machines, so no vendor is expected.")
    ctx.link("IEEE OUI search", "https://standards-oui.ieee.org/oui/oui.txt")


MODULE = Module(
    id="mac_lookup",
    title="MAC Vendor",
    category="Network",
    summary="Resolve MAC addresses to manufacturers, and flag randomised or multicast addresses.",
    fields=(
        Field("macs", "MAC addresses", kind="multiline", required=True,
              placeholder="3C:5A:B4:11:22:33\nA4:83:E7:44:55:66",
              help="One per line, or comma separated. Up to a handful per run (1 req/sec free)."),
    ),
    run=run,
    order=95,
)
