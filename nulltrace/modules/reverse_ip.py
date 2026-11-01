"""Domains sharing an IP address, from HackerTarget's passive reverse-IP index."""

from __future__ import annotations

from ..job import Field, Module
from ..net import HttpError, http, resolve

MAX_ROWS = 100


def run(ctx) -> None:
    raw = ctx.value("ip").strip()
    if not raw:
        ctx.error("Enter an IP address or hostname.")
        return
    ip = raw
    try:
        import ipaddress
        ipaddress.ip_address(raw)
    except ValueError:
        addresses = resolve(raw)
        if not addresses:
            ctx.error(f"Could not resolve {raw}")
            return
        ip = addresses[0]
        ctx.muted(f"{raw} → {ip}")

    ctx.title(f"Reverse IP — {ip}")
    ctx.status("Querying HackerTarget ...")
    try:
        response = http(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=30)
    except HttpError as exc:
        ctx.error(f"Lookup failed: {exc}")
        return

    body = response.text.strip()
    if not body or "error" in body.lower() or "API count exceeded" in body:
        ctx.warn("HackerTarget returned an error or an empty result.")
        if body:
            ctx.muted(body[:200])
        ctx.link("ViewDNS (manual)", f"https://viewdns.info/reverseip/?host={ip}")
        return

    domains = sorted({line.strip() for line in body.splitlines() if line.strip()})
    ctx.kv("Domains on this address", len(domains))
    ctx.section("Domains")
    for domain in domains[:MAX_ROWS]:
        ctx.text(f"  {domain}")
    if len(domains) > MAX_ROWS:
        ctx.muted(f"  … {len(domains) - MAX_ROWS} more")

    ctx.section("Notes")
    ctx.note("Shared hosting means unrelated sites appear here; this is not attribution.")
    ctx.link("ViewDNS", f"https://viewdns.info/reverseip/?host={ip}")
    ctx.link("Shodan host view", f"https://www.shodan.io/host/{ip}")


MODULE = Module(
    id="reverse_ip",
    title="Reverse IP",
    category="Network",
    summary="Domains hosted on the same address, from a passive reverse-IP index.",
    fields=(
        Field("ip", "IP or hostname", placeholder="104.20.23.154", required=True),
    ),
    run=run,
    order=96,
)
