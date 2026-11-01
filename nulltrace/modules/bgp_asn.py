"""ASN and routing data through RIPE Stat (public, no key)."""

from __future__ import annotations

import ipaddress

from ..job import Field, Module
from ..net import HttpError, get_json

API = "https://stat.ripe.net/data"


def _asn(value: str) -> int | None:
    digits = value.upper().lstrip("AS")
    return int(digits) if digits.isdigit() else None


def _get(name: str, resource: str, timeout: int = 30) -> dict:
    data = get_json(f"{API}/{name}/data.json?resource={resource}", timeout=timeout)
    return data.get("data") or {}


def run(ctx) -> None:
    raw = ctx.value("query").strip()
    if not raw:
        ctx.error("Enter an ASN (AS13335) or an IP address.")
        return
    ctx.title(f"BGP / ASN — {raw}")

    is_ip = False
    try:
        ipaddress.ip_address(raw)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        ctx.status("Mapping the address to a network ...")
        try:
            info = _get("network-info", raw)
        except HttpError as exc:
            ctx.error(f"RIPE Stat request failed: {exc}")
            return
        prefix = info.get("prefix") or "—"
        asns = info.get("asns") or []
        ctx.section("Address")
        ctx.kv("Prefix", prefix)
        ctx.kv("ASNs", ", ".join(f"AS{a}" for a in asns) or "—")
        if not asns:
            ctx.warn("No origin ASN found for this address.")
            return
        asn = int(asns[0])
    else:
        asn = _asn(raw)
        if not asn:
            ctx.error("That does not look like an ASN or an IP address.")
            return

    ctx.check_cancel()
    ctx.status(f"Loading AS{asn} ...")
    try:
        overview = _get("as-overview", f"AS{asn}")
    except HttpError as exc:
        ctx.error(f"AS overview failed: {exc}")
        return
    ctx.section(f"AS{asn}")
    ctx.kv("Holder", overview.get("holder") or "—")
    ctx.kv("Type", overview.get("type") or "—")
    ctx.kv("Announced", "yes" if overview.get("announced") else "no")
    block = overview.get("block") or {}
    if block:
        ctx.kv("Allocated block", f"{block.get('resource', '?')} ({block.get('desc', '')})")

    ctx.check_cancel()
    ctx.status("Loading announced prefixes ...")
    try:
        prefixes = _get("announced-prefixes", f"AS{asn}")
    except HttpError:
        prefixes = {}
    entries = prefixes.get("prefixes") or []
    v4 = [p["prefix"] for p in entries if ":" not in p.get("prefix", "")]
    v6 = [p["prefix"] for p in entries if ":" in p.get("prefix", "")]
    ctx.kv("IPv4 prefixes", len(v4))
    ctx.kv("IPv6 prefixes", len(v6))
    if v4:
        ctx.section("IPv4 prefixes")
        for prefix in v4[:30]:
            ctx.text(f"  {prefix}")
        if len(v4) > 30:
            ctx.muted(f"  … {len(v4) - 30} more")

    ctx.check_cancel()
    ctx.status("Loading neighbours ...")
    try:
        neighbours = _get("asn-neighbours", f"AS{asn}")
    except HttpError:
        neighbours = {}
    peers = neighbours.get("neighbours") or []
    upstreams = [p for p in peers if p.get("type") == "left"]
    downstreams = [p for p in peers if p.get("type") == "right"]
    ctx.kv("Upstreams", len(upstreams))
    ctx.kv("Downstreams", len(downstreams))
    if upstreams:
        ctx.section("Upstreams")
        rows = [(f"AS{p.get('asn')}", (p.get("name") or "—")[:38]) for p in upstreams[:15]]
        ctx.table(("ASN", "Name"), rows)

    ctx.link("RIPE Stat", f"https://stat.ripe.net/AS{asn}")
    ctx.link("bgp.he.net", f"https://bgp.he.net/AS{asn}")
    ctx.note("Routing changes constantly; this is a snapshot of the global table right now.")


MODULE = Module(
    id="bgp_asn",
    title="BGP / ASN",
    category="Network",
    summary="Autonomous system holder, announced prefixes and upstreams, via RIPE Stat.",
    fields=(
        Field("query", "ASN or IP", placeholder="AS13335 or 1.1.1.1", required=True),
    ),
    run=run,
    order=92,
)
