"""IP reputation against public DNS blocklists (DNSBL)."""

from __future__ import annotations

import ipaddress

from ..job import Field, Module

BLOCKLISTS = (
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("Barracuda", "b.barracudacentral.org"),
    ("SORBS", "dnsbl.sorbs.net"),
    ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"),
    ("SORBS spam", "spam.dnsbl.sorbs.net"),
)

RETURN_CODES = {
    "127.0.0.2": "listed", "127.0.0.3": "listed", "127.0.0.4": "listed",
    "127.0.0.10": "listed", "127.0.0.11": "listed",
    "127.255.255.254": "query blocked by the list (open resolver)",
    "127.255.255.255": "query blocked by the list (open resolver)",
}


def _lookup(zone: str, reversed_ip: str) -> tuple[str, str]:
    try:
        import dns.resolver
    except ImportError:
        return "unknown", "dnspython missing"
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 6
    try:
        answer = resolver.resolve(f"{reversed_ip}.{zone}", "A", raise_on_no_answer=False)
    except Exception as exc:
        name = type(exc).__name__
        if "NXDOMAIN" in name or "NoAnswer" in name:
            return "clean", ""
        return "unknown", name
    if answer.rrset is None:
        return "clean", ""
    codes = [record.to_text() for record in answer]
    reason = ""
    try:
        txt = resolver.resolve(f"{reversed_ip}.{zone}", "TXT", raise_on_no_answer=False)
        if txt.rrset is not None:
            reason = " ".join(
                " ".join(part.decode("utf-8", "replace") for part in r.strings) for r in txt)
    except Exception:
        pass
    first = codes[0] if codes else ""
    state = RETURN_CODES.get(first, "listed")
    return state, reason or ", ".join(codes)


def run(ctx) -> None:
    raw = ctx.value("ip").strip()
    if not raw:
        ctx.error("Enter an IPv4 address.")
        return
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        ctx.error("That is not a valid IP address.")
        return
    if address.version != 4:
        ctx.error("DNSBL lookups are IPv4 only.")
        return
    if address.is_private:
        ctx.warn("Private addresses are not listed on public blocklists.")

    reversed_ip = ".".join(reversed(raw.split(".")))
    ctx.title(f"IP reputation — {raw}")
    ctx.muted("Each list is asked directly; a listing means someone reported mail from this address.")

    rows = []
    listed = 0
    blocked = 0
    for label, zone in BLOCKLISTS:
        ctx.check_cancel()
        ctx.status(f"Asking {label} ...")
        state, reason = _lookup(zone, reversed_ip)
        if state in ("listed",):
            listed += 1
        if state.startswith("query blocked"):
            blocked += 1
        rows.append((label, zone, state.upper(), reason[:40]))

    ctx.section("Blocklists")
    ctx.table(("List", "Zone", "Result", "Reason"), rows)

    ctx.section("Verdict")
    ctx.kv("Listed on", f"{listed} of {len(BLOCKLISTS)}")
    if listed:
        ctx.warn("Listed somewhere — inspect the reason and delisting process before acting.")
    elif blocked:
        ctx.muted(f"{blocked} list(s) refused the query; results are partial.")
    else:
        ctx.ok("Not listed on any queried blocklist.")

    ctx.note("Blocklists flag sending reputation, not intent. Shared IPs can carry another tenant's history.")
    ctx.link("Spamhaus lookup", "https://check.spamhaus.org/")
    ctx.link("MXToolbox blacklist", f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{raw}")


MODULE = Module(
    id="dnsbl",
    title="IP Reputation",
    category="Network",
    summary="Check an IPv4 address against six public DNS blocklists and list the reasons.",
    fields=(
        Field("ip", "IPv4 address", placeholder="8.8.8.8", required=True),
    ),
    run=run,
    order=94,
)
