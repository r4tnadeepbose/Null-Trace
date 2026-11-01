"""Email header analysis: authentication results, hop chain and spoofing signals."""

from __future__ import annotations

import re
from email import policy
from email.parser import Parser
from email.utils import parsedate_to_datetime

from ..job import Field, Module
from ..net import HttpError, get_json

IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
AUTH_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip("> ").lower() if "@" in address else ""


def _auth_results(msg) -> list[tuple[str, str, str]]:
    rows = []
    for header in ("Authentication-Results", "ARC-Authentication-Results", "Received-SPF"):
        for value in msg.get_all(header, []) or []:
            text = str(value)
            if header == "Received-SPF":
                verdict = text.split()[0] if text.split() else "unknown"
                rows.append(("spf", verdict.lower(), text[:160]))
                continue
            for mechanism, verdict in AUTH_RE.findall(text):
                rows.append((mechanism.lower(), verdict.lower(), text[:160]))
    return rows


def _hops(msg) -> list[dict]:
    hops = []
    for value in msg.get_all("Received", []) or []:
        text = " ".join(str(value).split())
        ip_match = IP_RE.search(text)
        date_text = text.rsplit(";", 1)[-1].strip()
        try:
            when = parsedate_to_datetime(date_text)
        except (TypeError, ValueError):
            when = None
        hops.append({
            "ip": ip_match.group(1) if ip_match else "",
            "when": when,
            "raw": text[:180],
        })
    hops.reverse()
    return hops


def _geo(ip: str) -> str:
    try:
        data = get_json(f"https://ipinfo.io/{ip}/json", timeout=8)
    except HttpError:
        return ""
    if data.get("bogon"):
        return "private / reserved"
    parts = [data.get("city"), data.get("region"), data.get("country"), data.get("org")]
    return " · ".join(p for p in parts if p)


def run(ctx) -> None:
    raw = ctx.value("raw")
    if not raw.strip():
        ctx.error("Paste the raw message headers.")
        return
    if ":" not in raw:
        ctx.error("That does not look like email headers (no 'Name: value' lines).")
        return

    msg = Parser(policy=policy.default).parsestr(raw)
    ctx.title("Email header analysis")
    ctx.section("Envelope")
    for label, header in (
        ("From", "From"), ("Reply-To", "Reply-To"), ("Return-Path", "Return-Path"),
        ("To", "To"), ("Cc", "Cc"), ("Subject", "Subject"), ("Date", "Date"),
        ("Message-ID", "Message-ID"), ("X-Mailer", "X-Mailer"),
        ("User-Agent", "User-Agent"),
    ):
        value = msg.get(header)
        if value:
            ctx.kv(label, str(value)[:160])

    from_header = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", "") or "")
    return_path = str(msg.get("Return-Path", "") or "")
    from_domain = _domain(from_header)
    ctx.kv("From domain", from_domain or "—")

    ctx.check_cancel()
    rows = _auth_results(msg)
    ctx.section("Authentication")
    if rows:
        seen = set()
        for mechanism, verdict, _detail in rows:
            key = (mechanism, verdict)
            if key in seen:
                continue
            seen.add(key)
            good = verdict in ("pass", "none")
            fn = ctx.ok if verdict == "pass" else (ctx.muted if verdict == "none" else ctx.warn)
            fn(f"  {mechanism.upper()}: {verdict}")
    else:
        ctx.warn("  No Authentication-Results / Received-SPF header found.")
        ctx.muted("  Many clients strip these — check the original raw message.")

    ctx.check_cancel()
    hops = _hops(msg)
    ctx.section(f"Hop chain ({len(hops)})")
    if hops:
        geo = ctx.checked("geo")
        table_rows = []
        previous = None
        for index, hop in enumerate(hops, start=1):
            delta = ""
            if previous and hop["when"] and previous["when"]:
                seconds = (hop["when"] - previous["when"]).total_seconds()
                delta = f"+{seconds:.0f}s" if seconds >= 0 else f"{seconds:.0f}s"
            location = _geo(hop["ip"]) if geo and hop["ip"] else ""
            table_rows.append((index, hop["ip"] or "—",
                               hop["when"].isoformat(sep=" ")[:19] if hop["when"] else "—",
                               delta or "—", location or "—"))
            previous = hop
        ctx.table(("Hop", "IP", "Timestamp", "Delay", "Location"), table_rows)
        ctx.kv("Hops", len(hops))
        numeric_delays = [float(r[3].strip("+s")) for r in table_rows
                          if r[3] not in ("—", "") and r[3].strip("+s").replace(".", "", 1).isdigit()]
        if numeric_delays:
            ctx.muted(f"Largest hop delay: {max(numeric_delays):.0f}s")
        first_ip = hops[0]["ip"]
        if first_ip:
            ctx.kv("Originating IP", first_ip)
            ctx.note("The first hop is the sender's own mail server (or a forgery of it).")
    else:
        ctx.muted("No Received headers present.")

    ctx.check_cancel()
    ctx.section("Spoofing signals")
    warnings = 0
    if reply_to and from_domain and _domain(reply_to) != from_domain:
        warnings += 1
        ctx.warn(f"Reply-To ({_domain(reply_to)}) differs from From ({from_domain})")
    if return_path and from_domain and _domain(return_path) != from_domain:
        warnings += 1
        ctx.warn(f"Return-Path ({_domain(return_path)}) differs from From ({from_domain})")
    for mechanism, verdict, _detail in rows:
        if mechanism == "spf" and verdict in ("fail", "softfail"):
            warnings += 1
            ctx.error(f"SPF {verdict} — envelope sender is not authorised for that domain.")
        if mechanism == "dkim" and verdict in ("fail", "temperror", "permerror"):
            warnings += 1
            ctx.error(f"DKIM {verdict} — signature did not validate.")
        if mechanism == "dmarc" and verdict == "fail":
            warnings += 1
            ctx.error("DMARC failed — the message failed domain alignment.")
    display = str(msg.get("From", ""))
    if display.count("@") == 0 and "<" not in display:
        ctx.muted("From header has no address in angle brackets — unusual for mail clients.")
    if warnings == 0:
        ctx.ok("No structural spoofing signals detected (absence is not proof of legitimacy).")

    ctx.section("Verdict")
    level = "high risk" if warnings >= 2 else ("suspicious" if warnings == 1 else "consistent")
    ctx.kv("Assessment", level)
    ctx.kv("Signals", warnings)
    ctx.note("Forward the original message (not a screenshot) when reporting phishing.")


MODULE = Module(
    id="email_headers",
    title="Email Headers",
    category="Identity",
    summary="Paste raw headers to trace the hop chain, read SPF/DKIM/DMARC and spot spoofing.",
    fields=(
        Field("raw", "Raw headers", kind="multiline", required=True,
              placeholder="Received: from ...\nFrom: ...\nAuthentication-Results: ...",
              help="In most clients: View source / Show original, then copy the header block."),
        Field("geo", "Geolocate hop IPs", kind="checkbox", default="0"),
    ),
    run=run,
    order=66,
)
