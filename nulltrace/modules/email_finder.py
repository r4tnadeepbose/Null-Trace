"""Email finder: Hunter.io domain search plus pattern generation with optional SMTP probing."""

from __future__ import annotations

import smtplib
import socket

from ..job import Field, Module
from ..net import HttpError, get_json


def _hunter(domain: str, key: str) -> dict | None:
    try:
        data = get_json(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": key, "limit": 25},
            timeout=20,
        )
    except HttpError as exc:
        return {"error": str(exc)}
    return data.get("data", {})


def _patterns(first: str, last: str, domain: str) -> list[str]:
    first, last = first.lower(), last.lower()
    if not first and not last:
        return []
    local_parts = []
    if first and last:
        local_parts += [
            f"{first}.{last}", f"{first}{last}", f"{first[0]}{last}", f"{first}_{last}",
            f"{first}-{last}", f"{last}.{first}", f"{last}{first[0]}",
        ]
    if first:
        local_parts += [first]
    if last:
        local_parts += [last]
    seen, out = set(), []
    for local in local_parts:
        address = f"{local}@{domain}"
        if address not in seen:
            seen.add(address)
            out.append(address)
    return out


def _smtp_verify(address: str, mx_host: str) -> str:
    """RCPT probe. Returns accepted / rejected / unknown / blocked."""
    try:
        with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
            smtp.ehlo_or_helo_if_needed()
            smtp.mail("verify@example.com")
            code, _ = smtp.rcpt(address)
    except (socket.timeout, ConnectionRefusedError, smtplib.SMTPConnectError):
        return "blocked"
    except smtplib.SMTPServerDisconnected:
        return "blocked"
    except smtplib.SMTPRecipientsRefused:
        return "rejected"
    except (smtplib.SMTPException, OSError):
        return "unknown"
    if 200 <= code < 300:
        return "accepted"
    if 500 <= code < 600:
        return "rejected"
    return "unknown"


def _mx_host(domain: str) -> str | None:
    try:
        import dns.resolver
        answers = sorted(dns.resolver.resolve(domain, "MX", lifetime=10),
                         key=lambda r: r.preference)
        return str(answers[0].exchange).rstrip(".") if answers else None
    except Exception:
        return None


def run(ctx) -> None:
    domain = ctx.value("domain").lower().lstrip("@")
    first = ctx.value("first")
    last = ctx.value("last")
    if not domain:
        ctx.error("Enter the company domain (e.g. example.com).")
        return
    ctx.title(f"Email finder — {domain}")

    key = ctx.key("hunter")
    if key:
        ctx.section("Hunter.io domain search")
        ctx.status("Querying Hunter.io ...")
        result = _hunter(domain, key)
        if not result:
            ctx.warn("  Hunter returned no data (quota or unindexed domain).")
        elif result.get("error"):
            ctx.warn(f"  {result['error']}")
        else:
            ctx.kv("Organisation", result.get("organization"))
            ctx.kv("Pattern", result.get("pattern"))
            ctx.kv("Emails known", result.get("total"))
            emails = result.get("emails", [])
            if emails:
                ctx.table(
                    ("Email", "Name", "Position", "Confidence"),
                    ((e.get("value"), (e.get("first_name") or "") + " " + (e.get("last_name") or ""),
                      e.get("position") or "", f"{e.get('confidence', 0)}%") for e in emails),
                )
            ctx.muted("Respect Hunter's terms and applicable privacy law before contacting people.")
    else:
        ctx.warn("No Hunter.io key — skipping API search (pattern generation still runs).")
        ctx.link("Hunter.io", "https://hunter.io")

    ctx.check_cancel()
    candidates = _patterns(first, last, domain)
    if not candidates:
        ctx.muted("Fill in first/last name to generate candidate addresses.")
        return

    ctx.section("Generated candidates")
    mx_host = _mx_host(domain)
    verify = ctx.checked("smtp") and bool(mx_host)
    if verify:
        ctx.note(f"SMTP probing via {mx_host} on port 25 — outbound 25 is often blocked.")
    elif ctx.checked("smtp"):
        ctx.warn("No MX host found — SMTP verification skipped.")

    rows = []
    for address in candidates:
        ctx.check_cancel()
        verdict = "syntax ok"
        if verify:
            verdict = _smtp_verify(address, mx_host)
            ctx.status(f"Probing {address} -> {verdict}")
        rows.append((address, verdict))
    ctx.table(("Candidate", "SMTP"), rows)

    accepted = [a for a, v in rows if v == "accepted"]
    if accepted:
        ctx.ok(f"{len(accepted)} address(es) accepted by the mail server (still not proof of ownership).")
    elif verify:
        ctx.muted("No address accepted. Servers commonly reject probes regardless of validity.")
    ctx.link("Hunter verify", "https://hunter.io/email-verifier")


MODULE = Module(
    id="email_finder",
    title="Email Finder",
    category="Identity",
    summary="Hunter.io lookup plus name-pattern candidates, with optional SMTP RCPT verification.",
    fields=(
        Field("domain", "Company domain", placeholder="example.com", required=True),
        Field("first", "First name", placeholder="jane"),
        Field("last", "Last name", placeholder="doe"),
        Field("smtp", "Verify candidates over SMTP (port 25)", kind="checkbox", default="0"),
    ),
    keys=("hunter",),
    run=run,
    order=50,
)
