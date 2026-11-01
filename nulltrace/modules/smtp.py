"""SMTP posture analysis: MX, banner, capabilities, STARTTLS and SPF/DKIM/DMARC hints."""

from __future__ import annotations

import smtplib
import ssl

from ..job import Field, Module
from ..net import EMAIL_RE

try:
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None


def _mx(domain: str) -> list[tuple[int, str]]:
    if dns is None:
        return []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=10)
    except Exception:
        return []
    return sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)


def _txt(name: str) -> list[str]:
    if dns is None:
        return []
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=10)
    except Exception:
        return []
    return [" ".join(p.decode("utf-8", "replace") for p in r.strings) for r in answers]


def run(ctx) -> None:
    domain = ctx.value("domain").lower().strip().lstrip("@")
    if not domain:
        ctx.error("Enter the recipient domain.")
        return
    ctx.title(f"SMTP analysis — {domain}")

    ctx.section("Mail exchangers")
    record = _mx(domain)
    if not record:
        ctx.error("No MX records — the domain does not accept mail.")
        return
    for preference, host in record:
        ctx.text(f"  {preference:>3}  {host}")

    ctx.section("Authentication DNS")
    spf = next((t for t in _txt(domain) if t.lower().startswith("v=spf1")), "")
    ctx.kv("SPF", spf or "missing")
    dmarc = next((t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")), "")
    ctx.kv("DMARC", dmarc or "missing")
    if not dmarc:
        ctx.warn("No DMARC record — spoofed mail is not discouraged by policy.")
    elif "p=none" in dmarc.lower():
        ctx.warn("DMARC is p=none — reports only, no enforcement.")

    ctx.check_cancel()
    host = record[0][1]
    ctx.section(f"Session with {host}:25")
    try:
        smtp = smtplib.SMTP(host, 25, timeout=15)
    except (OSError, smtplib.SMTPException) as exc:
        ctx.error(f"Could not connect on port 25: {exc}")
        ctx.note("Many networks and ISPs block outbound port 25 — try from a VPS if needed.")
        return

    try:
        with smtp:
            smtp.ehlo_or_helo_if_needed()
            banner = getattr(smtp, "ehlo_resp", None) or getattr(smtp, "helo_resp", None)
            if isinstance(banner, bytes):
                banner = banner.decode("utf-8", "replace")
            ctx.kv("Banner", banner or "—")
            features = smtp.esmtp_features
            interesting = ("starttls", "auth", "8bitmime", "smtputf8", "chunking", "pipelining",
                           "size", "dsn", "enhancedstatuscodes")
            for feature in interesting:
                if feature in features:
                    ctx.ok(f"  supported: {feature.upper()}" +
                           (f" {features[feature]}".rstrip() if features[feature] else ""))
            for feature in ("starttls", "auth"):
                if feature not in features:
                    ctx.warn(f"  missing: {feature.upper()}")

            if ctx.checked("starttls") and "starttls" in features:
                ctx.status("Negotiating STARTTLS ...")
                try:
                    smtp.starttls(context=ssl.create_default_context())
                    cipher = smtp.sock.cipher()
                    ctx.ok(f"STARTTLS negotiated — {cipher[0] if cipher else 'unknown cipher'}")
                    ctx.kv("TLS version", cipher[1] if cipher else "?")
                    smtp.ehlo()
                except (ssl.SSLError, smtplib.SMTPException, OSError) as exc:
                    ctx.error(f"STARTTLS failed: {exc}")

            recipient = ctx.value("recipient").strip()
            if recipient and EMAIL_RE.match(recipient):
                ctx.status(f"Probing recipient {recipient} ...")
                try:
                    code, message = smtp.rcpt(recipient)
                    verdict = "accepted" if 200 <= code < 300 else "rejected"
                    level = ctx.ok if verdict == "accepted" else ctx.warn
                    level(f"  RCPT TO <{recipient}> -> {code} {message.decode(errors='replace') if isinstance(message, bytes) else message}")
                    ctx.muted("  A 250 response means the mailbox exists; a 550 means it does not.")
                except smtplib.SMTPRecipientsRefused as exc:
                    ctx.warn(f"  recipient refused: {exc}")
            elif recipient:
                ctx.warn("Recipient is not a valid email address — probe skipped.")
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


MODULE = Module(
    id="smtp",
    title="SMTP Analysis",
    category="Identity",
    summary="MX records, SPF/DMARC, live SMTP banner, ESMTP capabilities, STARTTLS and one RCPT probe.",
    fields=(
        Field("domain", "Domain", placeholder="example.com", required=True),
        Field("recipient", "Recipient to verify", placeholder="someone@example.com",
              help="Optional. Single probe only — repeated probing gets you blocked."),
        Field("starttls", "Negotiate STARTTLS", kind="checkbox", default="1"),
    ),
    run=run,
    order=130,
)
