"""Personal exposure audit: everything public about identifiers you own, in one report."""

from __future__ import annotations

import hashlib
import urllib.parse

from ..job import Field, Module
from ..net import EMAIL_RE, HttpError, get_json
from .email_intel import _dmarc, _gravatar, _hibp, _mx, _txt
from .infostealer import _pluck

SEVERITY_WEIGHTS = {"critical": 30, "high": 20, "medium": 10, "low": 5}


def _score(findings: list[tuple[str, str]]) -> tuple[int, str]:
    score = sum(SEVERITY_WEIGHTS.get(level, 0) for level, _text in findings)
    score = min(100, score)
    if score >= 60:
        return score, "high"
    if score >= 30:
        return score, "moderate"
    if score > 0:
        return score, "low"
    return 0, "clean"


def _hudson_rock(query: str, param: str) -> tuple[str, int]:
    try:
        data = get_json(
            f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-{param}"
            f"?{param}={urllib.parse.quote(query)}",
            timeout=30, allow_status=(404, 429),
        )
    except HttpError:
        return "lookup failed", 0
    if not isinstance(data, dict):
        return "unreadable", 0
    message, stealers = _pluck(data)
    total = data.get("total") or len(stealers)
    return message or "", int(total) if isinstance(total, int) else 0


def run(ctx) -> None:
    email = ctx.value("email").lower()
    phone = ctx.value("phone")
    name = ctx.value("name").strip()
    if not email and not phone:
        ctx.error("Enter at least an email or a phone number.")
        return

    ctx.title("Personal exposure audit")
    ctx.note("Use this on identifiers you own. It reports exposure; it does not take down data.")
    findings: list[tuple[str, str]] = []

    # ---------------------------------------------------------------- identity
    ctx.section("Identifiers")
    if email:
        if not EMAIL_RE.match(email):
            ctx.error(f"'{email}' is not a valid email address.")
            return
        local, domain = email.split("@", 1)
        ctx.kv("Email", email)
        ctx.kv("Domain", domain)
        ctx.kv("Gravatar", {True: "profile exists", False: "no profile", None: "lookup failed"}
               [_gravatar(email)])
        digest = hashlib.sha256(email.encode()).hexdigest()[:16]
        ctx.kv("Email fingerprint", digest)
    if phone:
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder
            parsed = phonenumbers.parse(phone, None)
            ctx.kv("Phone", phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
            ctx.kv("Phone country", phonenumbers.region_code_for_number(parsed))
            ctx.kv("Carrier", carrier.name_for_number(parsed, "en") or "unknown")
            ctx.kv("Region", geocoder.description_for_number(parsed, "en") or "unknown")
        except Exception as exc:
            ctx.warn(f"Phone could not be parsed: {exc}")
    if name:
        ctx.kv("Name", name)

    # ---------------------------------------------------------------- mail auth
    if email and ctx.checked("dns"):
        ctx.check_cancel()
        ctx.section("Mail domain posture")
        domain = email.split("@", 1)[1]
        mx = _mx(domain)
        ctx.kv("MX records", len(mx))
        spf = next((t for t in _txt(domain) if t.lower().startswith("v=spf1")), "")
        dmarc = _dmarc(domain)
        ctx.kv("SPF", spf or "missing")
        ctx.kv("DMARC", dmarc or "missing")
        if not dmarc:
            findings.append(("medium", "Mail domain has no DMARC policy"))
        elif "p=none" in dmarc.lower():
            findings.append(("low", "DMARC is monitor-only (p=none)"))
        if not spf:
            findings.append(("medium", "No SPF record on the mail domain"))

    # ---------------------------------------------------------------- breaches
    if email and ctx.checked("breach"):
        ctx.check_cancel()
        ctx.section("Breach exposure (HaveIBeenPwned)")
        key = ctx.key("hibp")
        if key:
            verdict, breaches = _hibp(email, key)
            if verdict == "breached":
                ctx.warn(f"Found in {len(breaches)} breach(es)")
                for breach in breaches[:30]:
                    ctx.text(f"  - {breach}")
                level = "critical" if len(breaches) >= 5 else "high"
                findings.append((level, f"Email appears in {len(breaches)} known breach(es)"))
            elif verdict == "clean":
                ctx.ok("No known breaches")
            else:
                ctx.muted(verdict)
        else:
            ctx.muted("No HIBP key — manual check below.")
            ctx.link("Check manually", f"https://haveibeenpwned.com/unifiedsearch/{email}")

    # ---------------------------------------------------------------- stealer
    if email and ctx.checked("stealer"):
        ctx.check_cancel()
        ctx.section("Infostealer logs (Hudson Rock)")
        message, total = _hudson_rock(email, "email")
        if total:
            ctx.warn(f"Mentioned in {total} infected-machine record(s)")
            if message:
                ctx.muted(message)
            findings.append(("critical", f"Email appears in {total} infostealer log(s)"))
        elif message:
            ctx.ok(message)
        else:
            ctx.muted("No stealer records found (absence is not proof of a clean machine).")

    if name and ctx.checked("stealer"):
        ctx.check_cancel()
        ctx.section("Infostealer logs by username")
        message, total = _hudson_rock(name, "username")
        if total:
            ctx.warn(f"Username appears in {total} record(s)")
            findings.append(("high", f"Username appears in {total} stealer record(s)"))
        else:
            ctx.muted(message or "no records for that username")

    # ---------------------------------------------------------------- footprint
    if ctx.checked("footprint"):
        ctx.check_cancel()
        ctx.section("Public footprint")
        links: list[tuple[str, str]] = []
        if email:
            links += [
                ("Google: exact email", f"https://www.google.com/search?q=%22{email}%22"),
                ("DuckDuckGo: exact email", f"https://duckduckgo.com/?q=%22{email}%22"),
                ("GitHub code search", f"https://github.com/search?q=%22{email}%22&type=code"),
                ("Pastebin dumps", f"https://duckduckgo.com/?q=%22{email}%22+site%3Apastebin.com"),
            ]
            ctx.link("Hudson Rock", "https://cavalier.hudsonrock.com/")
        if phone:
            links += [
                ("Truecaller (manual)", f"https://www.truecaller.com/search/in/{phone.lstrip('+')}"),
                ("Google: phone", f"https://www.google.com/search?q=%22{phone}%22"),
            ]
        if name:
            links += [
                ("Google: name", f"https://www.google.com/search?q=%22{name}%22"),
                ("LinkedIn", f"https://www.linkedin.com/search/results/all/?keywords={urllib.parse.quote(name)}"),
            ]
        for label, url in links:
            ctx.link(f"  {label}", url)
        ctx.muted("  These open in your browser — the tool does not scrape them for you.")
        findings.append(("low", "Public search footprint links generated — review manually"))

    # ---------------------------------------------------------------- summary
    ctx.check_cancel()
    score, band = _score(findings)
    ctx.section("Risk summary")
    ctx.kv("Score", f"{score}/100 ({band})")
    if findings:
        for level, text_ in sorted(findings, key=lambda f: -SEVERITY_WEIGHTS.get(f[0], 0)):
            level_fn = {"critical": ctx.error, "high": ctx.warn,
                        "medium": ctx.warn, "low": ctx.muted}[level]
            level_fn(f"  [{level.upper()}] {text_}")
    else:
        ctx.ok("No findings from the checks you enabled.")

    ctx.section("Remediation checklist")
    steps = [
        "Rotate the password on every account tied to this identifier.",
        "Revoke active sessions and API tokens after any stealer hit.",
        "Enable MFA, preferably an authenticator app or hardware key.",
        "Use a unique password manager alias per service.",
        "Request removal from data brokers and people-search sites.",
        "For exposed documents, file a takedown with the hosting provider.",
    ]
    for step in steps:
        ctx.text(f"  [ ] {step}")
    if score:
        ctx.link("Data removal guides", "https://www.privacyguides.org/en/data-redaction/")
        ctx.note("Re-run this audit after rotating credentials to confirm exposure dropped.")


MODULE = Module(
    id="exposure_audit",
    title="Exposure Audit",
    category="Identity",
    summary="Self-audit: breaches, stealer logs, mail posture and public footprint in one scored report.",
    fields=(
        Field("email", "Your email", placeholder="you@example.com",
              help="Use identifiers you own — this reports exposure, it does not remove data."),
        Field("phone", "Your phone (optional)", placeholder="+919876543210"),
        Field("name", "Your name (optional)", placeholder="Ratnadeep Bose"),
        Field("breach", "Check HaveIBeenPwned", kind="checkbox", default="1"),
        Field("stealer", "Check infostealer logs", kind="checkbox", default="1"),
        Field("dns", "Check mail domain posture", kind="checkbox", default="1"),
        Field("footprint", "Generate public footprint links", kind="checkbox", default="1"),
    ),
    keys=("hibp",),
    run=run,
    order=55,
)
