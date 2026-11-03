"""Email intelligence: domain infrastructure, reputation and public exposure."""

from __future__ import annotations

import hashlib
import re

from ..datasets import load_lines
from ..job import Field, Module
from ..net import EMAIL_RE, HttpError, http

_DEFAULT_DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com",
    "dispostable.com", "throwawaymail.com", "maildrop.cc", "mytemp.email",
}
DISPOSABLE = set(load_lines("disposable_domains.txt", _DEFAULT_DISPOSABLE))

PROVIDERS = {
    "gmail.com": "Google", "googlemail.com": "Google", "outlook.com": "Microsoft",
    "hotmail.com": "Microsoft", "live.com": "Microsoft", "yahoo.com": "Yahoo",
    "protonmail.com": "Proton", "proton.me": "Proton", "icloud.com": "Apple",
    "aol.com": "AOL", "gmx.com": "GMX", "zoho.com": "Zoho", "yandex.com": "Yandex",
}


def _mx(domain: str) -> list[str]:
    try:
        import dns.resolver
    except ImportError:
        return []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=10)
    except Exception:
        return []
    return [f"{r.preference} {r.exchange}".rstrip(".") for r in answers]


def _txt(domain: str) -> list[str]:
    try:
        import dns.resolver
    except ImportError:
        return []
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=10)
    except Exception:
        return []
    return [" ".join(p.decode("utf-8", "replace") for p in r.strings) for r in answers]


def _dmarc(domain: str) -> str:
    for record in _txt(f"_dmarc.{domain}"):
        if record.lower().startswith("v=dmarc1"):
            return record
    return ""


def _gravatar(email: str) -> bool | None:
    digest = hashlib.md5(email.lower().encode()).hexdigest()
    try:
        response = http(
            f"https://www.gravatar.com/avatar/{digest}?d=404&s=1",
            allow_status=(404,), timeout=8,
        )
    except HttpError:
        return None
    return response.status_code == 200


def _proton_key(email: str) -> dict | None:
    try:
        response = http(
            f"https://api.protonmail.ch/pks/lookup?op=index&search={email}",
            timeout=10, allow_status=(404,),
        )
    except HttpError:
        return None
    body = response.text
    if "info:1:0" in body:
        return {"exists": False}
    if "info:1:1" not in body:
        return None
    result: dict = {"exists": True}
    for label, pattern in (("RSA 2048", r"2048:(\d+)::"), ("RSA 4096", r"4096:(\d+)::"),
                           ("X25519", r"22:(\d+)::")):
        match = re.search(pattern, body)
        if match:
            result["encryption"] = label
            result["created"] = int(match.group(1))
            break
    return result


def _hibp(email: str, key: str) -> tuple[str, list[str]]:
    try:
        response = http(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=true",
            headers={"hibp-api-key": key, "User-Agent": "Null-Trace"},
            allow_status=(404, 401, 403, 429), timeout=15,
        )
    except HttpError as exc:
        return f"lookup failed: {exc}", []
    if response.status_code in (401, 403):
        return "API key rejected or not entitled", []
    if response.status_code == 429:
        return "rate limited by HIBP (retry in a minute)", []
    if response.status_code == 404:
        return "clean", []
    try:
        return "breached", [str(item.get("Name")) for item in response.json()]
    except ValueError:
        return "unreadable response", []


def run(ctx) -> None:
    email = ctx.value("email").lower()
    if not email:
        ctx.error("Enter an email address.")
        return
    if not EMAIL_RE.match(email):
        ctx.error("That does not look like a valid email address.")
        return

    local, domain = email.split("@", 1)
    ctx.title(f"Email intelligence — {email}")
    ctx.section("Identity")
    ctx.kv("Local part", local)
    ctx.kv("Domain", domain)
    provider = PROVIDERS.get(domain)
    ctx.kv("Provider", provider or "custom / corporate")
    ctx.kv("Disposable domain", "yes" if domain in DISPOSABLE else "no")
    ctx.kv("Gravatar profile", {True: "found", False: "not found", None: "lookup failed"}
           [_gravatar(email)])

    ctx.check_cancel()
    ctx.section("Mail infrastructure")
    records = _mx(domain)
    if records:
        for record in records:
            ctx.text(f"  MX  {record}")
    else:
        ctx.warn("  no MX records (domain cannot receive mail)")

    txts = _txt(domain)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), "")
    if spf:
        ctx.text(f"  SPF  {spf}")
        if spf.strip().lower().endswith(("~all", "-all")):
            ctx.ok("  SPF policy enforced")
        else:
            ctx.warn("  SPF present but permissive (no hard/soft fail)")
    else:
        ctx.warn("  no SPF record")

    dmarc = _dmarc(domain)
    if dmarc:
        ctx.text(f"  DMARC {dmarc}")
        ctx.ok("  DMARC present") if "p=none" not in dmarc.lower() else ctx.warn(
            "  DMARC policy is p=none (monitor only)")
    else:
        ctx.warn("  no DMARC record")

    ctx.check_cancel()
    if domain in ("protonmail.com", "proton.me"):
        ctx.section("ProtonMail PGP key")
        result = _proton_key(email)
        if result is None:
            ctx.muted("  key directory unreachable")
        elif not result["exists"]:
            ctx.error("  address is NOT registered on ProtonMail")
        else:
            ctx.ok("  address is registered")
            ctx.kv("Encryption", result.get("encryption"))
            if result.get("created"):
                from datetime import datetime
                ctx.kv("Key created", datetime.fromtimestamp(result["created"]).isoformat(sep=" "))

    ctx.check_cancel()
    ctx.section("Breach exposure")
    key = ctx.key("hibp")
    if key:
        verdict, breaches = _hibp(email, key)
        if verdict == "clean":
            ctx.ok("  no breaches found in HaveIBeenPwned")
        elif verdict == "breached":
            ctx.warn(f"  found in {len(breaches)} breach(es)")
            for name in breaches[:25]:
                ctx.text(f"  - {name}")
        else:
            ctx.muted(f"  {verdict}")
    else:
        ctx.muted("  set a HaveIBeenPwned key in Settings for breach lookups")
        ctx.link("Manual check", f"https://haveibeenpwned.com/unifiedsearch/{email}")

    ctx.section("Public footprint")
    for label, url in (
        ("Search mentions", f"https://duckduckgo.com/?q=%22{email}%22"),
        ("Google dorks", f"https://www.google.com/search?q=%22{email}%22+filetype%3Apdf"),
        ("GitHub code", f"https://github.com/search?q=%22{email}%22&type=code"),
    ):
        ctx.link(label, url)


MODULE = Module(
    id="email_intel",
    title="Email Intel",
    category="Identity",
    summary="Mail infrastructure, SPF/DMARC, Gravatar, ProtonMail key directory and breach exposure.",
    fields=(
        Field("email", "Email address", placeholder="someone@example.com", required=True),
    ),
    keys=("hibp",),
    run=run,
    order=40,
)
