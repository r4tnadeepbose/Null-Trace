"""URL inspection: redirect chain, final destination, host reputation signals."""

from __future__ import annotations

import re
import urllib.parse

from ..job import Field, Module
from ..net import HttpError, http, resolve, serve_url, tls_certificate

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in", "bit.do", "soo.gd",
}
SUSPICIOUS = ("login", "verify", "secure", "update", "account", "billing", "wallet",
              "unlock", "recover", "confirm", "invoice", "signin", "auth")


def _looks_punycode(host: str) -> bool:
    return "xn--" in host


def run(ctx) -> None:
    raw = ctx.value("url").strip()
    if not raw:
        ctx.error("Enter a URL.")
        return
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urllib.parse.urlparse(raw)
    host = parsed.hostname or ""
    ctx.title("URL inspector")
    ctx.kv("Input", raw)
    ctx.kv("Scheme", parsed.scheme)
    ctx.kv("Host", host)
    ctx.kv("Path", parsed.path or "/")
    if parsed.query:
        ctx.kv("Query", parsed.query[:200])
    if parsed.port:
        ctx.kv("Port", parsed.port)

    ctx.check_cancel()
    ctx.section("Resolution")
    addresses = resolve(host)
    ctx.kv("Addresses", ", ".join(addresses) or "unresolved")
    if _looks_punycode(host):
        ctx.warn("Host uses punycode (xn--) — possible homograph/lookalike domain.")
    if host in SHORTENERS:
        ctx.warn("Known URL shortener — the real destination is hidden until expanded.")

    ctx.check_cancel()
    ctx.section("Redirect chain")
    chain: list[tuple[str, str]] = []
    current = raw
    seen: set[str] = set()
    for _ in range(12):
        if current in seen:
            ctx.warn("Redirect loop detected.")
            break
        seen.add(current)
        try:
            response = http(current, method="GET", timeout=15, stream=True,
                            allow_status=tuple(range(200, 600)))
            status = f"{response.status_code} {response.reason}"
            location = response.headers.get("location")
            response.close()
        except HttpError as exc:
            ctx.error(f"{current} -> {exc}")
            break
        chain.append((current, status))
        if 300 <= int(status.split()[0]) < 400 and location:
            current = urllib.parse.urljoin(current, location)
            continue
        break

    for index, (url, status) in enumerate(chain, start=1):
        ctx.text(f"  {index}. [{status}] {url}")
    if not chain:
        ctx.muted("  no response")

    final = chain[-1][0] if chain else raw
    final_host = urllib.parse.urlparse(final).hostname or host
    ctx.kv("Final URL", final)
    ctx.kv("Final host", final_host)
    if final_host != host:
        ctx.warn(f"Destination changed domain: {host} -> {final_host}")

    ctx.check_cancel()
    ctx.section("Destination")
    try:
        head = http(final, method="HEAD", timeout=15, allow_status=tuple(range(200, 600)))
        ctx.kv("Status", f"{head.status_code} {head.reason}")
        ctx.kv("Server", head.headers.get("server", "—"))
        ctx.kv("Content-Type", head.headers.get("content-type", "—"))
    except HttpError as exc:
        ctx.muted(f"  HEAD failed: {exc}")

    if final.startswith("https://"):
        try:
            cert = tls_certificate(final_host)
            issuer = dict(x[0] for x in cert.get("issuer") or [])
            ctx.kv("TLS issuer", issuer.get("organizationName") or "—")
            ctx.kv("TLS valid until", cert.get("not_after") or "—")
            if cert.get("verified") is False:
                ctx.warn("Certificate does not validate — do not enter credentials.")
        except Exception as exc:
            ctx.muted(f"  TLS probe failed: {exc}")

    ctx.section("Risk signals")
    signals = 0
    lowered = final.lower()
    hits = [word for word in SUSPICIOUS if word in lowered]
    if hits:
        signals += 1
        ctx.warn(f"  Suspicious keywords in URL: {', '.join(hits)}")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", final_host or ""):
        signals += 1
        ctx.warn("  Host is a raw IP address, not a domain name.")
    if len(final) > 120:
        signals += 1
        ctx.warn("  Unusually long URL (obfuscation tactic).")
    if "@" in parsed.netloc:
        signals += 1
        ctx.warn("  URL contains '@' in the authority — classic credential-spoof trick.")
    if signals == 0:
        ctx.ok("  No obvious structural red flags (not a guarantee of safety).")

    ctx.link("VirusTotal (manual)", f"https://www.virustotal.com/gui/url/{final}")
    ctx.link("Google Safe Browsing", "https://transparencyreport.google.com/safe-browsing/search")
    ctx.note("Short links and redirects are resolved by following them — some trackers log the visit.")


MODULE = Module(
    id="url_inspector",
    title="URL Inspector",
    category="Web",
    summary="Expand short links, follow the redirect chain, and flag homograph or phishing patterns.",
    fields=(
        Field("url", "URL", placeholder="https://bit.ly/abc123", required=True),
    ),
    run=run,
    order=35,
)
