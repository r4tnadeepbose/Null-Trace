"""Host / web service recon: headers, TLS, technology fingerprints, security posture."""

from __future__ import annotations

import re

from ..datasets import load_json
from ..job import Field, Module
from ..net import HttpError, http, serve_url, tls_certificate

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing — HTTPS not pinned for future visits",
    "content-security-policy": "No CSP — XSS mitigation weakened",
    "x-frame-options": "No X-Frame-Options — clickjacking protection missing",
    "x-content-type-options": "No X-Content-Type-Options — MIME sniffing possible",
    "referrer-policy": "No Referrer-Policy — referrer leaks to third parties",
    "permissions-policy": "No Permissions-Policy — browser features unrestricted",
}

_DEFAULT_TECH_SIGNATURES = {
    "cloudflare": "Cloudflare", "nginx": "Nginx", "apache": "Apache", "iis": "Microsoft IIS",
    "litespeed": "LiteSpeed", "openresty": "OpenResty", "caddy": "Caddy",
    "express": "Express.js", "next.js": "Next.js", "nuxt": "Nuxt", "react": "React",
    "vue": "Vue.js", "angular": "Angular", "jquery": "jQuery", "bootstrap": "Bootstrap",
    "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla", "shopify": "Shopify",
    "wix": "Wix", "squarespace": "Squarespace", "django": "Django", "laravel": "Laravel",
    "php": "PHP", "asp.net": "ASP.NET", "tomcat": "Tomcat", "grafana": "Grafana",
    "jenkins": "Jenkins", "gitlab": "GitLab", "github pages": "GitHub Pages",
    "google analytics": "Google Analytics", "gtag": "Google Tag", "hotjar": "Hotjar",
    "hubspot": "HubSpot", "sentry": "Sentry", "stripe": "Stripe", "recaptcha": "reCAPTCHA",
}
TECH_SIGNATURES = load_json("tech_signatures.json", _DEFAULT_TECH_SIGNATURES)


def run(ctx) -> None:
    target = ctx.value("target")
    if not target:
        ctx.error("Enter a URL or hostname.")
        return
    url = serve_url(target)
    ctx.title(f"Host recon — {url}")
    ctx.status("Fetching headers ...")
    try:
        response = http(url, allow_status=tuple(range(200, 600)), timeout=20)
    except HttpError as exc:
        ctx.error(f"Request failed: {exc}")
        return

    ctx.section("Response")
    ctx.kv("Final URL", response.url)
    ctx.kv("Status", f"{response.status_code} {response.reason}")
    ctx.kv("Server", response.headers.get("server", "—"))
    ctx.kv("Content-Type", response.headers.get("content-type", "—"))
    ctx.kv("Content-Length", f"{len(response.content) / 1024:,.1f} KB")
    if response.history:
        ctx.kv("Redirects", " -> ".join(r.url for r in response.history))

    ctx.section("Headers")
    for name, value in response.headers.items():
        ctx.kv(name, value)

    ctx.section("Security posture")
    lower = {k.lower(): v for k, v in response.headers.items()}
    missing = 0
    for header, warning in SECURITY_HEADERS.items():
        if header in lower:
            ctx.ok(f"  {header}: {lower[header]}")
        else:
            missing += 1
            ctx.warn(f"  {warning}")
    if missing == 0:
        ctx.ok("All checked security headers are present.")

    ctx.check_cancel()
    if ctx.checked("tls"):
        ctx.section("TLS certificate")
        host = response.url.split("//", 1)[-1].split("/")[0].split(":")[0]
        try:
            cert = tls_certificate(host)
            if cert.get("verified") is False:
                ctx.warn("  certificate did NOT verify against the system trust store")
            subject = dict(x[0] for x in cert["subject"] or [])
            issuer = dict(x[0] for x in cert["issuer"] or [])
            ctx.kv("Subject CN", subject.get("commonName") or "—")
            ctx.kv("Issuer", issuer.get("organizationName") or issuer.get("commonName") or "—")
            ctx.kv("Valid from", cert["not_before"] or "—")
            ctx.kv("Valid until", cert["not_after"] or "—")
            ctx.kv("Protocol", cert["version"])
            ctx.kv("Cipher", cert["cipher"])
            san = [v for k, v in (cert.get("san") or []) if k == "DNS"]
            if san:
                ctx.kv("SANs", ", ".join(san[:20]))
        except Exception as exc:
            ctx.warn(f"  TLS probe failed: {exc}")

    ctx.check_cancel()
    ctx.section("Technology fingerprints")
    haystack = (str(response.headers) + response.text[:20000]).lower()
    found = sorted({name for token, name in TECH_SIGNATURES.items() if token in haystack})
    if found:
        for name in found:
            ctx.text(f"  {name}")
    else:
        ctx.muted("  no obvious fingerprints")

    match = re.search(r"<title[^>]*>(.*?)</title>", response.text, re.I | re.S)
    if match:
        ctx.kv("Page title", " ".join(match.group(1).split())[:160])

    ctx.check_cancel()
    ctx.section("Well-known paths")
    base = response.url.rstrip("/")
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.git/config"):
        ctx.check_cancel()
        try:
            probe = http(base + path, allow_status=tuple(range(200, 600)), timeout=10)
        except HttpError:
            ctx.muted(f"  {path:<30} unreachable")
            continue
        marker = "exposed" if probe.status_code == 200 and len(probe.content) > 0 else "—"
        level = ctx.warn if path == "/.git/config" and marker == "exposed" else ctx.text
        level(f"  {path:<30} {probe.status_code}   {marker}")


MODULE = Module(
    id="host_search",
    title="Host Search",
    category="Web",
    summary="HTTP headers, redirects, TLS certificate, tech fingerprints and exposed well-known paths.",
    fields=(
        Field("target", "URL or hostname", placeholder="https://example.com", required=True),
        Field("tls", "Inspect TLS certificate", kind="checkbox", default="1"),
    ),
    run=run,
    order=80,
)
