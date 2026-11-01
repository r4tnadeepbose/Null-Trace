"""The files a site publishes about itself: robots, sitemap, security.txt, ads.txt."""

from __future__ import annotations

import re

from ..job import Field, Module
from ..net import HttpError, http, serve_url

PATHS = (
    ("/robots.txt", "Robots policy"),
    ("/sitemap.xml", "Sitemap"),
    ("/.well-known/security.txt", "Security contact"),
    ("/humans.txt", "Humans"),
    ("/ads.txt", "Authorised sellers"),
)


def run(ctx) -> None:
    target = ctx.value("target").strip()
    if not target:
        ctx.error("Enter a domain or URL.")
        return
    base = serve_url(target).rstrip("/")
    ctx.title(f"Site files — {base}")

    results: list[tuple[str, str, int, str]] = []
    for path, label in PATHS:
        ctx.check_cancel()
        ctx.status(f"Fetching {path} ...")
        try:
            response = http(base + path, timeout=15, allow_status=tuple(range(200, 600)))
        except HttpError:
            results.append((path, label, 0, ""))
            continue
        text = response.text if "text" in response.headers.get("content-type", "") else ""
        results.append((path, label, response.status_code, text))

    ctx.section("Presence")
    ctx.table(("Path", "Purpose", "Status"),
              ((path, label, f"{code}" if code else "unreachable")
               for path, label, code, _text in results))

    found = [(path, label, text) for path, label, code, text in results if code == 200 and text]
    if not found:
        ctx.warn("None of the standard files answered with content.")
        return

    for path, label, text in found:
        ctx.section(f"{label} ({path})")
        if path == "/robots.txt":
            disallow = [line for line in text.splitlines()
                        if re.match(r"^\s*disallow:", line, re.I)]
            agents = [line for line in text.splitlines()
                      if re.match(r"^\s*user-agent:", line, re.I)]
            ctx.kv("User-agent blocks", len(agents))
            ctx.kv("Disallow rules", len(disallow))
            for line in disallow[:20]:
                ctx.text(f"  {line.strip()}")
            if any("disallow: /" == line.strip().lower().replace(" ", "")
                   for line in disallow):
                ctx.note("A blanket Disallow hides the site from crawlers, not from you.")
        elif path == "/sitemap.xml":
            urls = re.findall(r"<loc>(.*?)</loc>", text)
            ctx.kv("URLs listed", len(urls))
            for url in urls[:20]:
                ctx.text(f"  {url}")
            if len(urls) > 20:
                ctx.muted(f"  … {len(urls) - 20} more")
        elif path == "/.well-known/security.txt":
            contacts = re.findall(r"^Contact:\s*(.+)$", text, re.I | re.M)
            ctx.kv("Contacts", len(contacts))
            for contact in contacts[:10]:
                ctx.text(f"  {contact}")
            expires = re.search(r"^Expires:\s*(.+)$", text, re.I | re.M)
            if expires:
                ctx.kv("Expires", expires.group(1).strip())
        else:
            lines = [line for line in text.splitlines() if line.strip()]
            ctx.kv("Lines", len(lines))
            for line in lines[:15]:
                ctx.text(f"  {line}")
            if len(lines) > 15:
                ctx.muted(f"  … {len(lines) - 15} more")

    ctx.link("robots.txt spec", "https://www.rfc-editor.org/rfc/rfc9309")
    ctx.link("security.txt spec", "https://www.rfc-editor.org/rfc/rfc9116")


MODULE = Module(
    id="site_files",
    title="Site Files",
    category="Web",
    summary="robots.txt, sitemap.xml, security.txt, humans.txt and ads.txt, parsed into a summary.",
    fields=(
        Field("target", "Domain or URL", placeholder="example.com", required=True),
    ),
    run=run,
    order=38,
)
