"""Google dork builder with a curated catalogue and search-engine links."""

from __future__ import annotations

import urllib.parse

from ..datasets import load_json
from ..job import Field, Module

ENGINES = {
    "Google": "https://www.google.com/search?q={q}",
    "Bing": "https://www.bing.com/search?q={q}",
    "DuckDuckGo": "https://duckduckgo.com/?q={q}",
}

_DEFAULT_CATALOG: dict[str, list[str]] = {
    "Exposed documents": [
        'site:{d} ext:pdf', 'site:{d} ext:xlsx OR ext:xls OR ext:csv',
        'site:{d} ext:docx OR ext:doc', 'site:{d} ext:pptx OR ext:ppt',
        'site:{d} intitle:"index of"', 'site:{d} inurl:backup',
    ],
    "Config & secrets": [
        'site:{d} ext:env OR ext:ini OR ext:cfg', 'site:{d} inurl:.git/config',
        'site:{d} "BEGIN RSA PRIVATE KEY"', 'site:{d} intext:"api_key" OR intext:"apikey"',
        'site:{d} intext:"password" filetype:txt',
    ],
    "Admin & login panels": [
        'site:{d} inurl:admin', 'site:{d} inurl:login OR inurl:signin',
        'site:{d} intitle:"dashboard"', 'site:{d} inurl:phpmyadmin',
        'site:{d} intitle:"phpMyAdmin" OR intitle:"Adminer"',
    ],
    "Devices & cameras": [
        'inurl:"/view/index.shtml"', 'intitle:"Network Camera" inurl:view',
        'inurl:8080 intitle:"DVR"', 'intitle:"webcamXP"',
    ],
    "People & contacts": [
        'site:{d} "@{d}"', 'site:linkedin.com "{d}"', 'site:github.com "{d}"',
        'site:{d} intext:"@gmail.com"',
    ],
    "Vulnerable stacks": [
        'site:{d} intitle:"Jenkins"', 'site:{d} inurl:wp-content',
        'site:{d} intitle:"Grafana"', 'site:{d} intitle:"Kibana"',
        'site:{d} "Index of /" intext:"Parent Directory"',
    ],
    "Subdomains & staging": [
        'site:*.{d} -site:www.{d}', 'site:{d} inurl:staging OR inurl:dev OR inurl:test',
        'site:{d} inurl:api', 'site:{d} inurl:internal',
    ],
}
CATALOG: dict[str, list[str]] = load_json("dorks.json", _DEFAULT_CATALOG)


def _clean_domain(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = value.split("//", 1)[1]
    return value.split("/")[0].lstrip(".") or "example.com"


def run(ctx) -> None:
    domain = _clean_domain(ctx.value("domain") or "example.com")
    extra = ctx.value("terms")
    category = ctx.value("category") or "All"
    engine = ctx.value("engine") or "Google"
    template = ENGINES.get(engine, ENGINES["Google"])
    limit = 4
    try:
        limit = max(1, min(20, int(ctx.value("limit") or "4")))
    except ValueError:
        pass

    ctx.title(f"Dork set — {domain}")
    ctx.kv("Engine", engine)
    if extra:
        ctx.kv("Extra terms", extra)

    categories = list(CATALOG) if category == "All" else [category]
    total = 0
    for name in categories:
        ctx.section(name)
        for dork in CATALOG[name][:limit]:
            ctx.check_cancel()
            query = dork.format(d=domain)
            if extra:
                query = f"{query} {extra}"
            url = template.format(q=urllib.parse.quote_plus(query))
            ctx.link(f"  {query}", url)
            total += 1

    ctx.section("Custom")
    manual = f"site:{domain} {extra}".strip()
    ctx.link(f"  {manual}", template.format(q=urllib.parse.quote_plus(manual)))
    ctx.kv("Dorks generated", total + 1)

    ctx.note("Dorks only surface what a search engine already indexed. Request removal rather")
    ctx.note("than exploiting anything you find, and stay inside your authorisation.")


MODULE = Module(
    id="dorks",
    title="Google Dorks",
    category="Web",
    summary="Generate targeted dork queries for a domain and open them in Google, Bing or DuckDuckGo.",
    fields=(
        Field("domain", "Domain or site", placeholder="example.com", required=True),
        Field("terms", "Extra terms", placeholder='intext:"internal use"'),
        Field("category", "Category", kind="choice", choices=("All", *CATALOG), default="All"),
        Field("engine", "Engine", kind="choice", choices=tuple(ENGINES), default="Google"),
        Field("limit", "Dorks per category", default="4"),
    ),
    run=run,
    order=120,
)
