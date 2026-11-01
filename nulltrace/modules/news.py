"""News monitoring: NewsAPI when a key exists, Google News RSS otherwise."""

from __future__ import annotations

import urllib.parse
import xml.etree.ElementTree as ET

from ..job import Field, Module
from ..net import HttpError, get_json, http


def _newsapi(query: str, key: str, limit: int) -> list[tuple[str, str, str, str]]:
    data = get_json(
        "https://newsapi.org/v2/everything",
        params={"q": query, "pageSize": limit, "sortBy": "publishedAt",
                "language": "en"},
        headers={"X-Api-Key": key},
        timeout=25,
    )
    return [
        (a.get("publishedAt", "")[:16].replace("T", " "), a.get("source", {}).get("name", "?"),
         a.get("title", "?"), a.get("url", ""))
        for a in data.get("articles", [])
    ]


def _google_rss(query: str, limit: int) -> list[tuple[str, str, str, str]]:
    url = ("https://news.google.com/rss/search?q=" + urllib.parse.quote_plus(query) +
           "&hl=en-US&gl=US&ceid=US:en")
    response = http(url, timeout=25)
    try:
        root = ET.fromstring(response.content)
    except ET.ParseError as exc:
        raise HttpError(f"RSS parse error: {exc}") from exc
    rows = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "?").strip()
        link = (item.findtext("link") or "").strip()
        published = (item.findtext("pubDate") or "").strip()
        source_el = item.find("source")
        source = (source_el.text if source_el is not None and source_el.text else "Google News")
        rows.append((published[:22], source, title, link))
        if len(rows) >= limit:
            break
    return rows


def run(ctx) -> None:
    query = ctx.value("query").strip()
    if not query:
        ctx.error("Enter a search query.")
        return
    try:
        limit = max(1, min(50, int(ctx.value("limit") or "15")))
    except ValueError:
        limit = 15
    ctx.title(f"News search — {query}")

    key = ctx.key("newsapi")
    rows: list[tuple[str, str, str, str]] = []
    source = ""
    if key:
        ctx.status("Querying NewsAPI ...")
        try:
            rows = _newsapi(query, key, limit)
            source = "NewsAPI"
        except HttpError as exc:
            ctx.warn(f"NewsAPI failed ({exc}) — falling back to Google News RSS.")
    if not rows:
        ctx.status("Querying Google News RSS ...")
        try:
            rows = _google_rss(query, limit)
            source = "Google News RSS"
        except HttpError as exc:
            ctx.error(f"News lookup failed: {exc}")
            return

    ctx.kv("Source", source)
    ctx.kv("Articles", len(rows))
    if not rows:
        ctx.warn("No articles matched.")
        return

    for published, publisher, title, link in rows[:limit]:
        ctx.check_cancel()
        ctx.text(f"{published or '—'}  [{publisher}]")
        ctx.text(f"  {title}")
        if link:
            ctx.link("    read", link)
        ctx.text("")

    ctx.note("News coverage is not verification. Corroborate claims before acting on them.")


MODULE = Module(
    id="news",
    title="News",
    category="Web",
    summary="Search recent coverage for a person, company or keyword; uses NewsAPI when configured.",
    fields=(
        Field("query", "Query", placeholder='"Example Corp" breach', required=True),
        Field("limit", "Max articles", default="15"),
    ),
    keys=("newsapi",),
    run=run,
    order=210,
)
