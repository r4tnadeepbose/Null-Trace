"""Dark web search via Ahmia, optionally routed through a local Tor SOCKS proxy."""

from __future__ import annotations

import re
import urllib.parse

from bs4 import BeautifulSoup

from ..config import CONFIG
from ..job import Field, Module
from ..net import HttpError, http, new_session

CLEARNET = "https://ahmia.fi"
ONION = ("http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion")
TOKEN_RE = re.compile(r'name="([0-9a-f]{6})"\s+value="([0-9a-f]+)"')


def _has_socks() -> bool:
    try:
        import socks  # noqa: F401
        return True
    except ImportError:
        return False


def _parse(html: str) -> list[tuple[str, str, str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    results = []
    for item in soup.select("li.result"):
        link = item.find("a", href=True)
        if not link:
            continue
        title = " ".join(link.get_text(" ", strip=True).split()) or "(untitled)"
        href = link["href"]
        query = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
        target = (query.get("redirect_url") or [""])[0]
        snippet_tag = item.find("p")
        snippet = " ".join(snippet_tag.get_text(" ", strip=True).split()) if snippet_tag else ""
        cite = item.find("cite")
        domain = cite.get_text(strip=True) if cite else ""
        results.append((title, target or href, snippet, domain))
    return results


def _search(base: str, query: str, proxy: str | None) -> tuple[list, str]:
    session = new_session()
    landing = http(f"{base}/search/", proxy=proxy, session=session, timeout=45)
    token = TOKEN_RE.search(landing.text)
    params = {"q": query}
    if token:
        params[token.group(1)] = token.group(2)
    response = http(f"{base}/search/", params=params, proxy=proxy, session=session,
                    timeout=60, allow_status=(429, 503))
    if response.status_code != 200:
        raise HttpError(f"Ahmia returned {response.status_code}")
    return _parse(response.text), str(response.url)


def run(ctx) -> None:
    query = ctx.value("query").strip()
    if not query:
        ctx.error("Enter a search query.")
        return
    use_tor = ctx.checked("tor")
    ctx.title(f"Dark web search — {query}")
    ctx.muted("Ahmia indexes onion services that its crawler considers legal. Results are")
    ctx.muted("unverified; never open unknown onion links outside an isolated environment.")

    proxy = CONFIG.tor_proxy if use_tor else None
    source = "Ahmia (onion via Tor)" if use_tor else "Ahmia (clearnet)"
    if use_tor and not _has_socks():
        ctx.error("PySocks is not installed — run: pip install requests[socks]")
        return
    if use_tor:
        ctx.note(f"Routing through Tor at {proxy}")

    ctx.status("Querying Ahmia ...")
    try:
        results, final_url = _search(ONION if use_tor else CLEARNET, query, proxy)
    except HttpError as exc:
        ctx.error(f"Search failed: {exc}")
        if use_tor:
            ctx.note("Is the Tor service running on 127.0.0.1:9050?")
        else:
            ctx.note("Ahmia rate limits aggressively — wait a minute and retry.")
        return

    ctx.kv("Source", source)
    ctx.kv("Results", len(results))
    if not results:
        ctx.warn("No results parsed — Ahmia may have returned its landing page.")
        ctx.link("Open in browser", final_url)
        return

    ctx.section("Results")
    for index, (title, link, snippet, domain) in enumerate(results[:25], start=1):
        ctx.check_cancel()
        ctx.text(f"{index:>2}. {title}")
        if domain:
            ctx.muted(f"    {domain}")
        if link.startswith("/"):
            link = CLEARNET + link
        ctx.link("    open via Ahmia", link)
        if snippet:
            ctx.muted(f"    {snippet[:220]}")

    ctx.section("Safety")
    ctx.note("Do not follow links that solicit illegal content. Possession of such material is")
    ctx.note("a criminal offence in most jurisdictions, regardless of how you found it.")


MODULE = Module(
    id="darkweb",
    title="Dark Web Search",
    category="Web",
    summary="Query Ahmia for indexed onion services, over clearnet or through a local Tor SOCKS proxy.",
    fields=(
        Field("query", "Query", placeholder="leaked database", required=True),
        Field("tor", "Route through Tor (requires tor on 127.0.0.1:9050)", kind="checkbox",
              default="0"),
    ),
    run=run,
    order=150,
)
