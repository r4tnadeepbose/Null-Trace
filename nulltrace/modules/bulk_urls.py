"""Check a list of URLs at once: status, title and latency."""

from __future__ import annotations

import re
import time

from ..job import Field, Module
from ..net import HttpError, http, serve_url
from ..parallel import map_parallel

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _probe(url: str) -> dict:
    started = time.time()
    try:
        response = http(serve_url(url), allow_status=tuple(range(200, 600)), timeout=15)
    except HttpError as exc:
        return {"url": url, "status": "error", "title": str(exc)[:60],
                "ms": int((time.time() - started) * 1000), "size": 0}
    match = TITLE_RE.search(response.text or "")
    title = " ".join(match.group(1).split())[:60] if match else ""
    return {
        "url": url,
        "status": response.status_code,
        "title": title,
        "ms": int((time.time() - started) * 1000),
        "size": len(response.content),
    }


def run(ctx) -> None:
    raw = ctx.value("urls")
    urls = [line.strip() for line in raw.splitlines() if line.strip()]
    if not urls:
        ctx.error("Paste one URL per line.")
        return
    if len(urls) > 100:
        ctx.warn("Only the first 100 URLs are checked.")
        urls = urls[:100]

    ctx.title("Bulk URL check")
    ctx.kv("Targets", len(urls))

    def progress(done: int, total: int) -> None:
        if done % 10 == 0 or done == total:
            ctx.status(f"Checked {done}/{total}")

    results = map_parallel(_probe, urls, workers=16,
                           should_stop=ctx.cancel_event.is_set, on_progress=progress)
    ctx.check_cancel()
    results.sort(key=lambda item: urls.index(item["url"]))

    ctx.section("Results")
    rows = [(item["url"][:46], item["status"], f"{item['ms']} ms",
             item["title"] or "—") for item in results]
    ctx.table(("URL", "Status", "Time", "Title"), rows)

    ok = sum(1 for item in results if isinstance(item["status"], int) and item["status"] < 400)
    redirects = sum(1 for item in results if isinstance(item["status"], int)
                    and 300 <= item["status"] < 400)
    errors = sum(1 for item in results if item["status"] == "error")
    broken = sum(1 for item in results if isinstance(item["status"], int)
                 and item["status"] >= 400)
    ctx.section("Summary")
    ctx.kv("OK", ok)
    ctx.kv("Redirects", redirects)
    ctx.kv("Client/server errors", broken)
    ctx.kv("Unreachable", errors)
    slow = [item for item in results if item["ms"] > 3000]
    if slow:
        ctx.warn(f"{len(slow)} URL(s) took longer than 3 seconds.")
    ctx.note("Only the status line and title are read; no content is stored.")


MODULE = Module(
    id="bulk_urls",
    title="Bulk URLs",
    category="Web",
    summary="Fetch many URLs concurrently and report status, latency and page title.",
    fields=(
        Field("urls", "URLs, one per line", kind="multiline", required=True,
              placeholder="https://example.com\nhttps://example.org/status"),
    ),
    run=run,
    order=44,
)
