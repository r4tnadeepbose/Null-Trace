"""Wayback Machine snapshots through the CDX API."""

from __future__ import annotations

import urllib.parse

from ..job import Field, Module
from ..net import HttpError, get_json

CDX = "https://web.archive.org/cdx/search/cdx"


def run(ctx) -> None:
    target = ctx.value("target").strip()
    if not target:
        ctx.error("Enter a URL or domain.")
        return
    if "://" not in target:
        target = "http://" + target
    try:
        limit = max(1, min(200, int(ctx.value("limit") or "25")))
    except ValueError:
        limit = 25

    ctx.title(f"Wayback snapshots — {target}")
    ctx.status("Querying the CDX API ...")
    params = {
        "url": target,
        "output": "json",
        "limit": str(limit),
        "collapse": "timestamp:8",
        "fl": "timestamp,original,statuscode,mimetype,length",
    }
    url = f"{CDX}?{urllib.parse.urlencode(params)}"
    try:
        rows = get_json(url, timeout=45)
    except HttpError as exc:
        ctx.error(f"CDX request failed: {exc}")
        ctx.note("The archive throttles heavily; wait a minute and retry.")
        return

    if not isinstance(rows, list) or len(rows) < 2:
        ctx.muted("No snapshots recorded for that address.")
        ctx.link("Open the archive", f"https://web.archive.org/web/*/{target}")
        return

    header = rows[0]
    body = rows[1:]
    ctx.kv("Snapshots returned", len(body))
    ctx.section("Snapshots")
    table = []
    for row in body:
        record = dict(zip(header, row, strict=False))
        stamp = record.get("timestamp", "")
        when = f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]}" if len(stamp) >= 8 else stamp
        table.append((when, record.get("statuscode", "—"),
                      record.get("mimetype", "—"), record.get("length", "—"),
                      record.get("original", "")))
    ctx.table(("Date", "Status", "Type", "Bytes", "URL"), table)

    newest = body[-1]
    last = dict(zip(header, newest, strict=False))
    ctx.section("Latest")
    ctx.kv("Captured", last.get("timestamp", "—"))
    ctx.link("Open snapshot", f"https://web.archive.org/web/{last.get('timestamp', '')}/{last.get('original', target)}")
    ctx.link("Full history", f"https://web.archive.org/web/*/{urllib.parse.quote(target)}")
    ctx.note("A snapshot is a point-in-time copy; content can differ from the live site.")


MODULE = Module(
    id="wayback",
    title="Wayback",
    category="Web",
    summary="Archived snapshots of a URL or domain from the Internet Archive CDX index.",
    fields=(
        Field("target", "URL or domain", placeholder="example.com", required=True),
        Field("limit", "Snapshots", default="25"),
    ),
    run=run,
    order=32,
)
