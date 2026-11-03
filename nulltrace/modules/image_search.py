"""Reverse image search helpers: hashes, Google Lens/CSE and manual engine links."""

from __future__ import annotations

import hashlib
import urllib.parse
from pathlib import Path

from ..job import Field, Module
from ..net import HttpError, get_json


def _hashes(path: Path) -> dict | None:
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        with Image.open(path) as image:
            info = f"{image.format} {image.width}x{image.height}"
        data = path.read_bytes()
    except OSError:
        return None
    return {
        "info": info,
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": f"{len(data) / 1024:,.1f} KB",
    }


def _cse(image_url: str, key: str, cx: str) -> list[tuple[str, str, str]]:
    data = get_json(
        "https://www.googleapis.com/customsearch/v1",
        params={"key": key, "cx": cx, "searchType": "image", "q": image_url,
                "num": 10},
        timeout=25,
    )
    return [
        (item.get("title", "?"), item.get("link", ""),
         item.get("displayLink", ""))
        for item in data.get("items", [])
    ]


def _links(url: str) -> list[tuple[str, str]]:
    quoted = urllib.parse.quote(url, safe="")
    return [
        ("Google Lens", f"https://lens.google.com/uploadbyurl?url={quoted}"),
        ("Yandex images", f"https://yandex.com/images/search?rpt=imageview&url={quoted}"),
        ("Bing visual", f"https://www.bing.com/images/search?q=imgurl:{quoted}&view=detailv2"),
        ("TinEye", f"https://tineye.com/search?url={quoted}"),
        ("Google images", f"https://www.google.com/searchbyimage?image_url={quoted}"),
    ]


def run(ctx) -> None:
    raw = ctx.value("target").strip().strip('"')
    if not raw:
        ctx.error("Enter an image URL or a local file path.")
        return
    ctx.title("Reverse image search")

    looks_local = "://" not in raw and Path(raw).expanduser().exists()
    if looks_local:
        path = Path(raw).expanduser()
        info = _hashes(path)
        if not info:
            ctx.error("Could not read that file as an image.")
            return
        ctx.section("File")
        ctx.kv("Name", path.name)
        ctx.kv("Format", info["info"])
        ctx.kv("Size", info["size"])
        ctx.kv("MD5", info["md5"])
        ctx.kv("SHA1", info["sha1"])
        ctx.kv("SHA256", info["sha256"])
        ctx.note("Upload the file manually to one of the engines below — they do not")
        ctx.note("accept a local path, and hash lookup only works for exact duplicates.")
        ctx.section("Engines")
        for label, url in (
            ("Google Lens (upload)", "https://lens.google.com/"),
            ("Yandex (upload)", "https://yandex.com/images/"),
            ("TinEye (upload)", "https://tineye.com/"),
            ("Bing visual (upload)", "https://www.bing.com/images/"),
        ):
            ctx.link(f"  {label}", url)
        return

    if "://" not in raw:
        ctx.error("That is not a URL and the file does not exist.")
        return

    ctx.section("Image URL")
    ctx.kv("URL", raw)
    try:
        from ..net import http
        head = http(raw, method="HEAD", timeout=15, allow_status=tuple(range(200, 600)))
        ctx.kv("HTTP status", head.status_code)
        ctx.kv("Content-Type", head.headers.get("content-type", "—"))
        ctx.kv("Content-Length", head.headers.get("content-length", "—"))
    except HttpError as exc:
        ctx.warn(f"Could not fetch headers: {exc}")

    key, cx = ctx.key("google_cse_key"), ctx.key("google_cse_cx")
    if key and cx:
        ctx.section("Google Custom Search (image)")
        ctx.status("Querying Google CSE ...")
        try:
            results = _cse(raw, key, cx)
        except HttpError as exc:
            ctx.error(f"CSE request failed: {exc}")
            results = []
        if results:
            ctx.table(("Title", "Source"), ((t[:60], d) for t, _u, d in results))
            for title, link, _domain in results[:10]:
                ctx.link(f"  {title[:60]}", link)
        else:
            ctx.muted("  no CSE results")
    else:
        ctx.muted("No Google CSE key/cx configured — manual engine links only.")

    ctx.section("Engines")
    for label, url in _links(raw):
        ctx.link(f"  {label}", url)

    ctx.note("Reverse image results identify near-duplicates, not necessarily the same person.")


MODULE = Module(
    id="image_search",
    title="Image Search",
    category="Media",
    summary="Hash a local image or run a URL through Google Lens, Yandex, Bing, TinEye and Google CSE.",
    fields=(
        Field("target", "Image URL or file", kind="file", placeholder="https://... or C:\\photo.jpg",
              required=True),
    ),
    keys=("google_cse_key", "google_cse_cx"),
    run=run,
    order=220,
)
