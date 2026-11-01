"""Username presence across public developer and social platforms."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from ..job import Field, Module
from ..net import HttpError, http

# name, url template, extra marker that means "account missing" in the body
PLATFORMS: list[tuple[str, str, str]] = [
    ("GitHub", "https://github.com/{u}", ""),
    ("GitLab", "https://gitlab.com/{u}", ""),
    ("Codeberg", "https://codeberg.org/{u}", ""),
    ("Bitbucket", "https://bitbucket.org/{u}/", ""),
    ("PyPI", "https://pypi.org/user/{u}/", ""),
    ("Reddit", "https://www.reddit.com/user/{u}/about.json", ""),
    ("Keybase", "https://keybase.io/{u}", ""),
    ("Hacker News", "https://news.ycombinator.com/user?id={u}", "No such user"),
    ("Docker Hub", "https://hub.docker.com/v2/users/{u}/", ""),
    ("Dev.to", "https://dev.to/api/users/by_username?url={u}", ""),
    ("Medium", "https://medium.com/@{u}", ""),
    ("SoundCloud", "https://soundcloud.com/{u}", ""),
    ("Steam", "https://steamcommunity.com/id/{u}", "could not be found"),
    ("Letterboxd", "https://letterboxd.com/{u}/", ""),
    ("Last.fm", "https://www.last.fm/user/{u}", ""),
    ("SourceHut", "https://git.sr.ht/~{u}", ""),
    ("Telegram", "https://t.me/{u}", "tgme_page_icon"),
]

FOUND, MISSING, UNKNOWN = "found", "missing", "unknown"


def _probe(name: str, template: str, marker: str, username: str) -> tuple[str, str, str]:
    url = template.format(u=username)
    try:
        response = http(url, timeout=12, allow_status=tuple(range(200, 600)))
    except HttpError as exc:
        return name, UNKNOWN, str(exc)[:60]
    status = response.status_code
    if status == 404:
        return name, MISSING, url
    if status in (401, 403, 429):
        return name, UNKNOWN, f"blocked ({status})"
    if status >= 500:
        return name, UNKNOWN, f"server error ({status})"
    if marker and marker.lower() in response.text.lower():
        return name, MISSING, url
    if name == "Telegram":
        # t.me renders a contact page only for existing handles
        return name, (FOUND if "tgme_page_title" in response.text else MISSING), url
    if status in (200, 301, 302):
        return name, FOUND, url
    return name, UNKNOWN, f"HTTP {status}"


def run(ctx) -> None:
    username = ctx.value("username").strip().lstrip("@")
    if not username:
        ctx.error("Enter a username.")
        return
    chosen = ctx.value("scope") or "All"
    platforms = PLATFORMS if chosen == "All" else [
        p for p in PLATFORMS if p[0] == chosen
    ]
    ctx.title(f"Username scan — @{username}")
    ctx.kv("Platforms checked", len(platforms))
    ctx.muted("Only public profile pages are requested; nothing is scraped beyond existence.")

    results: list[tuple[str, str, str]] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_probe, name, template, marker, username)
                   for name, template, marker in platforms]
        for future in as_completed(futures):
            if ctx.cancel_event.is_set():
                for pending in futures:
                    pending.cancel()
                ctx.check_cancel()
            results.append(future.result())

    order = {name: index for index, (name, _t, _m) in enumerate(platforms)}
    results.sort(key=lambda r: order.get(r[0], 99))

    ctx.section("Results")
    ctx.table(("Platform", "Status", "URL"),
              ((name, {"found": "FOUND", "missing": "-", "unknown": "?  "}[status], url)
               for name, status, url in results))

    found = [(name, url) for name, status, url in results if status == FOUND]
    unknown = [name for name, status, _ in results if status == UNKNOWN]
    ctx.section("Summary")
    ctx.kv("Found", len(found))
    ctx.kv("Not found", sum(1 for _n, s, _u in results if s == MISSING))
    ctx.kv("Inconclusive", len(unknown))
    if found:
        for name, url in found:
            ctx.link(f"  {name}", url)
    if unknown:
        ctx.muted(f"Blocked or ambiguous: {', '.join(unknown)}")
    ctx.note("A matched handle is not proof of a shared owner — people reuse names.")


MODULE = Module(
    id="username_scan",
    title="Username Scan",
    category="Identity",
    summary="Check whether a handle exists on 20 developer and social platforms, with profile links.",
    fields=(
        Field("username", "Username", placeholder="r4tnadeepbose", required=True),
        Field("scope", "Scope", kind="choice",
              choices=("All", *(p[0] for p in PLATFORMS)), default="All"),
    ),
    run=run,
    order=65,
)
