"""Cookie flag audit for a site's response headers."""

from __future__ import annotations

from http.cookies import CookieError, SimpleCookie

from ..job import Field, Module
from ..net import HttpError, http, serve_url


def parse_cookies(headers: list[str]) -> list[dict]:
    """Turn raw Set-Cookie lines into a list of attribute dictionaries."""
    cookies: list[dict] = []
    for raw in headers:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            continue
        for name, morsel in cookie.items():
            cookies.append({
                "name": name,
                "value": morsel.value,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": (morsel["samesite"] or "unset"),
                "domain": morsel["domain"] or "",
                "path": morsel["path"] or "",
                "expires": morsel["expires"] or "",
                "max_age": morsel["max-age"] or "",
            })
    return cookies


def _issues(cookie: dict) -> list[str]:
    issues = []
    if not cookie["secure"]:
        issues.append("no Secure")
    if not cookie["httponly"]:
        issues.append("no HttpOnly")
    samesite = cookie["samesite"].lower()
    if samesite in ("", "unset"):
        issues.append("no SameSite")
    elif samesite == "none" and not cookie["secure"]:
        issues.append("SameSite=None without Secure")
    if cookie["max_age"]:
        try:
            if int(cookie["max_age"]) > 60 * 60 * 24 * 365:
                issues.append("lifetime over a year")
        except ValueError:
            pass
    return issues


def run(ctx) -> None:
    target = ctx.value("url").strip()
    if not target:
        ctx.error("Enter a URL.")
        return
    url = serve_url(target)
    ctx.title(f"Cookie audit — {url}")
    ctx.status("Fetching response headers ...")
    try:
        response = http(url, allow_status=tuple(range(200, 600)), timeout=20)
    except HttpError as exc:
        ctx.error(f"Request failed: {exc}")
        return

    raw = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    if not raw:
        raw = [v for k, v in response.headers.items() if k.lower() == "set-cookie"]
    cookies = parse_cookies(raw)
    ctx.kv("Set-Cookie headers", len(raw))
    ctx.kv("Cookies parsed", len(cookies))
    if not cookies:
        ctx.ok("No cookies set on the first response.")
        ctx.note("Session cookies often appear after login; test an authenticated page too.")
        return

    ctx.section("Cookies")
    rows = []
    for cookie in cookies:
        rows.append((
            cookie["name"][:22],
            "yes" if cookie["secure"] else "NO",
            "yes" if cookie["httponly"] else "NO",
            cookie["samesite"],
            cookie["domain"] or "host-only",
        ))
    ctx.table(("Name", "Secure", "HttpOnly", "SameSite", "Domain"), rows)

    ctx.section("Findings")
    weak = 0
    for cookie in cookies:
        issues = _issues(cookie)
        if issues:
            weak += 1
            ctx.warn(f"  {cookie['name']}: {', '.join(issues)}")
        else:
            ctx.ok(f"  {cookie['name']}: flags look correct")

    ctx.section("Summary")
    ctx.kv("Cookies with weak flags", f"{weak}/{len(cookies)}")
    if weak == 0:
        ctx.ok("Every cookie sets Secure, HttpOnly and SameSite.")
    else:
        ctx.note("HttpOnly stops script access; Secure stops plaintext leaks; SameSite limits CSRF.")
    if any(not c["secure"] for c in cookies) and url.startswith("https://"):
        ctx.error("Cookies travel without Secure on an HTTPS page — a downgrade can expose them.")

    ctx.link("MDN Set-Cookie", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie")


MODULE = Module(
    id="cookie_audit",
    title="Cookie Audit",
    category="Web",
    summary="Parse Set-Cookie headers and flag missing Secure, HttpOnly, SameSite or bad lifetimes.",
    fields=(
        Field("url", "URL", placeholder="https://example.com", required=True),
    ),
    run=run,
    order=42,
)
