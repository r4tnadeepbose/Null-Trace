"""CORS configuration check for a single endpoint."""

from __future__ import annotations

from ..job import Field, Module
from ..net import HttpError, http, serve_url


def run(ctx) -> None:
    target = ctx.value("url").strip()
    if not target:
        ctx.error("Enter a URL.")
        return
    url = serve_url(target)
    origin = ctx.value("origin").strip() or "https://nulltrace.invalid"

    ctx.title(f"CORS check — {url}")
    ctx.kv("Test origin", origin)
    ctx.muted("Only an authorised endpoint should be probed. The request is a normal GET.")

    ctx.section("Simple request")
    try:
        response = http(url, headers={"Origin": origin},
                        allow_status=tuple(range(200, 600)), timeout=20)
    except HttpError as exc:
        ctx.error(f"Request failed: {exc}")
        return
    ctx.kv("Status", response.status_code)
    allow_origin = response.headers.get("access-control-allow-origin", "")
    allow_creds = response.headers.get("access-control-allow-credentials", "")
    vary = response.headers.get("vary", "")
    ctx.kv("Access-Control-Allow-Origin", allow_origin or "—")
    ctx.kv("Allow-Credentials", allow_creds or "—")
    ctx.kv("Vary", vary or "—")

    ctx.check_cancel()
    ctx.section("Preflight (OPTIONS)")
    preflight_origin = ""
    try:
        preflight = http(url, method="OPTIONS",
                         headers={"Origin": origin,
                                  "Access-Control-Request-Method": "GET"},
                         allow_status=tuple(range(200, 600)), timeout=20)
        preflight_origin = preflight.headers.get("access-control-allow-origin", "")
        ctx.kv("Status", preflight.status_code)
        ctx.kv("Allow-Origin", preflight_origin or "—")
        ctx.kv("Allow-Methods", preflight.headers.get("access-control-allow-methods", "—"))
        ctx.kv("Allow-Headers", preflight.headers.get("access-control-allow-headers", "—"))
        ctx.kv("Max-Age", preflight.headers.get("access-control-max-age", "—"))
    except HttpError as exc:
        ctx.muted(f"Preflight failed: {exc}")

    ctx.section("Verdict")
    effective = (allow_origin or preflight_origin or "").strip()
    if not effective:
        ctx.ok("No CORS headers — browsers will block cross-origin reads.")
    elif effective == "*" and allow_creds.lower() == "true":
        ctx.error("Wildcard origin with credentials is invalid and dangerous.")
    elif effective == "*":
        ctx.warn("Any origin may read this response (no credentials). Fine for public data only.")
    elif effective == origin:
        ctx.warn("The endpoint reflects an arbitrary origin — cross-origin reads are allowed.")
        if allow_creds.lower() == "true":
            ctx.error("And credentials are allowed: any site can act as a logged-in user.")
    elif effective == "null":
        ctx.warn("Origin 'null' is allowed — sandboxed frames and file:// pages can read it.")
    else:
        ctx.muted(f"Only {effective} is allowed; the test origin was rejected.")

    if "origin" not in vary.lower():
        ctx.note("Vary is missing 'Origin' — shared caches can serve the wrong CORS header.")

    ctx.link("MDN CORS", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS")


MODULE = Module(
    id="cors_check",
    title="CORS Check",
    category="Web",
    summary="Send a foreign Origin and report whether the endpoint reflects it or allows credentials.",
    fields=(
        Field("url", "Endpoint", placeholder="https://api.example.com/v1/me", required=True),
        Field("origin", "Test origin", placeholder="https://nulltrace.invalid"),
    ),
    run=run,
    order=40,
)
