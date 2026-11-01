"""Subdomain takeover signals: dangling CNAMEs pointing at abandoned services."""

from __future__ import annotations

from ..job import Field, Module
from ..net import HttpError, http

# service suffix -> (label, markers that mean "this host no longer exists")
SERVICES = {
    "github.io": ("GitHub Pages", ["There isn't a GitHub Pages site here"]),
    "herokuapp.com": ("Heroku", ["No such app", "heroku | no such app"]),
    "s3.amazonaws.com": ("Amazon S3", ["NoSuchBucket", "The specified bucket does not exist"]),
    "cloudfront.net": ("CloudFront", ["Bad request", "ERROR: The request could not be satisfied"]),
    "azurewebsites.net": ("Azure App Service", ["404 Web Site not found"]),
    "cloudapp.azure.com": ("Azure VM", ["404 Not Found"]),
    "netlify.app": ("Netlify", ["Not Found - Request ID"]),
    "netlify.com": ("Netlify", ["Not Found - Request ID"]),
    "vercel.app": ("Vercel", ["DEPLOYMENT_NOT_FOUND", "The deployment could not be found"]),
    "pages.dev": ("Cloudflare Pages", ["project not found", "Could not find"]),
    "webflow.io": ("Webflow", ["The page you are looking for doesn't exist"]),
    "readthedocs.io": ("Read the Docs", ["unknown to Read the Docs"]),
    "surge.sh": ("Surge", ["project not found"]),
    "bitbucket.io": ("Bitbucket", ["Repository not found"]),
    "ghost.io": ("Ghost", ["Site not found"]),
    "tumblr.com": ("Tumblr", ["There's nothing here."]),
    "myshopify.com": ("Shopify", ["Sorry, this shop is currently unavailable"]),
    "wpengine.com": ("WP Engine", ["Site Not Found"]),
    "teamwork.com": ("Teamwork", ["Trouble finding"]),
    "zendesk.com": ("Zendesk", ["Help Center Closed"]),
}


def _cname_chain(host: str) -> list[str]:
    try:
        import dns.resolver
    except ImportError:
        return []
    chain: list[str] = []
    current = host
    for _ in range(6):
        try:
            answer = dns.resolver.resolve(current, "CNAME", lifetime=8)
        except Exception:
            break
        target = str(answer[0].target).rstrip(".")
        if target in chain:
            break
        chain.append(target)
        current = target
    return chain


def run(ctx) -> None:
    host = ctx.value("host").strip().lower().lstrip(".")
    if not host:
        ctx.error("Enter a hostname.")
        return
    ctx.title(f"Subdomain takeover — {host}")

    ctx.status("Tracing CNAMEs ...")
    chain = _cname_chain(host)
    if chain:
        ctx.section("CNAME chain")
        for index, step in enumerate(chain):
            ctx.text(f"  {step}" if index == 0 else f"  →  {step}")
    else:
        ctx.section("CNAME chain")
        ctx.muted("No CNAME records — the host is not delegated to a third party.")

    target = chain[-1] if chain else host
    service = next((SERVICES[suffix] for suffix in SERVICES if target.endswith(suffix)), None)

    ctx.section("Assessment")
    if not service:
        ctx.ok("No known takeover-prone service in the chain.")
        ctx.note("Only CNAME-based takeovers are checked; A records and dangling NS are not.")
        return

    label, markers = service
    ctx.kv("Service", label)
    ctx.kv("Dangling target", target)

    found = False
    checked = False
    for scheme in ("https", "http"):
        if found:
            break
        try:
            response = http(f"{scheme}://{host}", allow_status=tuple(range(200, 600)), timeout=15)
        except HttpError:
            continue
        checked = True
        body = response.text[:4000]
        hit = next((marker for marker in markers if marker.lower() in body.lower()), None)
        if hit:
            found = True
            ctx.error(f"Service returned its 'not found' page: {hit!r}")
            ctx.error("This looks like an unclaimed host — an attacker could register it.")
            break
        ctx.muted(f"{scheme}: HTTP {response.status_code}, no takeover marker in the body")

    if found:
        ctx.section("Next steps")
        ctx.note("Remove the DNS record, or register the name on the service before someone else does.")
        ctx.link("can-i-take-over-xyz", "https://github.com/EdOverflow/can-i-take-over-xyz")
    elif checked:
        ctx.warn("Points at a takeover-prone service but the app answered — verify ownership.")
        ctx.note("A healthy app can still be abandoned later; keep the CNAME on a watchlist.")
    else:
        ctx.warn("Could not fetch the host; the CNAME is still worth verifying by hand.")


MODULE = Module(
    id="subdomain_takeover",
    title="Takeover Check",
    category="Web",
    summary="Follow CNAMEs into known services and look for the 'this host is gone' page.",
    fields=(
        Field("host", "Hostname", placeholder="status.example.com", required=True),
    ),
    run=run,
    order=36,
)
