"""Subdomain enumeration from certificate transparency and passive DNS."""

from __future__ import annotations

import re

from ..datasets import load_lines
from ..job import Field, Module
from ..net import HttpError, get_json, http, resolve

_DEFAULT_BRUTE_WORDS = (
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure",
    "vpn", "api", "dev", "staging", "test", "portal", "admin", "app", "cdn", "static",
    "media", "support", "shop", "store", "docs", "git", "ci", "jenkins", "monitor", "status",
    "internal", "intranet", "db", "backup", "old", "beta", "demo", "qa", "uat", "m", "wap",
)
BRUTE_WORDS = tuple(load_lines("subdomain_words.txt", _DEFAULT_BRUTE_WORDS))
RESOLVE_LIMIT = 400


def _crtsh(domain: str) -> set[str]:
    try:
        data = get_json(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=60, allow_status=(502, 503, 504),
        )
    except HttpError:
        return set()
    if not isinstance(data, list):
        return set()
    out: set[str] = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if name.endswith(domain) and name != domain and "*" not in name:
                out.add(name)
    return out


def _hackertarget(domain: str) -> set[str]:
    try:
        response = http(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
    except HttpError:
        return set()
    body = response.text
    if "error" in body.lower() or "API count exceeded" in body:
        return set()
    out = set()
    for line in body.splitlines():
        host = line.split(",")[0].strip().lower()
        if host.endswith(domain):
            out.add(host)
    return out


def resolve_many(hosts: list[str], workers: int = 128) -> dict[str, list[str]]:
    """Resolve names concurrently through the OS resolver (fast, no extra deps)."""
    from ..parallel import map_parallel

    def one(host: str) -> tuple[str, list[str]]:
        return host, resolve(host)

    return dict(map_parallel(one, hosts, workers=workers))


def _brute(domain: str) -> set[str]:
    names = [f"{word}.{domain}" for word in BRUTE_WORDS]
    resolved = resolve_many(names)
    return {host for host, addresses in resolved.items() if addresses}


def run(ctx) -> None:
    domain = ctx.value("domain").lower().strip().rstrip(".")
    if not domain:
        ctx.error("Enter a domain.")
        return
    if re.search(r"https?://", domain):
        domain = domain.split("//", 1)[1].split("/")[0]
    ctx.title(f"Subdomain enumeration — {domain}")

    sources: dict[str, set[str]] = {}
    ctx.status("Querying crt.sh ...")
    sources["crt.sh"] = _crtsh(domain)
    ctx.kv("crt.sh", len(sources["crt.sh"]))

    ctx.check_cancel()
    ctx.status("Querying HackerTarget ...")
    sources["hackertarget"] = _hackertarget(domain)
    ctx.kv("HackerTarget", len(sources["hackertarget"]))

    if ctx.checked("brute"):
        ctx.status("Brute-forcing common labels ...")
        sources["bruteforce"] = _brute(domain)
        ctx.kv("Brute force", len(sources["bruteforce"]))

    combined: set[str] = set().union(*sources.values()) if sources else set()
    ctx.section("Sources")
    for name, found in sources.items():
        ctx.kv(name, len(found))
    ctx.kv("Unique subdomains", len(combined))
    if not combined:
        ctx.warn("No subdomains found. crt.sh is frequently rate limited — retry later.")
        return

    resolve_addresses = ctx.checked("resolve")
    ctx.section("Subdomains")
    if resolve_addresses:
        targets = sorted(combined)
        if len(targets) > RESOLVE_LIMIT:
            ctx.muted(f"Resolving the first {RESOLVE_LIMIT} of {len(targets)} names "
                      f"(crt.sh often returns thousands of stale hosts).")
            targets = targets[:RESOLVE_LIMIT]
        ctx.status(f"Resolving {len(targets)} hosts ...")
        resolved = resolve_many(targets)
        rows = [
            (host, ", ".join(addresses[:3]) if addresses else "no A/AAAA")
            for host, addresses in resolved.items()
        ]
        ctx.table(("Subdomain", "Addresses"), rows)
    else:
        for host in sorted(combined):
            ctx.text(f"  {host}")

    ctx.section("Next steps")
    ctx.link("SpiderFoot", "https://github.com/smicallef/spiderfoot")
    ctx.note("Verify scope and authorisation before probing discovered hosts.")


MODULE = Module(
    id="subdomains",
    title="Subdomains",
    category="Web",
    summary="Certificate transparency (crt.sh), passive DNS (HackerTarget) and optional label brute force.",
    fields=(
        Field("domain", "Domain", placeholder="example.com", required=True),
        Field("resolve", "Resolve each host", kind="checkbox", default="1"),
        Field("brute", "Add common-label brute force", kind="checkbox", default="0"),
    ),
    run=run,
    order=110,
)
