"""Sherlock username OSINT — the full upstream engine, inside Null-Trace.

Wraps the vendored ``sherlock_project`` package (MIT, Siddharth Dushantha and
contributors) so the whole 480-site manifest, its per-site probe methods,
false-positive exclusions and NSFW scope are reachable from the GUI and the
headless CLI without leaving this workbench.
"""

from __future__ import annotations

import itertools

from ..browser import open_url
from ..job import Field, Module
from ..net import Cancelled, tor_running
from ..sherlock_engine import (SiteRow, build_plan, engine_version, expand_variants,
                               missing_dependency, output_dir, parse_usernames,
                               probe, slowest, summarize, write_report)

MAX_BROWSE = 25


def _variants(name: str) -> list[str]:
    """Separator variants of one handle: every . - _ tried as all three."""
    positions = [i for i, char in enumerate(name) if char in "._-"]
    if not positions:
        return []
    combos: list[tuple[str, ...]] = []
    if len(positions) <= 2:
        combos = list(itertools.product("._-", repeat=len(positions)))
    else:  # too many separators to explode — swap one at a time
        for index, _pos in enumerate(positions):
            for swap in "._-":
                combos.append(tuple(swap if i == index else name[p]
                                    for i, p in enumerate(positions)))
    seen: list[str] = []
    for combo in combos:
        chars = list(name)
        for pos, char in zip(positions, combo):
            chars[pos] = char
        candidate = "".join(chars)
        if candidate != name and candidate not in seen:
            seen.append(candidate)
    return seen


def run(ctx) -> None:
    names = parse_usernames(ctx.value("usernames"))
    if not names:
        ctx.error("Enter at least one username.")
        return

    gap = missing_dependency()
    if gap:
        ctx.error(f"The vendored engine needs the '{gap}' package.")
        ctx.muted("Install dependencies with:  python -m pip install -r requirements.txt")
        return

    expanded: list[str] = []
    for name in names:
        variants: list[str] = []
        if "{?}" in name:
            variants = expand_variants(name)
        elif ctx.checked("variants"):
            variants = _variants(name)
        for candidate in [name, *variants] if variants else [name]:
            if candidate not in expanded:
                expanded.append(candidate)
    names = expanded

    timeout = ctx.value("timeout") or "15"
    try:
        timeout_seconds = max(2.0, min(float(timeout), 120.0))
    except ValueError:
        timeout_seconds = 15.0
        ctx.warn(f"Timeout '{timeout}' is not a number — using 15 seconds.")

    proxy = ctx.value("proxy") or None
    if ctx.checked("tor"):
        if tor_running():
            proxy = proxy or "socks5h://127.0.0.1:9050"
            ctx.ok("Routing through the local Tor SOCKS listener.")
        else:
            ctx.warn("Nothing is listening on 127.0.0.1:9050 — scanning directly.")

    ctx.title(f"Sherlock username OSINT — {len(names)} name(s)")
    try:
        plan = build_plan(live=ctx.value("manifest").startswith("Live"),
                          manifest_path=ctx.value("custom_manifest") or None,
                          only=parse_usernames(ctx.value("only_sites")),
                          skip=parse_usernames(ctx.value("skip_sites")),
                          include_nsfw=ctx.value("scope").startswith("Everything"),
                          honor_exclusions=ctx.checked("exclusions"))
    except Exception as exc:
        ctx.error(f"Could not load the site manifest: {exc}")
        return

    total = len(plan.site_data)
    if not total:
        ctx.error("No sites left after filtering. Check the scope and site lists.")
        return

    everything = ctx.value("scope").startswith("Everything")
    ctx.kv("Engine", f"Sherlock {engine_version()} (vendored, MIT)")
    ctx.kv("Manifest", plan.manifest)
    ctx.kv("Sites per name", total)
    ctx.kv("Scope", "including NSFW" if everything else "safe sites only")
    ctx.kv("Upstream exclusions", "honored" if plan.honor_exclusions else "ignored")
    ctx.kv("Timeout per request", f"{timeout_seconds:.0f}s")
    ctx.kv("Proxy", proxy or "direct connection")
    ctx.muted(f"{plan.nsfw_total} NSFW sites sit in the manifest; "
              f"{'probed' if everything else 'skipped this run'}.")
    if plan.manifest_error:
        ctx.warn(f"Manifest note: {plan.manifest_error}")
    if plan.unknown_sites:
        ctx.warn("Site names not in the manifest: " + ", ".join(plan.unknown_sites))
        ctx.muted("A withheld upstream site counts as unknown here — untick the "
                  "exclusion filter if you still want it probed.")

    print_all = ctx.checked("print_all")
    if ctx.checked("list_sites"):
        ctx.section(f"Manifest sites ({total})")
        ctx.table(("Site", "Probe", "NSFW"),
                  ((name, str(info.get("method", "get")).upper(),
                    "yes" if info.get("isNSFW") else "-")
                   for name, info in sorted(plan.site_data.items(),
                                            key=lambda item: item[0].casefold())))
    collected: dict[str, list[SiteRow]] = {}
    aborted = False

    for name in names:
        if len(names) > 1:
            ctx.section(f"@{name}")
        counter = {"done": 0}

        def on_result(row: SiteRow) -> None:
            counter["done"] += 1
            if row.status == "found":
                ctx.ok(f"FOUND  {row.site}")
                ctx.link(f"  {row.site}", row.url)
            elif print_all and row.status != "error":
                ctx.muted(f"  {row.site}: {row.verdict}")
            if counter["done"] % 40 == 0:
                ctx.status(f"@{name}: {counter['done']}/{total} answered")

        try:
            rows, stopped, elapsed = probe(name, plan.site_data, proxy=proxy,
                                           timeout=timeout_seconds,
                                           on_result=on_result,
                                           cancel=ctx.cancel_event)
        except Cancelled:
            rows, stopped, elapsed = [], True, 0.0
        collected[name] = rows
        if stopped:
            aborted = True
            ctx.warn(f"@{name}: stopped after {counter['done']} answers.")
            break

        counts = summarize(rows)
        found = [r for r in rows if r.status == "found" and r.url]
        noise = [r for r in rows if r.status in ("blocked", "error", "illegal")]

        ctx.section(f"Matched profiles — @{name}")
        if found:
            ctx.table(("Site", "URL", "HTTP", "Seconds"),
                      ((r.site, r.url, r.http_status or "-",
                        f"{r.seconds:.2f}" if r.seconds else "-") for r in found))
            if ctx.checked("browse"):
                for row in found[:MAX_BROWSE]:
                    open_url(row.url)
                if len(found) > MAX_BROWSE:
                    ctx.muted(f"Opened {MAX_BROWSE} links; the rest stay in the table.")
        else:
            ctx.muted("  (no site reported a match)")

        if print_all:
            ctx.section(f"No profile — @{name}")
            ctx.table(("Site", "Verdict", "HTTP"),
                      ((r.site, r.verdict, r.http_status or "-")
                       for r in rows if r.status == "free"))

        if noise:
            ctx.section(f"Inconclusive — @{name}")
            ctx.table(("Site", "Verdict", "Why"),
                      ((r.site, r.verdict, (r.reason or "-")[:70]) for r in noise))

        ctx.section(f"Statistics — @{name}")
        ctx.kv("Probed", len(rows))
        ctx.kv("Found", counts.get("found", 0))
        ctx.kv("Clear", counts.get("free", 0))
        ctx.kv("Blocked (WAF or 429)", counts.get("blocked", 0))
        ctx.kv("Errors", counts.get("error", 0))
        ctx.kv("Rejected by site rules", counts.get("illegal", 0))
        ctx.kv("Wall-clock time", f"{elapsed:.1f}s")
        slow = slowest(rows, 3)
        if slow:
            ctx.muted("Slowest: " + ", ".join(
                f"{r.site} {r.seconds:.1f}s" for r in slow if r.seconds))

    if ctx.checked("save"):
        formats = ["txt", "csv", "json"] + (["xlsx"] if ctx.checked("xlsx") else [])
        ctx.section("Saved reports")
        try:
            for name, rows in collected.items():
                for path in write_report(name, rows, manifest=plan.manifest,
                                        formats=formats):
                    ctx.link(f"  {path.name}", str(path))
        except Exception as exc:
            ctx.warn(f"Report writing failed: {exc}")
        ctx.muted(f"Folder: {output_dir()}")
        if ctx.checked("xlsx"):
            ctx.muted("The .xlsx workbook needs openpyxl, listed in requirements.txt.")

    ctx.section("How to read this")
    ctx.note(
        "Sherlock compares each reply against that site's own 'profile missing' "
        "signature, so a match is a strong hint rather than proof: people reuse "
        "handles, and some sites answer 200 for everyone. Anything inconclusive is "
        "counted separately instead of being hidden. Only public profile pages are "
        "requested, one pass per site."
    )
    ctx.note("Engine: Sherlock " + engine_version() + ", MIT licensed — "
             "sherlockproject.xyz, notice in legal/THIRD_PARTY.md.")

    if aborted:
        raise Cancelled()


MODULE = Module(
    id="sherlock_scan",
    title="Sherlock Username OSINT",
    category="Identity",
    summary="The whole vendored Sherlock engine: one handle against the full "
            "480-site manifest, with exclusions, NSFW scope, proxy or Tor, and "
            "txt, csv, json, xlsx reports.",
    order=64,
    fields=(
        Field("usernames", "Usernames", kind="multiline", required=True,
              placeholder="r4tnadeepbose\nrate_bose\nuser{?}name",
              help="One per line, or separated by spaces and commas. "
                   "{?} becomes _ , - and . as upstream does."),
        Field("scope", "Site scope", kind="choice",
              choices=("Safe sites only (recommended)", "Everything, including NSFW"),
              default="Safe sites only (recommended)"),
        Field("manifest", "Site manifest", kind="choice",
              choices=("Bundled data.json (offline-safe)",
                       "Live upstream manifest (freshest)"),
              default="Bundled data.json (offline-safe)"),
        Field("custom_manifest", "Custom site list",
              placeholder=r"C:\Lists\my_sites.json  or  https://example.com/data.json",
              help="Optional, must end in .json — overrides the choice above "
                   "(upstream --json)."),
        Field("only_sites", "Only these sites", placeholder="github, twitter, tiktok",
              help="Leave empty to probe the entire manifest (upstream --site)."),
        Field("skip_sites", "Never probe these", placeholder="Instagram, Vsco"),
        Field("timeout", "Timeout per request", default="15",
              help="Seconds, 2-120. Raise it on a routed or slow connection."),
        Field("proxy", "Proxy URL", placeholder="socks5h://127.0.0.1:9050"),
        Field("exclusions", "Honor upstream false-positive exclusions",
              kind="checkbox", default="True"),
        Field("variants", "Also try . - _ separator variants", kind="checkbox"),
        Field("tor", "Route through Tor when it is listening", kind="checkbox"),
        Field("print_all", "List every site checked", kind="checkbox"),
        Field("list_sites", "Print the site list before scanning", kind="checkbox"),
        Field("browse", "Open matched profiles in the browser", kind="checkbox"),
        Field("save", "Save txt + csv + json report", kind="checkbox"),
        Field("xlsx", "Also save an .xlsx workbook", kind="checkbox"),
    ),
    run=run,
)
