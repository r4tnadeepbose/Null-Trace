"""About / changelog view."""

from __future__ import annotations

from ..job import Module
from ..version import APP_NAME, AUTHOR, GITHUB, TAGLINE, VERSION

CHANGELOG = [
    ("1.2.2", [
        "Tor Expert Bundle installed and detected from the usual folders; the",
        "dashboard distinguishes running, installed and missing, and Toolkit",
        "gains a Start Tor action that waits for the SOCKS port.",
    ]),
    ("1.2.1", [
        "ExifTool is discovered on PATH or in its usual install folders, so the",
        "Metadata module picks it up without a reboot after installation.",
    ]),
    ("1.2.0", [
        "Eight new modules: TLS Inspector, Wayback, BGP / ASN, DNS Propagation,",
        "IP Reputation (DNSBL), Reverse IP, Site Files and File Triage.",
        "One red 1px edge on every surface, with rules separating the sidebar,",
        "top bar and content.",
    ]),
    ("1.1.2", [
        "Interface text is larger by default (115%) with A- / A+ controls to scale",
        "every font between 100% and 140%; the choice is stored in the config.",
        "Dashboard scrolls as a page so scaled text never clips.",
    ]),
    ("1.1.1", [
        "Removed the white-mode switch and its palette; the interface is dark only.",
        "Top bar now carries the views, fullscreen and the help page.",
    ]),
    ("1.1.0", [
        "Quick Recon: one field for a domain, IP, email, phone, VIN, hash or "
        "username, auto-detected and swept with a findings summary.",
        "Fullscreen toggle (F11, Escape to leave) and the workspace views moved "
        "into the top bar.",
        "Brighter text, framed module list and a cleaner wordmark on white.",
    ]),
    ("1.0.0", [
        "Complete rewrite as a native Python GUI application.",
        "Unified module contract: every tool is a self-contained module.",
        "Local scan history with sqlite, exportable results.",
        "Free-first data sources: NVD + CISA KEV, crt.sh, NHTSA, Hudson Rock, Ahmia.",
        "API keys are optional and stored locally, never transmitted elsewhere.",
    ]),
]


def run(ctx) -> None:
    ctx.title(f"{APP_NAME} {VERSION}")
    ctx.muted(TAGLINE)
    ctx.section("About")
    ctx.note("Null-Trace is a workstation for open-source intelligence: it consolidates")
    ctx.note("public records, DNS, certificates, metadata and breach exposure into one")
    ctx.note("interface. Every module runs locally; requests go straight from your")
    ctx.note("machine to the upstream source.")
    ctx.section("What's new")
    for version, entries in CHANGELOG:
        ctx.text(f"{version}")
        for entry in entries:
            ctx.text(f"   - {entry}")
    ctx.section("Principles")
    ctx.note("Scope first. Only investigate people and systems you have a lawful basis to")
    ctx.note("investigate. Prefer public sources; never bypass authentication; do not")
    ctx.note("harass, dox or profile private individuals. Findings are evidence of")
    ctx.note("exposure, not proof of wrongdoing.")
    ctx.section("Credits")
    ctx.note(f"Built by {AUTHOR} (he/him).")
    ctx.link("  GitHub", f"{GITHUB}?tab=repositories")
    ctx.link("  Profile", GITHUB)
    ctx.note("Independent Python rewrite inspired by the open-source TermuxHackz")
    ctx.note("X-osint tool. Data providers: ipinfo.io, ip-api.com, Shodan InternetDB,")
    ctx.note("NVD, CISA, crt.sh, HackerTarget, Hudson Rock, Ahmia, NHTSA, GitHub,")
    ctx.note("Google News.")
    ctx.note("Released under the MIT licence, © 2026 Ratnadeep Bose.")


MODULE = Module(
    id="about",
    title="About",
    category="System",
    summary="Version, changelog and the rules of engagement this tool is built around.",
    fields=(),
    run=run,
    order=240,
)
