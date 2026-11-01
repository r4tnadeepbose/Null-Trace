"""Module registry: import every module and expose an ordered catalogue."""

from __future__ import annotations

from ..job import Module
from . import (
    about,
    auto_recon,
    bgp_asn,
    cve,
    darkweb,
    dns_propagation,
    dns_tools,
    dorks,
    email_finder,
    email_headers,
    email_intel,
    exposure_audit,
    file_triage,
    github,
    hash_lookup,
    host_search,
    image_search,
    infostealer,
    ip_info,
    mac_lookup,
    metadata,
    netmap,
    dnsbl,
    news,
    phone_info,
    port_scan,
    reverse_ip,
    site_files,
    smtp,
    speedtest,
    subdomains,
    tls_inspector,
    tools,
    url_inspector,
    username_scan,
    vin,
    wayback,
    whois_rdap,
    wifi,
)

CATEGORY_ORDER = ("Recon", "Network", "Web", "Identity", "Vulnerability", "Media", "System")


def all_modules() -> list[Module]:
    modules = [
        # recon
        auto_recon.MODULE,
        # network
        ip_info.MODULE,
        dns_tools.DNS_LOOKUP,
        dns_propagation.MODULE,
        dns_tools.DNS_REVERSE,
        port_scan.MODULE,
        bgp_asn.MODULE,
        mac_lookup.MODULE,
        dnsbl.MODULE,
        reverse_ip.MODULE,
        netmap.MODULE,
        # web
        whois_rdap.MODULE,
        tls_inspector.MODULE,
        wayback.MODULE,
        url_inspector.MODULE,
        site_files.MODULE,
        host_search.MODULE,
        subdomains.MODULE,
        dorks.MODULE,
        darkweb.MODULE,
        news.MODULE,
        # identity
        email_intel.MODULE,
        email_finder.MODULE,
        exposure_audit.MODULE,
        phone_info.MODULE,
        username_scan.MODULE,
        email_headers.MODULE,
        smtp.MODULE,
        infostealer.MODULE,
        github.MODULE,
        # vulnerability
        cve.MODULE,
        # media
        metadata.MODULE,
        hash_lookup.MODULE,
        file_triage.MODULE,
        vin.MODULE,
        image_search.MODULE,
        # system
        wifi.MODULE,
        speedtest.MODULE,
        tools.MODULE,
        about.MODULE,
    ]
    return sorted(
        modules,
        key=lambda m: (CATEGORY_ORDER.index(m.category) if m.category in CATEGORY_ORDER else 99,
                       m.order),
    )


def grouped() -> dict[str, list[Module]]:
    groups: dict[str, list[Module]] = {}
    for module in all_modules():
        groups.setdefault(module.category, []).append(module)
    return groups


def find(module_id: str) -> Module | None:
    return next((m for m in all_modules() if m.id == module_id), None)
