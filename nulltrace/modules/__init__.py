"""Module registry: import every module and expose an ordered catalogue."""

from __future__ import annotations

from ..job import Module
from . import (
    about,
    auto_recon,
    bgp_asn,
    bulk_urls,
    cookie_audit,
    cors_check,
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
    hash_identify,
    hash_lookup,
    host_search,
    image_search,
    infostealer,
    ip_info,
    jwt_inspector,
    mac_lookup,
    metadata,
    my_connection,
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
    subdomain_takeover,
    tls_inspector,
    tls_versions,
    tools,
    url_inspector,
    username_scan,
    vin,
    wayback,
    whois_rdap,
    wifi,
)

CATEGORY_ORDER = ("Recon", "Network", "Web", "Identity", "Utility", "Vulnerability",
                  "Media", "System")


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
        my_connection.MODULE,
        # web
        whois_rdap.MODULE,
        tls_versions.MODULE,
        tls_inspector.MODULE,
        wayback.MODULE,
        url_inspector.MODULE,
        site_files.MODULE,
        subdomain_takeover.MODULE,
        cors_check.MODULE,
        cookie_audit.MODULE,
        bulk_urls.MODULE,
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
        # utility
        jwt_inspector.MODULE,
        hash_identify.MODULE,
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
