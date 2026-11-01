"""IP address intelligence: geolocation, ASN, reverse DNS, open ports."""

from __future__ import annotations

import ipaddress

from ..job import Field, Module
from ..net import HttpError, get_json, geo_summary, is_ip, resolve, reverse_dns


def _ipinfo(target: str) -> dict:
    data = get_json(f"https://ipinfo.io/{target}/json")
    if data.get("bogon") or "ip" not in data:
        raise HttpError("ipinfo returned no record")
    return data


def _ipapi(target: str) -> dict:
    data = get_json(f"http://ip-api.com/json/{target}?fields=status,message,country,"
                    "regionName,city,zip,lat,lon,timezone,isp,org,as,query,mobile,proxy,hosting")
    if data.get("status") != "success":
        raise HttpError(data.get("message", "ip-api lookup failed"))
    return data


def _internetdb(target: str) -> dict | None:
    try:
        return get_json(f"https://internetdb.shodan.io/{target}", allow_status=(404,))
    except HttpError:
        return None


def run(ctx) -> None:
    raw = ctx.value("target")
    if not raw:
        ctx.error("Enter an IP address or hostname.")
        return
    target = raw
    if not is_ip(target):
        ctx.status(f"Resolving {target} ...")
        addresses = resolve(target)
        if not addresses:
            ctx.error(f"Could not resolve {target}")
            return
        target = addresses[0]
        ctx.muted(f"{raw} -> {target}")

    ip = ipaddress.ip_address(target)
    ctx.title(f"IP intelligence — {target}")
    ctx.kv("Version", f"IPv{ip.version}")
    ctx.kv("Scope", "private / reserved" if ip.is_private or ip.is_reserved or ip.is_loopback
           else "public")

    ctx.section("Geolocation & network")
    info: dict = {}
    try:
        info = _ipinfo(target)
        ctx.kv("City", info.get("city"))
        ctx.kv("Region", info.get("region"))
        ctx.kv("Country", info.get("country"))
        ctx.kv("Postal", info.get("postal"))
        ctx.kv("Timezone", info.get("timezone"))
        ctx.kv("Organisation", info.get("org"))
        ctx.kv("Hostname", info.get("hostname"))
    except HttpError as exc:
        ctx.warn(f"ipinfo.io unavailable ({exc}) — trying ip-api.com")
        try:
            alt = _ipapi(target)
            info = {
                "city": alt.get("city"), "region": alt.get("regionName"),
                "country": alt.get("country"), "postal": alt.get("zip"),
                "timezone": alt.get("timezone"), "org": alt.get("org") or alt.get("isp"),
            }
            for label, key in (("City", "city"), ("Region", "region"), ("Country", "country"),
                               ("Postal", "postal"), ("Timezone", "timezone"),
                               ("Organisation", "org"), ("ASN", "as")):
                ctx.kv(label, alt.get(key))
            if alt.get("proxy") or alt.get("hosting"):
                ctx.warn("ip-api flags this address as proxy/hosting infrastructure.")
        except HttpError as exc2:
            ctx.error(f"No geolocation provider answered: {exc2}")

    location = info.get("loc") or ""
    if not location:
        try:
            alt = _ipapi(target)
            if alt.get("lat") and alt.get("lon"):
                location = f"{alt['lat']},{alt['lon']}"
        except HttpError:
            location = ""
    if "," in str(location):
        lat, lon = str(location).split(",", 1)
        ctx.link("Map", geo_summary(lat.strip(), lon.strip()))

    ctx.check_cancel()
    ctx.section("Reverse DNS")
    names = reverse_dns(target)
    if names:
        for name in names:
            ctx.text(f"  {name}")
    else:
        ctx.muted("  no PTR record")

    ctx.check_cancel()
    ctx.section("Shodan InternetDB (free, no key)")
    db = _internetdb(target)
    if not db:
        ctx.muted("  no InternetDB record for this address")
        return
    ctx.kv("Open ports", ", ".join(str(p) for p in db.get("ports", [])) or "none")
    ctx.kv("Hostnames", ", ".join(db.get("hostnames", [])) or "none")
    ctx.kv("CPEs", ", ".join(db.get("cpes", [])) or "none")
    tags = db.get("tags", [])
    if tags:
        ctx.kv("Tags", ", ".join(tags))
    vulns = db.get("vulns", [])
    if vulns:
        ctx.section(f"Known vulnerabilities ({len(vulns)})")
        for cve in vulns:
            ctx.warn(f"  {cve}")
        ctx.link("Details", "https://www.cve.org/CVERecord?id=" + (vulns[0] if vulns else ""))
    else:
        ctx.ok("No known CVEs in Shodan's passive dataset.")


MODULE = Module(
    id="ip_info",
    title="IP Intel",
    category="Network",
    summary="Geolocation, ASN, reverse DNS, exposed ports and known CVEs for an IP or hostname.",
    fields=(
        Field("target", "IP or hostname", placeholder="8.8.8.8", required=True,
              help="Domain names are resolved first."),
    ),
    run=run,
    order=10,
)
