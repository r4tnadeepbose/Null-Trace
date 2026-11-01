"""Your own egress: public address, network owner and proxy signals."""

from __future__ import annotations

import platform
import socket

from ..job import Field, Module
from ..net import HttpError, get_json, reverse_dns


def run(ctx) -> None:
    ctx.title("My connection")
    ctx.kv("Hostname", socket.gethostname())
    ctx.kv("Platform", f"{platform.system()} {platform.release()}")

    ctx.section("Egress address")
    info: dict = {}
    try:
        info = get_json("https://ipinfo.io/json", timeout=12)
    except HttpError as exc:
        ctx.warn(f"ipinfo.io unavailable ({exc}); trying ip-api.com")
        try:
            alt = get_json("http://ip-api.com/json/?fields=status,country,regionName,city,"
                           "isp,org,as,query,mobile,proxy,hosting", timeout=12)
            info = {"ip": alt.get("query"), "city": alt.get("city"),
                    "region": alt.get("regionName"), "country": alt.get("country"),
                    "org": alt.get("org"), "asn": alt.get("as"), "loc": ""}
            if alt.get("proxy") or alt.get("hosting"):
                ctx.warn("The exit address is flagged as proxy/hosting.")
        except HttpError as exc2:
            ctx.error(f"No IP provider answered: {exc2}")
            return

    ip = info.get("ip") or ""
    ctx.kv("Public IP", ip or "—")
    ctx.kv("City", info.get("city") or "—")
    ctx.kv("Region", info.get("region") or "—")
    ctx.kv("Country", info.get("country") or "—")
    ctx.kv("Organisation", info.get("org") or "—")
    if info.get("asn"):
        ctx.kv("ASN", info["asn"])
    if info.get("timezone"):
        ctx.kv("Timezone", info["timezone"])
    if info.get("loc"):
        ctx.link("Map", f"https://www.openstreetmap.org/?mlat={info['loc'].split(',')[0]}"
                        f"&mlon={info['loc'].split(',')[-1]}")

    if ip:
        ctx.section("Reverse DNS")
        names = reverse_dns(ip)
        for name in names:
            ctx.text(f"  {name}")
        if not names:
            ctx.muted("  no PTR record")

    ctx.section("Checks")
    if info.get("bogon"):
        ctx.error("The address is private — a proxy or VPN is intercepting traffic.")
    else:
        ctx.ok("A public address answered, so requests leave this machine directly.")
    ctx.note("If this address is not your ISP's, a VPN or proxy is in front of the app.")
    ctx.link("What is my IP (browser)", "https://ifconfig.me/")
    ctx.link("IP details", f"https://ipinfo.io/{ip}" if ip else "https://ipinfo.io/")


MODULE = Module(
    id="my_connection",
    title="My Connection",
    category="Network",
    summary="Your public address, network owner, reverse DNS and whether a proxy is in front.",
    fields=(),
    run=run,
    order=186,
)
