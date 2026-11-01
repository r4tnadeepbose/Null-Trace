"""TCP port scanner with service detection and Shodan InternetDB enrichment."""

from __future__ import annotations

import socket
from ..job import Field, Module
from ..net import HttpError, get_json, resolve
from ..parallel import map_parallel, worker_count

TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106,
    109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222,
    254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427,
    443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545,
    548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687,
    691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873,
    880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001,
    1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030,
    1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045,
    1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060,
]

PRESETS = {
    "Top 100": TOP_100,
    "Web": [80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443],
    "Remote": [22, 23, 3389, 5900, 5901, 5985, 5986],
    "Mail": [25, 110, 143, 465, 587, 993, 995],
    "Database": [1433, 1521, 27017, 3306, 5432, 6379, 9042, 11211],
    "Full 1-1024": list(range(1, 1025)),
}

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp", 179: "bgp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 500: "isakmp", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    27017: "mongodb",
}


def _banner(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in (80, 8080, 8000, 8888, 8008, 81):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            try:
                data = sock.recv(256)
            except (socket.timeout, ConnectionResetError):
                return ""
    except OSError:
        return ""
    text = data.decode("utf-8", "replace").strip().splitlines()
    return text[0][:90] if text else ""


def _scan_one(host: str, port: int, timeout: float, banner: bool) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) != 0:
                return None
    except OSError:
        return None
    return {
        "port": port,
        "service": SERVICES.get(port, "unknown"),
        "banner": _banner(host, port, timeout) if banner else "",
    }


def _internetdb(host: str) -> list[int]:
    try:
        data = get_json(f"https://internetdb.shodan.io/{host}", allow_status=(404,))
    except HttpError:
        return []
    return list(data.get("ports", []))


def run(ctx) -> None:
    raw = ctx.value("host")
    if not raw:
        ctx.error("Enter a host or IP address.")
        return
    addresses = resolve(raw) if not raw.replace(".", "").isdigit() else [raw]
    if not addresses:
        ctx.error(f"Could not resolve {raw}")
        return
    host = addresses[0]

    preset = ctx.value("preset") or "Top 100"
    ports_text = ctx.value("ports")
    if ports_text:
        try:
            ports_set: set[int] = set()
            for token in ports_text.replace(",", " ").split():
                if "-" in token:
                    start, end = (int(x) for x in token.split("-", 1))
                    if start > end:
                        start, end = end, start
                    ports_set.update(range(max(1, start), min(65535, end) + 1))
                else:
                    ports_set.add(int(token))
            ports = sorted(p for p in ports_set if 0 < p < 65536)
        except ValueError:
            ctx.error("Custom port list must be numbers or ranges, e.g. 22,80,8000-8010.")
            return
        if not ports:
            ctx.error("No valid ports in the custom list.")
            return
    else:
        ports = PRESETS.get(preset, TOP_100)

    timeout = 1.0
    try:
        timeout = max(0.2, float(ctx.value("timeout") or "1.0"))
    except ValueError:
        pass
    workers = worker_count(len(ports))
    banner = ctx.checked("banner")

    ctx.title(f"Port scan — {raw} ({host})")
    ctx.kv("Ports to probe", len(ports))
    ctx.kv("Timeout", f"{timeout}s per port")
    ctx.kv("Workers", workers)
    ctx.muted("Only scan systems you own or are authorised to test.")

    def probe(port: int) -> dict | None:
        return _scan_one(host, port, timeout, banner)

    def progress(done: int, total: int) -> None:
        if done % 64 == 0 or done == total:
            ctx.status(f"Scanned {done}/{total}")

    found = map_parallel(probe, ports, workers=workers,
                         should_stop=ctx.cancel_event.is_set, on_progress=progress)
    ctx.check_cancel()
    open_ports = [item for item in found if item]

    ctx.section("Results")
    if open_ports:
        rows = [(r["port"], r["service"], r["banner"] or "—") for r in sorted(open_ports, key=lambda r: r["port"])]
        ctx.table(("Port", "Service", "Banner"), rows)
    else:
        ctx.muted("No open TCP ports found in the selected range.")

    ctx.check_cancel()
    ctx.section("Shodan InternetDB cross-check (passive, free)")
    passive = _internetdb(host)
    if passive:
        ctx.kv("Passively observed ports", ", ".join(str(p) for p in sorted(passive)))
        missed = sorted(set(passive) - {r["port"] for r in open_ports})
        if missed:
            ctx.note(f"Seen by Shodan but not active now (may be filtered): "
                     f"{', '.join(str(p) for p in missed)}")
    else:
        ctx.muted("No passive record for this host.")


MODULE = Module(
    id="port_scan",
    title="Port Scan",
    category="Network",
    summary="Multi-threaded TCP connect scan with service labels, banner grab and passive Shodan cross-check.",
    fields=(
        Field("host", "Host or IP", placeholder="example.com", required=True),
        Field("preset", "Preset range", kind="choice", choices=tuple(PRESETS), default="Top 100"),
        Field("ports", "Custom ports", placeholder="22,80,443,8000-8010",
              help="Overrides the preset. Ranges like 8000-8010 are supported."),
        Field("timeout", "Timeout per port (s)", default="1.0"),
        Field("banner", "Grab service banners", kind="checkbox", default="1"),
    ),
    run=run,
    order=90,
)
