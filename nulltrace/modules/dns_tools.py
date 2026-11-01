"""DNS lookups (forward records) and reverse PTR resolution."""

from __future__ import annotations

import ipaddress
import socket

from ..job import Field, Module
from ..net import is_ip, resolve, reverse_dns

try:
    import dns.resolver
    import dns.reversename
    HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover - dependency is in requirements.txt
    HAVE_DNSPYTHON = False

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "SRV", "ALL")

COMMON_SUBS = ("www", "mail", "ftp", "webmail", "smtp", "ns1", "ns2", "api", "dev", "vpn")


def _query(name: str, rtype: str) -> list[str]:
    if not HAVE_DNSPYTHON:
        raise RuntimeError("dnspython is not installed (pip install dnspython)")
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    try:
        answers = resolver.resolve(name, rtype, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return ["(NXDOMAIN — name does not exist)"]
    except (dns.resolver.NoNameservers, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout:
        return ["(resolver timeout)"]
    except dns.exception.DNSException as exc:
        return [f"(error: {exc})"]
    if answers.rrset is None:
        return []
    if rtype == "TXT":
        return [" ".join(part.decode("utf-8", "replace") for part in r.strings)
                for r in answers]
    if rtype == "MX":
        return [f"{r.preference} {r.exchange}" for r in answers]
    if rtype == "SOA":
        return [f"{r.mname} {r.rname} serial={r.serial} refresh={r.refresh} "
                f"retry={r.retry} expire={r.expire} minimum={r.minimum}" for r in answers]
    if rtype == "CAA":
        return [f"{r.flags} {r.tag} {r.value.decode('utf-8', 'replace')}" for r in answers]
    if rtype == "SRV":
        return [f"{r.priority} {r.weight} {r.port} {r.target}" for r in answers]
    return [r.to_text() for r in answers]


def run_lookup(ctx) -> None:
    domain = ctx.value("domain")
    if not domain:
        ctx.error("Enter a domain name.")
        return
    if is_ip(domain):
        ctx.warn("That is an IP address — use DNS Reverse instead.")
        return
    chosen = ctx.value("rtype") or "ALL"
    ctx.title(f"DNS records — {domain}")
    if not HAVE_DNSPYTHON:
        ctx.warn("dnspython missing — falling back to system resolver (A/AAAA only).")
        ctx.section("A / AAAA")
        addresses = resolve(domain)
        if addresses:
            for addr in addresses:
                ctx.text(f"  {addr}")
        else:
            ctx.error("  no addresses returned")
        return

    types = [t for t in RECORD_TYPES if t != "ALL"] if chosen == "ALL" else [chosen]
    for rtype in types:
        ctx.check_cancel()
        ctx.section(rtype)
        values = _query(domain, rtype)
        if not values:
            ctx.muted("  (none)")
        for value in values:
            ctx.text(f"  {value}")

    if chosen == "ALL" and ctx.checked("common"):
        ctx.section("Common subdomain probe")
        for sub in COMMON_SUBS:
            ctx.check_cancel()
            label = f"{sub}.{domain}"
            try:
                socket.gethostbyname(label)
            except socket.gaierror:
                continue
            ctx.text(f"  {label:<28} resolves")


def run_reverse(ctx) -> None:
    target = ctx.value("ip")
    if not target:
        ctx.error("Enter an IP address.")
        return
    if not is_ip(target):
        ctx.error("That is not a valid IP address.")
        return
    ctx.title(f"Reverse DNS — {target}")
    names = reverse_dns(target)
    if names:
        for name in names:
            ctx.ok(f"  {name}")
    else:
        ctx.warn("  no PTR record")

    if HAVE_DNSPYTHON:
        ctx.section("PTR via DNS")
        try:
            rev = dns.reversename.from_address(target)
            for value in _query(str(rev), "PTR"):
                ctx.text(f"  {value}")
        except Exception as exc:  # malformed input is already validated above
            ctx.muted(f"  {exc}")

    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private:
            ctx.note("Private address space — PTR records are usually local only.")
    except ValueError:
        pass


DNS_LOOKUP = Module(
    id="dns_lookup",
    title="DNS Lookup",
    category="Network",
    summary="Query any record type (A/AAAA/MX/TXT/NS/CNAME/SOA/CAA/SRV) with optional subdomain probe.",
    fields=(
        Field("domain", "Domain", placeholder="example.com", required=True),
        Field("rtype", "Record type", kind="choice", choices=RECORD_TYPES, default="ALL"),
        Field("common", "Also probe common subdomains", kind="checkbox", default="0"),
    ),
    run=run_lookup,
    order=20,
)

DNS_REVERSE = Module(
    id="dns_reverse",
    title="DNS Reverse",
    category="Network",
    summary="Resolve an IP back to hostnames (PTR records and system resolver).",
    fields=(
        Field("ip", "IP address", placeholder="1.1.1.1", required=True),
    ),
    run=run_reverse,
    order=30,
)
