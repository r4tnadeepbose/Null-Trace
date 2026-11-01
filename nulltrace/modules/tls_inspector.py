"""TLS certificate inspection: identity, validity window and expiry risk."""

from __future__ import annotations

from datetime import datetime, timezone

from ..job import Field, Module
from ..net import tls_certificate


def _fields(parts) -> dict:
    """ssl gives subject/issuer as nested sequences of (key, value) pairs."""
    values: dict[str, str] = {}
    for group in parts or []:
        if (isinstance(group, (tuple, list)) and len(group) == 2
                and all(isinstance(part, str) for part in group)):
            values[group[0]] = group[1]
            continue
        for item in group:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                values[str(item[0])] = str(item[1])
    return values


def _name(parts) -> str:
    values = _fields(parts)
    return (values.get("organizationName") or values.get("commonName")
            or values.get("organizationalUnitName") or "—")


def run(ctx) -> None:
    host = ctx.value("host").strip()
    host = host.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        port = int(ctx.value("port") or "443")
    except ValueError:
        ctx.error("Port must be a number.")
        return
    if not host:
        ctx.error("Enter a hostname.")
        return

    ctx.title(f"TLS certificate — {host}:{port}")
    ctx.status("Handshaking ...")
    try:
        cert = tls_certificate(host, port)
    except Exception as exc:
        ctx.error(f"Could not complete a TLS handshake: {exc}")
        ctx.note("The host may be down, the port closed, or the handshake refused.")
        return

    ctx.section("Connection")
    ctx.kv("Protocol", cert.get("version") or "—")
    ctx.kv("Cipher", cert.get("cipher") or "—")
    ctx.kv("Verified", "yes" if cert.get("verified") else "NO — chain or hostname failed")

    subject = cert.get("subject") or []
    issuer = cert.get("issuer") or []
    common = _fields(subject)
    ctx.section("Certificate")
    ctx.kv("Subject CN", common.get("commonName", "—"))
    ctx.kv("Issuer", _name(issuer))
    ctx.kv("Valid from", cert.get("not_before") or "—")
    ctx.kv("Valid until", cert.get("not_after") or "—")

    san = [value for kind, value in (cert.get("san") or []) if kind == "DNS"]
    ctx.kv("SAN entries", len(san))
    for name in san[:20]:
        ctx.text(f"  {name}")
    if len(san) > 20:
        ctx.muted(f"  … {len(san) - 20} more")
    if any(name.startswith("*.") for name in san):
        ctx.note("Wildcard certificate: covers any single label under the parent.")

    ctx.check_cancel()
    ctx.section("Expiry")
    until = cert.get("not_after") or ""
    try:
        expires = datetime.strptime(until, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        ctx.kv("Days remaining", days)
        if days < 0:
            ctx.error("Certificate has EXPIRED.")
        elif days < 14:
            ctx.warn("Expires within two weeks — renewal is overdue.")
        elif days < 30:
            ctx.warn("Expires within a month.")
        else:
            ctx.ok("Validity window looks healthy.")
    except ValueError:
        ctx.muted("Could not parse the expiry date.")
        if until:
            days = None

    ctx.section("Checks")
    if cert.get("verified") is False:
        ctx.err("Browsers will warn: the chain does not validate against the trust store.")
    if common.get("commonName", "").startswith("*."):
        ctx.note("The subject itself is a wildcard.")

    ctx.link("SSL Labs (manual)", f"https://www.ssllabs.com/ssltest/analyze.html?d={host}&hideResults=on")
    ctx.link("crt.sh history", f"https://crt.sh/?q={host}")


MODULE = Module(
    id="tls_inspector",
    title="TLS Inspector",
    category="Web",
    summary="Certificate subject, issuer, SANs, expiry countdown and whether the chain verifies.",
    fields=(
        Field("host", "Hostname", placeholder="example.com", required=True),
        Field("port", "Port", default="443"),
    ),
    run=run,
    order=28,
)
