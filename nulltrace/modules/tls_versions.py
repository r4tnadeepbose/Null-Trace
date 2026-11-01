"""Which TLS protocol versions and cipher suites a host still accepts."""

from __future__ import annotations

import socket
import ssl

from ..job import Field, Module

VERSIONS = (
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3, False),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2, False),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1, True),
    ("TLS 1.0", ssl.TLSVersion.TLSv1, True),
)

WEAK_CIPHERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")


def _handshake(host: str, port: int, version) -> tuple[bool, str, str]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
    except ValueError:
        return False, "unsupported by this build", ""
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                ciphers = tls.cipher()
                return True, tls.version() or "", ciphers[0] if ciphers else ""
    except (ssl.SSLError, OSError):
        return False, "", ""


def run(ctx) -> None:
    host = ctx.value("host").strip().replace("https://", "").split("/")[0]
    if not host:
        ctx.error("Enter a hostname.")
        return
    try:
        port = int(ctx.value("port") or "443")
    except ValueError:
        ctx.error("Port must be a number.")
        return

    ctx.title(f"TLS versions — {host}:{port}")
    ctx.muted("Each version is negotiated separately; a refusal means the server dropped it.")

    rows = []
    weak_supported = 0
    weak_ciphers = 0
    for label, version, deprecated in VERSIONS:
        ctx.check_cancel()
        ctx.status(f"Trying {label} ...")
        ok, negotiated, cipher = _handshake(host, port, version)
        if ok:
            note = "accepted"
            if deprecated:
                weak_supported += 1
                note = "ACCEPTED — deprecated"
            if any(token in cipher.upper() for token in WEAK_CIPHERS):
                weak_ciphers += 1
                note += " · weak cipher"
            rows.append((label, "yes", negotiated or "—", cipher or "—", note))
        else:
            rows.append((label, "no", "—", "—", "refused"))

    ctx.section("Results")
    ctx.table(("Version", "Accepted", "Negotiated", "Cipher", "Notes"), rows)

    ctx.section("Verdict")
    if weak_supported:
        ctx.error(f"{weak_supported} deprecated protocol version(s) still accepted.")
    else:
        ctx.ok("No deprecated TLS versions accepted.")
    if weak_ciphers:
        ctx.error(f"{weak_ciphers} negotiated a weak cipher suite.")
    tls13 = next((row for row in rows if row[0] == "TLS 1.3"), None)
    if tls13 and tls13[1] == "yes":
        ctx.ok("TLS 1.3 is available.")
    elif tls13 and tls13[1] == "no":
        ctx.warn("TLS 1.3 is unavailable; prefer servers that offer it.")

    ctx.note("Some networks block TLS 1.0/1.1 at the client, so a refusal can be local.")
    ctx.note("A TLS-inspecting proxy on this machine can also accept old versions on the "
             "server's behalf — confirm unusual results from a second network.")
    ctx.link("SSL Labs", f"https://www.ssllabs.com/ssltest/analyze.html?d={host}")


MODULE = Module(
    id="tls_versions",
    title="TLS Versions",
    category="Web",
    summary="Negotiate each TLS version in turn and flag deprecated protocols or weak ciphers.",
    fields=(
        Field("host", "Hostname", placeholder="example.com", required=True),
        Field("port", "Port", default="443"),
    ),
    run=run,
    order=29,
)
