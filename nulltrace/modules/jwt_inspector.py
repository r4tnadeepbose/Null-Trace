"""JWT inspection: decode header and claims, flag weak or unsafe settings."""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone

from ..job import Field, Module

SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")


def _decode(segment: str) -> dict | None:
    if not SEGMENT.match(segment):
        return None
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode())
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _when(value) -> str:
    try:
        stamp = int(value)
    except (TypeError, ValueError):
        return str(value)
    try:
        return datetime.fromtimestamp(stamp, timezone.utc).isoformat(sep=" ", timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return str(value)


def inspect(token: str) -> tuple[dict | None, dict | None, int, bool]:
    parts = token.split(".")
    signature_ok = len(parts) == 3 and bool(parts[2])
    header = _decode(parts[0]) if parts else None
    payload = _decode(parts[1]) if len(parts) > 1 else None
    return header, payload, len(parts), signature_ok


def run(ctx) -> None:
    token = ctx.value("token").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token:
        ctx.error("Paste a JWT.")
        return

    header, payload, segments, signed = inspect(token)
    ctx.title("JWT inspector")
    ctx.kv("Segments", segments)
    ctx.kv("Signature present", "yes" if signed else "NO")
    if header is None:
        ctx.error("The header is not valid base64url JSON — is this a JWT?")
        return

    ctx.section("Header")
    for key, value in header.items():
        ctx.kv(key, value)
    alg = str(header.get("alg", "")).upper()
    kid = header.get("kid")

    ctx.section("Verification")
    if alg == "NONE":
        ctx.error("alg=none — the token is unsigned and can be forged by anyone.")
    elif not signed:
        ctx.error("No signature segment — reject any token shaped like this.")
    else:
        ctx.ok("Signature segment present (not verified — NullTrace holds no key).")
    if alg.startswith("HS"):
        ctx.warn(f"{alg} is symmetric: anyone with the shared secret can mint tokens.")
    if kid:
        ctx.note(f"Key id '{kid}' — a server that trusts the header can be tricked into "
                 "verifying with the wrong key.")

    if payload is None:
        ctx.warn("Claims could not be decoded.")
        return

    ctx.section("Claims")
    standard = ("iss", "sub", "aud", "exp", "nbf", "iat", "jti", "scope", "roles")
    for key in standard:
        if key in payload:
            value = payload[key]
            if key in ("exp", "nbf", "iat"):
                ctx.kv(key, _when(value))
            else:
                ctx.kv(key, value)
    extra = [key for key in payload if key not in standard]
    if extra:
        ctx.kv("Other claims", ", ".join(extra))

    now = datetime.now(timezone.utc)
    timing = []
    for key, label in (("exp", "Expires"), ("nbf", "Not before"), ("iat", "Issued")):
        if key not in payload:
            continue
        try:
            moment = datetime.fromtimestamp(int(payload[key]), timezone.utc)
        except (TypeError, ValueError, OverflowError, OSError):
            continue
        timing.append((key, label, moment))
    if timing:
        ctx.section("Timing")
    for key, label, moment in timing:
        delta = (moment - now).total_seconds()
        ctx.kv(label, _when(payload[key]))
        if key == "exp":
            if delta < 0:
                ctx.error("Token has expired.")
            elif delta < 300:
                ctx.warn("Token expires in under five minutes.")
            elif delta > 60 * 60 * 24 * 30:
                ctx.warn("Lifetime over 30 days — long-lived tokens raise the blast radius.")

    ctx.section("Notes")
    ctx.note("Decoding proves nothing about validity: only the issuer can verify the signature.")
    ctx.note("Never paste production tokens into third-party sites; this runs locally.")
    ctx.link("jwt.io (manual)", "https://jwt.io/")


MODULE = Module(
    id="jwt_inspector",
    title="JWT Inspector",
    category="Utility",
    summary="Decode a JSON Web Token locally, list claims and flag alg=none, weak algorithms and long lifetimes.",
    fields=(
        Field("token", "JWT", kind="multiline", required=True,
              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
              help="Decoded on this machine only; nothing is sent anywhere."),
    ),
    run=run,
    order=10,
)
