"""Identify the algorithm behind a hash string, offline."""

from __future__ import annotations

import re

from ..job import Field, Module

PATTERNS: list[tuple[str, str, str]] = [
    (r"^[a-f0-9]{32}$", "MD5", "128-bit hex"),
    (r"^[a-f0-9]{40}$", "SHA-1", "160-bit hex"),
    (r"^[a-f0-9]{56}$", "SHA-224", "224-bit hex"),
    (r"^[a-f0-9]{64}$", "SHA-256", "256-bit hex"),
    (r"^[a-f0-9]{96}$", "SHA-384", "384-bit hex"),
    (r"^[a-f0-9]{128}$", "SHA-512", "512-bit hex"),
    (r"^[a-f0-9]{16}$", "MySQL323 / DES crypt", "64-bit hex"),
    (r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$", "MD5 crypt", "$1$ prefix"),
    (r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt", "$2a$/$2b$/$2y$ prefix"),
    (r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$", "SHA-256 crypt", "$5$ prefix"),
    (r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$", "SHA-512 crypt", "$6$ prefix"),
    (r"^\$argon2(id|i|d)\$", "Argon2", "$argon2 prefix"),
    (r"^\$scrypt\$", "scrypt", "$scrypt prefix"),
    (r"^[a-f0-9]{32}:[a-f0-9]{32}$", "NTLM (LM:NT pair)", "two 32-hex halves"),
    (r"^\{SSHA\}[A-Za-z0-9+/=]{20,}$", "SSHA (LDAP)", "base64 after {SSHA}"),
    (r"^[A-Za-z0-9+/]{27}=$", "bcrypt (base64 variant)", "28 chars ending in ="),
]

UPPER_NOTE = "Upper-case letters suggest NTLM or a case-insensitive hex digest."


def identify(value: str) -> list[tuple[str, str]]:
    matches = []
    for pattern, name, detail in PATTERNS:
        if re.match(pattern, value):
            matches.append((name, detail))
    return matches


def run(ctx) -> None:
    raw = ctx.value("hash").strip()
    if not raw:
        ctx.error("Paste a hash.")
        return
    ctx.title("Hash identifier")
    ctx.kv("Length", len(raw))
    ctx.kv("Characters", "hex" if re.fullmatch(r"[A-Fa-f0-9]+", raw) else "mixed")

    matches = identify(raw)
    ctx.section("Candidates")
    if matches:
        for name, detail in matches:
            ctx.text(f"  {name}  ({detail})")
        if len(matches) > 1:
            ctx.note("Several algorithms share this shape; the source decides which it is.")
    else:
        ctx.warn("No known format matched.")
        ctx.note("Truncated or salted hashes often fail to match; check how it was produced.")

    ctx.section("Context")
    if raw == raw.upper() and re.fullmatch(r"[A-F0-9]+", raw):
        ctx.note(UPPER_NOTE)
    if len(raw) <= 32:
        ctx.warn("Short digests (MD5/SHA-1) are fast to brute force — treat them as broken for passwords.")

    ctx.section("Lookup")
    ctx.link("VirusTotal hash search", f"https://www.virustotal.com/gui/search/{raw}")
    ctx.link("Hashes.com", "https://hashes.com/en/decrypt/hash")
    ctx.note("Submitting a hash to a public cracking site can reveal the original secret; only do it for data you own.")


MODULE = Module(
    id="hash_identify",
    title="Hash Identifier",
    category="Utility",
    summary="Name the likely algorithm from a digest's shape, with a warning for weak and short hashes.",
    fields=(
        Field("hash", "Hash value", required=True,
              placeholder="5f4dcc3b5aa765d61d8327deb882cf99"),
    ),
    run=run,
    order=20,
)
