"""Static file triage: entropy, printable strings and observable indicators."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path

from ..job import Field, Module

STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SUSPICIOUS = ("powershell", "cmd.exe /c", "wscript", "mshta", "regsvr32", "rundll32",
              "base64", "invoke-expression", "downloadstring", "bitcoin", "wallet",
              "onion", "miner", "http://")


def _entropy(path: Path) -> float:
    counter = Counter()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            counter.update(chunk)
            total += len(chunk)
    if not total:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def run(ctx) -> None:
    raw = ctx.value("path").strip().strip('"')
    if not raw:
        ctx.error("Choose a file.")
        return
    path = Path(raw).expanduser()
    if not path.is_file():
        ctx.error(f"File not found: {path}")
        return

    size = path.stat().st_size
    ctx.title(f"File triage — {path.name}")
    ctx.kv("Size", f"{size / 1024:,.1f} KB")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    ctx.kv("SHA256", digest.hexdigest())

    ctx.status("Measuring entropy ...")
    entropy = _entropy(path)
    ctx.section("Shape")
    ctx.kv("Entropy", f"{entropy:.2f} bits/byte")
    if entropy > 7.5:
        ctx.warn("High entropy — packed, encrypted or compressed payload.")
    elif entropy > 6.5:
        ctx.note("Moderate entropy, typical of compiled binaries.")
    else:
        ctx.ok("Low entropy, typical of text or structured data.")

    with path.open("rb") as handle:
        head = handle.read(16)
    kind = "unknown"
    if head[:2] == b"MZ":
        kind = "PE executable"
    elif head[:4] == b"\x7fELF":
        kind = "ELF executable"
    elif head[:4] == b"\xca\xfe\xba\xbe":
        kind = "Mach-O universal"
    elif head[:4] == b"%PDF":
        kind = "PDF document"
    elif head[:2] == b"PK":
        kind = "ZIP container"
    elif head[:4] == b"\x89PNG":
        kind = "PNG image"
    elif head[:3] == b"\xff\xd8\xff":
        kind = "JPEG image"
    ctx.kv("Header", f"{head.hex(' ').upper()} ({kind})")

    ctx.check_cancel()
    ctx.status("Extracting strings ...")
    found: list[tuple[str, str]] = []
    if 0 < size <= 40 * 1024 * 1024:
        with path.open("rb") as handle:
            blob = handle.read()
        strings = [s.decode("ascii", "replace") for s in STRING_RE.findall(blob)]
        ctx.kv("Printable strings", len(strings))
        for label, pattern in (("URLs", URL_RE), ("Emails", EMAIL_RE), ("IPs", IP_RE)):
            matches = sorted({m if isinstance(m, str) else m.group(0) for m in pattern.findall("\n".join(strings))})
            ctx.kv(label, len(matches))
            for value in matches[:12]:
                found.append((label, value))
        if found:
            ctx.section("Indicators")
            for label, value in found:
                ctx.text(f"  [{label}] {value}")

        haystack = "\n".join(strings).lower()
        hits = [word for word in SUSPICIOUS if word in haystack]
        if hits:
            ctx.section("Suspicious tokens")
            for word in hits[:12]:
                ctx.warn(f"  {word}")
        else:
            ctx.ok("No obvious script or download tokens found.")
    else:
        ctx.muted("Strings skipped: the file is larger than 40 MB.")

    ctx.section("Next")
    ctx.link("VirusTotal", f"https://www.virustotal.com/gui/file/{digest.hexdigest()}")
    ctx.link("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{digest.hexdigest()}")
    ctx.note("Never execute a sample to see what it does; analyse the bytes instead.")


MODULE = Module(
    id="file_triage",
    title="File Triage",
    category="Media",
    summary="Entropy, header type, printable strings and URL/IP/email indicators in a suspicious file.",
    fields=(
        Field("path", "File", kind="file", placeholder="C:\\samples\\sample.bin", required=True),
    ),
    run=run,
    order=78,
)
