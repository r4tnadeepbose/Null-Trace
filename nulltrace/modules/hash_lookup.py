"""File and text hashing with optional VirusTotal reputation."""

from __future__ import annotations

import hashlib
import mimetypes
from pathlib import Path

from ..job import Field, Module
from ..net import HttpError, get_json

CHUNK = 1 << 20


def _hash_file(path: Path) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"MD5": md5.hexdigest(), "SHA1": sha1.hexdigest(), "SHA256": sha256.hexdigest()}


def run(ctx) -> None:
    raw = ctx.value("value").strip().strip('"')
    if not raw:
        ctx.error("Enter text or a file path.")
        return
    path = Path(raw).expanduser()
    is_file = path.is_file() and "\n" not in raw

    ctx.title("Hash lookup")
    digests: dict[str, str] = {}
    if is_file:
        ctx.kv("Input", f"file · {path.name}")
        try:
            size = path.stat().st_size
            digests = _hash_file(path)
        except OSError as exc:
            ctx.error(f"Could not read file: {exc}")
            return
        ctx.kv("Size", f"{size / 1024:,.1f} KB")
        mime, _ = mimetypes.guess_type(path.name)
        ctx.kv("MIME (by extension)", mime or "unknown")
        with path.open("rb") as handle:
            head = handle.read(8)
        ctx.kv("Magic bytes", head.hex(" ").upper())
        if head[:4] == b"MZ":
            ctx.warn("PE executable signature (MZ) — treat as untrusted.")
        elif head[:4] == b"\x7fELF":
            ctx.warn("ELF binary signature — treat as untrusted.")
        elif head[:2] == b"PK":
            ctx.muted("ZIP container (also used by .docx/.xlsx/.jar/.apk).")
        elif head[:4] == b"%PDF":
            ctx.muted("PDF document.")
    else:
        ctx.kv("Input", f"text · {len(raw)} characters")
        data = raw.encode("utf-8")
        digests = {
            "MD5": hashlib.md5(data).hexdigest(),
            "SHA1": hashlib.sha1(data).hexdigest(),
            "SHA256": hashlib.sha256(data).hexdigest(),
        }

    ctx.section("Hashes")
    for name, value in digests.items():
        ctx.kv(name, value)

    ctx.check_cancel()
    key = ctx.key("virustotal")
    if key:
        ctx.section("VirusTotal")
        ctx.status("Querying VirusTotal ...")
        try:
            data = get_json(f"https://www.virustotal.com/api/v3/files/{digests['SHA256']}",
                            headers={"x-apikey": key}, timeout=25,
                            allow_status=(404, 401, 403, 429))
        except HttpError as exc:
            ctx.error(f"VirusTotal request failed: {exc}")
            data = {}
        if not data:
            ctx.muted("VirusTotal has no record for this hash.")
        else:
            attributes = (data.get("data") or {}).get("attributes") or {}
            stats = attributes.get("last_analysis_stats") or {}
            if not stats:
                ctx.muted("VirusTotal returned no analysis for this hash.")
            else:
                ctx.kv("Malicious", stats.get("malicious", 0))
                ctx.kv("Suspicious", stats.get("suspicious", 0))
                ctx.kv("Undetected", stats.get("undetected", 0))
                ctx.kv("Harmless", stats.get("harmless", 0))
                ctx.kv("Type", attributes.get("type_description", "—"))
                ctx.kv("Names", ", ".join((attributes.get("names") or [])[:5]) or "—")
                if stats.get("malicious"):
                    ctx.error(f"{stats['malicious']} engine(s) flag this object.")
                else:
                    ctx.ok("No engine flags this hash.")
    else:
        ctx.muted("No VirusTotal key — hashes only. Add a key in Settings for reputation.")

    ctx.section("Lookup")
    sha = digests["SHA256"]
    for label, url in (
        ("VirusTotal", f"https://www.virustotal.com/gui/file/{sha}"),
        ("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{sha}"),
        ("Hybrid Analysis", f"https://www.hybrid-analysis.com/search?query={sha}"),
        ("Triage", f"https://tria.ge/s?q={sha}"),
    ):
        ctx.link(f"  {label}", url)
    ctx.note("Never execute an unknown file to 'see what it does' — hash it first.")


MODULE = Module(
    id="hash_lookup",
    title="Hash Lookup",
    category="Media",
    summary="MD5/SHA1/SHA256 for a file or text, file-type heuristics and VirusTotal reputation.",
    fields=(
        Field("value", "File or text", kind="file", placeholder="C:\\path\\to\\file.exe", required=True,
              help="Pick a file, or type text to hash it."),
    ),
    keys=("virustotal",),
    run=run,
    order=75,
)
