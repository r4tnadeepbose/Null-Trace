"""Infostealer exposure lookups against Hudson Rock's free Cavalier API."""

from __future__ import annotations

from ..job import Field, Module
from ..net import HttpError, get_json

BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
MODES = {
    "Email": ("search-by-email", "email", "someone@example.com"),
    "Username": ("search-by-username", "username", "johndoe"),
    "Domain": ("search-by-domain", "domain", "example.com"),
}


def _pluck(data: dict) -> tuple[str, list[dict]]:
    """Normalise the three endpoint shapes into a message and a stealer list."""
    message = str(data.get("message") or "").strip()
    candidates: list[dict] = []
    blob = data.get("data")
    for source in (blob, data):
        if isinstance(source, dict):
            for key in ("stealers", "stealer", "employees_stealers", "users_stealers"):
                value = source.get(key)
                if isinstance(value, list):
                    candidates.extend(item for item in value if isinstance(item, dict))
    if not candidates and isinstance(blob, dict):
        candidates = [blob] if any(k in blob for k in ("computer_name", "stealer", "malware_path")) else []
    return message, candidates


def run(ctx) -> None:
    mode = ctx.value("mode") or "Email"
    endpoint, param, placeholder = MODES.get(mode, MODES["Email"])
    query = ctx.value("query").strip()
    if not query:
        ctx.error(f"Enter the {mode.lower()} to look up.")
        return

    ctx.title(f"Infostealer exposure — {query}")
    ctx.muted("Source: Hudson Rock Cavalier (free OSINT API) — logs from machines infected by malware.")
    ctx.status("Querying Cavalier ...")
    try:
        data = get_json(f"{BASE}/{endpoint}?{param}={query}", timeout=30,
                        allow_status=(404, 429))
    except HttpError as exc:
        ctx.error(f"Lookup failed: {exc}")
        return

    if not isinstance(data, dict):
        ctx.error("Unexpected response format.")
        return

    message, stealers = _pluck(data)
    total = data.get("total") or len(stealers)
    if message and not stealers:
        ctx.ok(message)
    if isinstance(total, int):
        ctx.kv("Infections found", total)

    if not stealers:
        if not message:
            ctx.ok("No infostealer records found for this query.")
        ctx.note("Absence of records is not proof of a clean machine — coverage is limited.")
        return

    ctx.warn(f"Credentials may have leaked from {len(stealers)} infected machine(s).")
    ctx.note("Rotate passwords, revoke sessions and enable MFA on every affected account.")

    ctx.section("Infected machines")
    rows = []
    for item in stealers[:40]:
        ctx.check_cancel()
        rows.append((
            (item.get("computer_name") or item.get("computerName") or "—")[:34],
            (item.get("operating_system") or item.get("operatingSystem") or "—")[:28],
            item.get("ip") or "—",
            (item.get("date_compromised") or item.get("dateCompromised") or "—")[:19],
            (item.get("malware_path") or item.get("malwarePath") or "—")[:40],
        ))
    ctx.table(("Computer", "OS", "IP", "Compromised", "Malware path"), rows)

    antivirus = sorted({
        str(item.get("antivirus") or "").strip()
        for item in stealers if item.get("antivirus")
    })
    if antivirus:
        ctx.kv("Antivirus present", ", ".join(antivirus[:12]))

    ctx.section("What leaked")
    for label in ("stealer_family", "top_passwords", "top_logins", "top_cookies",
                  "top_domains", "passwords", "logins"):
        value = data.get(label) if label in data else None
        if value:
            ctx.text(f"  {label}: {str(value)[:300]}")
    ctx.link("Check in Cavalier", f"https://cavalier.hudsonrock.com/")
    ctx.link("HaveIBeenPwned", f"https://haveibeenpwned.com/")


MODULE = Module(
    id="infostealer",
    title="Infostealer Exposure",
    category="Identity",
    summary="Check whether an email, username or domain appears in infostealer malware logs (Hudson Rock).",
    fields=(
        Field("mode", "Search by", kind="choice", choices=tuple(MODES), default="Email"),
        Field("query", "Value", placeholder="someone@example.com", required=True),
    ),
    run=run,
    order=140,
)
