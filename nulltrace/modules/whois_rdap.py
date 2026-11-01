"""WHOIS via RDAP (no API key, structured JSON)."""

from __future__ import annotations

import ipaddress
import json
import time
from datetime import datetime, timezone

from ..config import data_dir
from ..job import Field, Module
from ..net import HttpError, get_json

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_CACHE = data_dir() / "rdap_dns.json"
BOOTSTRAP_MAX_AGE = 7 * 24 * 3600


def _bootstrap() -> dict[str, str]:
    """Map TLD -> RDAP base URL using IANA's bootstrap file (cached for a week)."""
    fresh = BOOTSTRAP_CACHE.exists() and (time.time() - BOOTSTRAP_CACHE.stat().st_mtime) < BOOTSTRAP_MAX_AGE
    if not fresh:
        try:
            data = get_json(BOOTSTRAP_URL, timeout=30)
            BOOTSTRAP_CACHE.write_text(json.dumps(data), encoding="utf-8")
        except HttpError:
            if not BOOTSTRAP_CACHE.exists():
                return {}
    try:
        data = json.loads(BOOTSTRAP_CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    mapping: dict[str, str] = {}
    for service in data.get("services", []):
        urls = [u for u in service[1] if u.startswith("https://")] or service[1]
        if not urls:
            continue
        for tld in service[0]:
            mapping[tld.lower()] = urls[0].rstrip("/")
    return mapping


def _endpoint(target: str, is_ip: bool) -> str:
    if is_ip:
        return f"https://rdap.arin.net/registry/ip/{target}"
    mapping = _bootstrap()
    tld = target.rsplit(".", 1)[-1].lower()
    base = mapping.get(tld)
    if base:
        return f"{base}/domain/{target}"
    return f"https://rdap.org/domain/{target}"


def _vcard(entity: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    card = entity.get("vcardArray")
    items = card[1] if isinstance(card, list) and len(card) > 1 else []
    for item in items:
        if not isinstance(item, list) or len(item) < 4:
            continue
        name = item[0]
        value = item[3]
        if isinstance(value, list):
            value = value[0] if value else ""
        out[name] = str(value)
    return out


def _entities(data: dict) -> list[tuple[str, str, str]]:
    rows = []
    for entity in data.get("entities", []):
        roles = ", ".join(entity.get("roles", [])) or "—"
        card = _vcard(entity)
        label = card.get("org") or card.get("fn") or entity.get("handle", "?")
        email = card.get("email", "")
        if not email:
            for child in entity.get("entities", []) or []:
                child_card = _vcard(child)
                if child_card.get("email"):
                    email = child_card["email"]
                    break
        rows.append((label, roles, email or "—"))
    return rows


def _date(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def run(ctx) -> None:
    target = ctx.value("target").strip().lower()
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    if not target:
        ctx.error("Enter a domain or IP address.")
        return

    kind = "ip" if _is_ip(target) else "domain"
    ctx.title(f"Registration data — {target}")
    ctx.status("Querying RDAP ...")
    endpoint = _endpoint(target, kind == "ip")
    try:
        data = get_json(endpoint, timeout=30, allow_status=(404,))
    except HttpError as exc:
        ctx.error(f"RDAP lookup failed: {exc}")
        ctx.note("Some ccTLD registries (e.g. .in for some registrations) publish no RDAP data.")
        return
    if not data or data.get("errorCode") == 404:
        ctx.warn("The registry returned no record (unsupported TLD or unregistered name).")
        return

    ctx.section("Registration")
    ctx.kv("Handle", data.get("handle") or "—")
    ctx.kv("Name", data.get("ldhName") or data.get("name") or target)
    if kind == "domain" and data.get("unicodeName"):
        ctx.kv("Unicode name", data["unicodeName"])
    if data.get("port43"):
        ctx.kv("WHOIS server", data["port43"])
    ctx.kv("Statuses", ", ".join(data.get("status", [])) or "—")

    if kind == "ip":
        ctx.kv("Network", f"{data.get('startAddress')} – {data.get('endAddress')}")
        ctx.kv("Type", data.get("type") or "—")
        ctx.kv("Country", data.get("country") or "—")
        ctx.kv("Parent", data.get("parentHandle") or "—")

    events = {event.get("eventAction"): event.get("eventDate") for event in data.get("events", [])}
    if events:
        ctx.section("Dates")
        labels = {
            "registration": "Registered", "expiration": "Expires",
            "last changed": "Last changed", "last update of rdap database": "Registry updated",
        }
        for action, label in labels.items():
            if action in events:
                ctx.kv(label, events[action])
        created = _date(events.get("registration", ""))
        expires = _date(events.get("expiration", ""))
        now = datetime.now(timezone.utc)
        if created:
            ctx.kv("Age", f"{(now - created).days:,} days")
        if expires:
            remaining = (expires - now).days
            ctx.kv("Expires in", f"{remaining:,} days")
            if remaining < 30:
                ctx.warn("Domain expires within 30 days — common in phishing infrastructure.")

    nameservers = [ns.get("ldhName") or ns.get("unicodeName") for ns in data.get("nameservers", [])]
    if nameservers:
        ctx.section("Nameservers")
        for ns in nameservers:
            ctx.text(f"  {ns}")

    rows = _entities(data)
    if rows:
        ctx.section("Contacts")
        ctx.table(("Entity", "Roles", "Email"), rows)
        registrar = next((r for r in rows if "registrar" in r[1].lower()), None)
        if registrar:
            ctx.kv("Registrar", registrar[0])

    if data.get("secureDNS") is not None:
        ctx.section("DNSSEC")
        ctx.kv("Delegation signed", "yes" if data["secureDNS"].get("delegationSigned") else "no")

    ctx.link("Open in RDAP", f"https://rdap.org/{kind}/{target}")
    ctx.link("WhoisXML view", f"https://www.whoisxmlapi.com/whois-lookup?domainName={target}")
    ctx.note("Registrant details are redacted for most gTLDs since GDPR; only the registrar is public.")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


MODULE = Module(
    id="whois_rdap",
    title="WHOIS / RDAP",
    category="Web",
    summary="Domain or IP registration data: registrar, dates, statuses, nameservers and contacts.",
    fields=(
        Field("target", "Domain or IP", placeholder="example.com", required=True),
    ),
    run=run,
    order=25,
)
