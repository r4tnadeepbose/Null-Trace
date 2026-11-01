"""Quick Recon: one target in, a full sweep and a findings summary out."""

from __future__ import annotations

import re

from ..job import Field, Module
from ..net import DOMAIN_RE, EMAIL_RE, is_ip, resolve
from . import (
    dns_tools,
    email_intel,
    exposure_audit,
    hash_lookup,
    host_search,
    ip_info,
    phone_info,
    port_scan,
    subdomains,
    username_scan,
    vin,
    whois_rdap,
)

VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$", re.IGNORECASE)
HEX_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.IGNORECASE)
PHONE_RE = re.compile(r"^\+?[\d][\d\s().-]{5,}$")


def detect(raw: str) -> tuple[str, str]:
    """Return (kind, normalised value). Order matters: most specific first."""
    value = raw.strip()
    if is_ip(value):
        return "ip", value
    if EMAIL_RE.match(value):
        return "email", value.lower()
    if VIN_RE.match(value):
        return "vin", value.upper()
    if HEX_RE.match(value):
        return "hash", value.lower()
    if PHONE_RE.match(value) and sum(ch.isdigit() for ch in value) >= 7:
        return "phone", value
    if DOMAIN_RE.match(value):
        return "domain", value.lower().rstrip(".")
    if "://" in value:
        host = value.split("//", 1)[1].split("/")[0]
        return ("domain", host.lower()) if DOMAIN_RE.match(host) else ("username", value)
    return "username", value.lstrip("@")


class SubContext:
    """Forwards a child module's output into the parent, counting findings."""

    def __init__(self, parent, inputs: dict, label: str) -> None:
        self._parent = parent
        self.inputs = inputs
        self.cancel_event = parent.cancel_event
        self.label = label

    # ---- input -------------------------------------------------------
    def value(self, name: str) -> str:
        value = self.inputs.get(name, "")
        return str(value).strip() if not isinstance(value, bool) else value

    def checked(self, name: str) -> bool:
        return bool(self.inputs.get(name))

    def key(self, name: str) -> str:
        return self._parent.key(name)

    def require_key(self, name: str, human: str):
        return self._parent.require_key(name, human)

    # ---- output ------------------------------------------------------
    def title(self, text: str) -> None:
        self._parent.muted(f"» {text}")

    def section(self, text: str) -> None:
        self._parent._out("section", text)

    def status(self, text: str) -> None:
        self._parent.status(f"{self.label}: {text}")

    def kv(self, label: str, value) -> None:
        self._parent._rows += 1
        self._parent.kv(label, value)

    def table(self, headers, rows) -> None:
        rows = list(rows)
        self._parent.table(headers, rows)
        self._parent._rows += len(rows)

    def text(self, text: str) -> None:
        self._parent.text(text)

    def link(self, label: str, url: str) -> None:
        self._parent.link(label, url)

    def ok(self, text: str) -> None:
        self._parent.ok(text)

    def warn(self, text: str) -> None:
        self._parent._warnings += 1
        self._parent.warn(text)

    def error(self, text: str) -> None:
        self._parent._errors += 1
        self._parent.error(text)

    def muted(self, text: str) -> None:
        self._parent.muted(text)

    def note(self, text: str) -> None:
        self._parent.note(text)

    # ---- control -----------------------------------------------------
    def check_cancel(self) -> None:
        self._parent.check_cancel()

    def sleep(self, seconds: float) -> None:
        self._parent.sleep(seconds)

    def _out(self, kind: str, text: str) -> None:
        self._parent._out(kind, text)


PLANS: dict[str, list[str]] = {
    "ip": ["ip_info", "port_scan"],
    "domain": ["dns_lookup", "whois_rdap", "host_search", "subdomains"],
    "email": ["email_intel", "exposure_audit"],
    "phone": ["phone_info"],
    "vin": ["vin"],
    "hash": ["hash_lookup"],
    "username": ["username_scan"],
}


def _inputs_for(kind: str, value: str) -> dict[str, dict]:
    if kind == "ip":
        return {
            "ip_info": {"target": value},
            "port_scan": {"host": value, "preset": "Top 100", "ports": "",
                          "timeout": "0.8", "banner": True},
        }
    if kind == "domain":
        return {
            "dns_lookup": {"domain": value, "rtype": "ALL", "common": False},
            "whois_rdap": {"target": value},
            "host_search": {"target": value, "tls": True},
            "subdomains": {"domain": value, "resolve": True, "brute": False},
        }
    if kind == "email":
        return {
            "email_intel": {"email": value},
            "exposure_audit": {"email": value, "phone": "", "name": "",
                               "breach": True, "stealer": True, "dns": True,
                               "footprint": True},
        }
    if kind == "phone":
        return {"phone_info": {"number": value, "region": ""}}
    if kind == "vin":
        return {"vin": {"vin": value}}
    if kind == "hash":
        return {"hash_lookup": {"value": value}}
    return {"username_scan": {"username": value, "scope": "All"}}


RUNNERS = {
    "ip_info": ip_info.MODULE,
    "port_scan": port_scan.MODULE,
    "dns_lookup": dns_tools.DNS_LOOKUP,
    "whois_rdap": whois_rdap.MODULE,
    "host_search": host_search.MODULE,
    "subdomains": subdomains.MODULE,
    "email_intel": email_intel.MODULE,
    "exposure_audit": exposure_audit.MODULE,
    "phone_info": phone_info.MODULE,
    "vin": vin.MODULE,
    "hash_lookup": hash_lookup.MODULE,
    "username_scan": username_scan.MODULE,
}

KIND_LABEL = {
    "ip": "IP address", "domain": "Domain", "email": "Email address",
    "phone": "Phone number", "vin": "VIN", "hash": "File hash",
    "username": "Username",
}


def run(ctx) -> None:
    raw = ctx.value("target")
    if not raw:
        ctx.error("Enter a domain, IP, email, phone, VIN, hash or username.")
        return

    kind, value = detect(raw)
    plan = PLANS[kind]
    ctx._warnings = 0
    ctx._errors = 0
    ctx._rows = 0

    ctx.title(f"Quick recon — {value}")
    ctx.table(("Field", "Value"), (
        ("Detected", KIND_LABEL[kind]),
        ("Target", value),
        ("Modules", ", ".join(plan)),
    ))
    ctx.muted("Detected from the input shape. Every step below is a normal module; "
              "run any of them alone for more control.")

    for module_id in plan:
        ctx.check_cancel()
        module = RUNNERS[module_id]
        ctx.section(module.title)
        child = SubContext(ctx, _inputs_for(kind, value)[module_id], module.title)
        try:
            module.run(child)
        except Exception as exc:  # a broken step must not stop the sweep
            ctx._errors += 1
            ctx.error(f"{module.title} failed: {type(exc).__name__}: {exc}")

    if kind == "domain":
        ctx.check_cancel()
        addresses = resolve(value)
        if addresses:
            ctx.section("Resolved host")
            child = SubContext(ctx, {"target": addresses[0]}, "IP Intel")
            try:
                ip_info.MODULE.run(child)
            except Exception as exc:
                ctx.warn(f"Host lookup failed: {exc}")

    ctx.check_cancel()
    ctx.section("Findings")
    risk = "high" if ctx._errors else ("elevated" if ctx._warnings else "baseline")
    ctx.table(("Measure", "Value"), (
        ("Modules run", len(plan)),
        ("Rows returned", ctx._rows),
        ("Warnings", ctx._warnings),
        ("Errors", ctx._errors),
        ("Assessment", risk),
    ))
    if ctx._warnings or ctx._errors:
        ctx.warn("Warnings above are worth reading before you act on this target.")
    else:
        ctx.ok("Every step completed without warnings.")
    ctx.note("Quick recon is a starting point, not a verdict. Pivot into a module for detail.")


MODULE = Module(
    id="auto_recon",
    title="Quick Recon",
    category="Recon",
    summary="One target in — domain, IP, email, phone, VIN, hash or username — "
            "swept across the matching modules with a findings summary.",
    fields=(
        Field("target", "Target", required=True,
              placeholder="example.com · 1.1.1.1 · someone@example.com · +14155552671",
              help="The type is detected automatically; no need to pick a module."),
    ),
    run=run,
    order=1,
)
