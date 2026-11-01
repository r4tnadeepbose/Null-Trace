"""CVE research via NVD API 2.0, cross-referenced with CISA's KEV catalogue."""

from __future__ import annotations

import json
import time
from pathlib import Path

from ..config import data_dir
from ..job import Field, Module
from ..net import HttpError, get_json

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KEV_CACHE = data_dir() / "kev.json"
KEV_MAX_AGE = 24 * 3600


def _kev() -> dict[str, dict]:
    fresh = KEV_CACHE.exists() and (time.time() - KEV_CACHE.stat().st_mtime) < KEV_MAX_AGE
    if not fresh:
        try:
            response = get_json(KEV_URL, timeout=45)
            KEV_CACHE.write_text(json.dumps(response), encoding="utf-8")
        except HttpError:
            if not KEV_CACHE.exists():
                return {}
    try:
        data = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {item["cveID"]: item for item in data.get("vulnerabilities", [])}


def _severity(cve: dict) -> tuple[str, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            entry = entries[0]
            data = entry.get("cvssData", {})
            return (str(data.get("baseScore", "?")),
                    str(entry.get("cvssData", {}).get("baseSeverity")
                        or entry.get("baseSeverity") or "unknown").upper())
    return "?", "UNKNOWN"


def _description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return " ".join(desc["value"].split())
    return ""


def run(ctx) -> None:
    query = ctx.value("query").strip()
    if not query:
        ctx.error("Enter a CVE ID, product or keyword.")
        return
    is_id = query.upper().startswith("CVE-")
    limit = 20
    try:
        limit = min(100, max(1, int(ctx.value("limit") or "20")))
    except ValueError:
        pass
    severity_filter = ctx.value("severity") or "Any"

    params = {"resultsPerPage": limit}
    if is_id:
        params["cveId"] = query.upper()
    else:
        params["keywordSearch"] = query
        params["keywordExactMatch"] = ""
    if severity_filter != "Any":
        params["cvssV3Severity"] = severity_filter.upper()

    ctx.title(f"CVE research — {query}")
    ctx.status("Querying NVD ...")
    try:
        data = get_json(NVD, params=params, timeout=45)
    except HttpError as exc:
        ctx.error(f"NVD request failed: {exc}")
        ctx.note("NVD allows ~5 requests per 30 s without a key — wait and retry.")
        return

    total = data.get("totalResults", 0)
    ctx.kv("Matches", total)
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        ctx.warn("No matching CVEs.")
        return

    ctx.status("Loading CISA KEV catalogue ...")
    kev = _kev()
    ctx.kv("KEV catalogue", f"{len(kev)} known-exploited entries")

    rows = []
    details = []
    for item in vulnerabilities:
        ctx.check_cancel()
        cve = item.get("cve", {})
        cve_id = cve.get("id", "?")
        score, severity = _severity(cve)
        details.append((cve_id, score, severity, _description(cve), kev.get(cve_id)))
        rows.append((cve_id, score, severity, "YES" if cve_id in kev else "-",
                     cve.get("published", "")[:10]))
    ctx.section("Results")
    ctx.table(("CVE", "Score", "Severity", "KEV", "Published"), rows)

    exploited = [d for d in details if d[4]]
    if exploited:
        ctx.section("Actively exploited (CISA KEV)")
        for cve_id, score, severity, _desc, entry in exploited:
            ctx.warn(f"  {cve_id}  {severity} {score}  — {entry.get('vulnerabilityName', '')}")
            if entry.get("requiredAction"):
                ctx.note(f"      action: {entry['requiredAction'][:160]}")
            if entry.get("dueDate"):
                ctx.note(f"      remediation due: {entry['dueDate']}")

    ctx.section("Descriptions")
    for cve_id, score, severity, desc, _entry in details[:10]:
        ctx.text(f"  {cve_id}  [{severity} {score}]")
        ctx.text(f"    {desc[:400]}{'...' if len(desc) > 400 else ''}")
        ctx.link("  Details", f"https://nvd.nist.gov/vuln/detail/{cve_id}")

    ctx.note("Only use this for defensive triage: patch what applies to systems you own.")


MODULE = Module(
    id="cve_research",
    title="CVE / Exploits",
    category="Vulnerability",
    summary="Search NVD by CVE ID, product or keyword and flag entries in CISA's Known Exploited catalogue.",
    fields=(
        Field("query", "CVE ID or keyword", placeholder="CVE-2021-44228  |  apache struts",
              required=True),
        Field("severity", "Severity", kind="choice",
              choices=("Any", "Low", "Medium", "High", "Critical"), default="Any"),
        Field("limit", "Max results", default="20"),
    ),
    run=run,
    order=100,
)
