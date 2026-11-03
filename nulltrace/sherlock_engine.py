"""Bridge between Null-Trace and the vendored Sherlock engine.

`sherlock_project/` (repo root) is an unmodified copy of Sherlock 0.16.2 except
for two Null-Trace patches: a packaging-free version string and an openpyxl
.xlsx writer instead of pandas. Everything else — the 480-site manifest, the
per-site probe logic, soft404 handling, upstream false-positive exclusions,
WAF detection — is upstream behaviour reached through this module.
"""

from __future__ import annotations

import csv
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from .config import data_dir

ROOT = Path(__file__).resolve().parent.parent
RESOURCES = Path("sherlock_project") / "resources"


def resource_path(name: str) -> Path:
    """Locate a bundled engine resource in source checkout or frozen build."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / RESOURCES / name
    return ROOT / RESOURCES / name


BUNDLED_MANIFEST = resource_path("data.json")
LIVE_MANIFEST = "https://data.sherlockproject.xyz"


class EngineError(RuntimeError):
    """The vendored engine could not be imported."""


def _ready() -> None:
    try:
        import sherlock_project  # noqa: F401
    except ImportError:
        sys.path.insert(0, str(ROOT))
    try:
        import sherlock_project  # noqa: F401
    except ImportError as exc:  # broken install, say so plainly
        raise EngineError(f"Vendored Sherlock engine is missing or broken: {exc}") from exc


def engine_version() -> str:
    _ready()
    from sherlock_project import __version__
    return __version__


def missing_dependency() -> str | None:
    """Return the human name of the first engine dependency that is absent."""
    import importlib.util

    for module, package in (("requests_futures", "requests-futures"),
                            ("colorama", "colorama")):
        if importlib.util.find_spec(module) is None:
            return package
    return None


# ---------------------------------------------------------------- sites ------

@dataclass
class SitePlan:
    """The set of sites a scan will probe, plus how it was decided."""

    site_data: dict = field(default_factory=dict)
    manifest: str = ""
    manifest_error: str = ""
    honor_exclusions: bool = True
    nsfw_total: int = 0
    unknown_sites: tuple[str, ...] = ()


def build_plan(*, live: bool = False, manifest_path: str | None = None,
               only: Iterable[str] = (),
               skip: Iterable[str] = (), include_nsfw: bool = False,
               honor_exclusions: bool = True) -> SitePlan:
    """Assemble site data the way upstream ``sherlock`` does.

    ``only`` mirrors ``--site``, ``skip`` is a Null-Trace extra (never probe
    these), ``honor_exclusions`` mirrors ``--ignore-exclusions``,
    ``include_nsfw`` mirrors ``--nsfw`` and ``manifest_path`` mirrors ``--json``.
    """
    _ready()
    from sherlock_project.sites import SitesInformation

    only_list = [s.strip() for s in only if s and s.strip()]
    if manifest_path:
        manifest = manifest_path
    elif live:
        manifest = LIVE_MANIFEST
    else:
        manifest = str(BUNDLED_MANIFEST)
    plan = SitePlan(manifest=manifest, honor_exclusions=honor_exclusions)

    def _load(path: str, honor: bool) -> SitesInformation:
        return SitesInformation(data_file_path=path, honor_exclusions=honor,
                                do_not_exclude=only_list)

    try:
        sites = _load(manifest, honor_exclusions)
    except Exception as exc:  # manifest unreachable or malformed
        plan.manifest_error = str(exc).strip().splitlines()[0][:180]
        if manifest == LIVE_MANIFEST:
            # The live manifest needs network; fall back to the bundled copy.
            plan.manifest = str(BUNDLED_MANIFEST)
            sites = _load(plan.manifest, honor_exclusions)
        else:
            raise
    if plan.manifest_error:
        plan.honor_exclusions = False

    plan.nsfw_total = sum(1 for info in sites.sites.values() if info.is_nsfw)
    if not include_nsfw:
        sites.remove_nsfw_sites(do_not_remove=only_list)

    all_sites = {site.name: site.information for site in sites}
    skip_list = {s.strip().casefold() for s in skip if s and s.strip()}
    if skip_list:
        all_sites = {n: i for n, i in all_sites.items() if n.casefold() not in skip_list}

    if only_list:
        lookup = {n.casefold(): n for n in all_sites}
        chosen: dict[str, dict] = {}
        missing: list[str] = []
        for wanted in only_list:
            key = wanted.casefold()
            if key in lookup:
                chosen[lookup[key]] = all_sites[lookup[key]]
            else:
                missing.append(wanted)
        plan.unknown_sites = tuple(missing)
        all_sites = chosen

    plan.site_data = all_sites
    return plan


def site_names(site_data: dict) -> list[str]:
    return sorted(site_data)


# ---------------------------------------------------------------- probe ------

@dataclass
class SiteRow:
    site: str
    status: str = ""           # found | free | blocked | error | illegal
    verdict: str = ""           # upstream wording, e.g. "Claimed"
    url: str = ""
    url_main: str = ""
    http_status: str = ""
    reason: str = ""
    seconds: float | None = None


def _make_collector(on_result: Callable[[SiteRow], None] | None, cancel):
    """Build a QueryNotify that collects rows and aborts on request.

    ``sherlock()`` calls ``update()`` once per site from its result loop, and
    nothing inside that loop catches a raised exception, so raising here is the
    supported way to honour the Stop button.
    """
    _ready()
    from sherlock_project.notify import QueryNotify

    class Collector(QueryNotify):
        def __init__(self) -> None:
            super().__init__()
            self.rows: dict[str, SiteRow] = {}

        def start(self, message=None) -> None:
            return None

        def finish(self, message=None) -> None:
            return None

        def update(self, result) -> None:
            if cancel is not None and cancel.is_set():
                from .net import Cancelled
                raise Cancelled()
            row = classify(result)
            self.rows[row.site] = row
            if on_result is not None:
                on_result(row)

    return Collector()


def classify(result) -> SiteRow:
    """Map an upstream QueryResult onto a Null-Trace table row."""
    from sherlock_project.result import QueryStatus

    status = result.status
    verdict = str(status)
    reason = (result.context or "").strip()
    if status == QueryStatus.CLAIMED:
        label = "found"
    elif status == QueryStatus.AVAILABLE:
        label = "free"
    elif status == QueryStatus.WAF:
        label = "blocked"
        reason = reason or "Web application firewall answered instead of the profile"
    elif status == QueryStatus.ILLEGAL:
        label = "illegal"
        reason = reason or "Username does not match this site's rules"
    else:
        lowered = reason.casefold()
        if "429" in lowered or "too many requests" in lowered:
            label = "blocked"
            reason = reason or "Rate limited (HTTP 429)"
        else:
            label = "error"
    return SiteRow(site=result.site_name, status=label, verdict=verdict,
                   url=result.site_url_user or "", seconds=result.query_time,
                   reason=reason)


def probe(username: str, site_data: dict, *, proxy: str | None = None,
          timeout: float = 15.0, on_result: Callable[[SiteRow], None] | None = None,
          cancel=None, dump_response: bool = False
          ) -> tuple[list[SiteRow], bool, float]:
    """Run one username over the whole plan. Returns rows, aborted, elapsed."""
    _ready()
    from sherlock_project.sherlock import sherlock

    from .net import Cancelled

    collector = _make_collector(on_result, cancel)
    started = time.monotonic()
    raw: dict | None = None
    aborted = False
    try:
        raw = sherlock(username, site_data, collector,
                       dump_response=dump_response, proxy=proxy or None,
                       timeout=int(timeout))
    except Cancelled:
        aborted = True
    elapsed = time.monotonic() - started

    if raw:
        for site, info in raw.items():
            row = collector.rows.get(site)
            if row is None:
                row = SiteRow(site=site, status="error", verdict="Unknown",
                              reason="No verdict returned")
                collector.rows[site] = row
            row.url_main = str(info.get("url_main") or "")
            row.http_status = str(info.get("http_status") or "")
            if not row.url:
                row.url = str(info.get("url_user") or "")
    return list(collector.rows.values()), aborted, elapsed


# ------------------------------------------------------------- username ------

def expand_variants(username: str) -> list[str]:
    """Expand ``name{?}tail`` into the three separator variants upstream uses."""
    _ready()
    from sherlock_project.sherlock import check_for_parameter, multiple_usernames

    if check_for_parameter(username):
        return multiple_usernames(username)
    return [username]


def parse_usernames(raw: str) -> list[str]:
    """Split a multi-line/comma/space list into unique, ``@``-free tokens."""
    tokens: list[str] = []
    for chunk in raw.replace(",", " ").replace(";", " ").split():
        name = chunk.strip().lstrip("@")
        if name and name not in tokens:
            tokens.append(name)
    return tokens


# ---------------------------------------------------------------- stats ------

def summarize(rows: Iterable[SiteRow]) -> dict[str, int]:
    counts = {"found": 0, "free": 0, "blocked": 0, "error": 0, "illegal": 0}
    for row in rows:
        counts[row.status] = counts.get(row.status, 0) + 1
    return counts


def slowest(rows: Iterable[SiteRow], limit: int = 5) -> list[SiteRow]:
    timed = [r for r in rows if r.seconds]
    timed.sort(key=lambda r: r.seconds or 0.0, reverse=True)
    return timed[:limit]


# ---------------------------------------------------------------- output -----

def output_dir() -> Path:
    path = data_dir() / "sherlock"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_name(username: str) -> str:
    keep = [c for c in username if c.isalnum() or c in "._-"]
    return "".join(keep)[:60] or "username"


def write_report(username: str, rows: list[SiteRow], *, manifest: str,
                 formats: Iterable[str] = ("txt", "csv", "json")) -> list[Path]:
    """Write the per-username report files and return their paths."""
    wanted = {f.lower().lstrip(".") for f in formats}
    folder = output_dir()
    stem = _safe_name(username)
    written: list[Path] = []
    ordered = sorted(rows, key=lambda r: r.site.casefold())

    if "txt" in wanted:
        lines = [f"# Null-Trace / Sherlock report — @{username}",
                 f"# manifest: {manifest}",
                 f"# generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", ""]
        for row in ordered:
            if row.status == "found" and row.url:
                lines.append(f"[+] {row.site}: {row.url}")
        if len(lines) == 4:
            lines.append("[-] No profile matched on any probed site.")
        path = folder / f"{stem}.txt"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(path)

    if "csv" in wanted:
        path = folder / f"{stem}.csv"
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(["username", "name", "url_main", "url_user",
                             "exists", "http_status", "response_time_s"])
            for row in ordered:
                writer.writerow([username, row.site, row.url_main, row.url,
                                 row.verdict, row.http_status,
                                 "" if row.seconds is None else round(row.seconds, 3)])
        written.append(path)

    if "json" in wanted:
        path = folder / f"{stem}.json"
        payload = {
            "username": username,
            "manifest": manifest,
            "engine": _version_or_none(),
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "results": [asdict(row) for row in ordered],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        written.append(path)

    if "xlsx" in wanted:
        try:
            from openpyxl import Workbook
        except ImportError:
            return written
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "sheet1"
        sheet.append(["username", "name", "url_main", "url_user", "exists",
                      "http_status", "response_time_s"])
        for row in ordered:
            sheet.append([username, row.site, f'=HYPERLINK("{row.url_main}")',
                          f'=HYPERLINK("{row.url}")', row.verdict,
                          row.http_status,
                          "" if row.seconds is None else round(row.seconds, 3)])
        path = folder / f"{stem}.xlsx"
        workbook.save(path)
        written.append(path)

    return written


def _version_or_none() -> str:
    try:
        return engine_version()
    except EngineError:
        return "unavailable"
