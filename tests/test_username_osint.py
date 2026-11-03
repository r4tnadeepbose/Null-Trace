"""Username OSINT engine: manifest, classification, exports and cancel path.

Nothing here touches the network — the bundled manifest is used everywhere and
upstream exclusion fetching is switched off.
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nulltrace.net import Cancelled
from nulltrace.osint_engine import (BUNDLED_MANIFEST, LIVE_MANIFEST, SiteRow,
                                        build_plan,
                                        classify, manifest_version, expand_variants,
                                        missing_dependency, output_dir,
                                        parse_usernames, probe, site_names,
                                        slowest, summarize, write_report)

from username_probe.result import QueryResult, QueryStatus


def _result(site: str, status: QueryStatus, context: str | None = None,
            url: str = "") -> QueryResult:
    return QueryResult("tester", site, url or f"https://{site}/tester", status,
                       query_time=0.5, context=context)


class ManifestTests(unittest.TestCase):
    def test_bundled_manifest_present(self) -> None:
        self.assertTrue(BUNDLED_MANIFEST.is_file(), BUNDLED_MANIFEST)
        data = json.loads(BUNDLED_MANIFEST.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(data), 400)

    def test_engine_reports_version_without_pip(self) -> None:
        self.assertEqual(manifest_version(), "0.16.2")

    def test_dependencies_installed(self) -> None:
        self.assertIsNone(missing_dependency())

    def test_plan_offline_without_exclusions(self) -> None:
        plan = build_plan(honor_exclusions=False, include_nsfw=True)
        self.assertGreaterEqual(len(plan.site_data), 400)
        self.assertEqual(plan.source, str(BUNDLED_MANIFEST))
        self.assertEqual(plan.manifest, "bundled manifest (data.json)")
        self.assertGreater(plan.nsfw_total, 0)

    def test_nsfw_scope_is_a_real_filter(self) -> None:
        everything = build_plan(honor_exclusions=False, include_nsfw=True)
        safe = build_plan(honor_exclusions=False, include_nsfw=False)
        self.assertLess(len(safe.site_data), len(everything.site_data))
        self.assertEqual(everything.nsfw_total,
                         len(everything.site_data) - len(safe.site_data))

    def test_only_and_skip_filters(self) -> None:
        plan = build_plan(honor_exclusions=False, only=["github", "gitlab", "bogus"])
        self.assertEqual(site_names(plan.site_data), ["GitHub", "GitLab"])
        self.assertEqual(plan.unknown_sites, ("bogus",))
        trimmed = build_plan(honor_exclusions=False, skip=["GitHub"])
        self.assertNotIn("GitHub", trimmed.site_data)
        self.assertIn("GitLab", trimmed.site_data)

    def test_custom_manifest_overrides_the_choice(self) -> None:
        import tempfile

        payload = json.loads(BUNDLED_MANIFEST.read_text(encoding="utf-8"))
        subset = {"OnlyTest": payload["GitHub"]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mini.json"
            path.write_text(json.dumps(subset), encoding="utf-8")
            plan = build_plan(manifest_path=str(path), honor_exclusions=False)
        self.assertEqual(site_names(plan.site_data), ["OnlyTest"])
        self.assertEqual(plan.source, str(path))
        self.assertIn("your own site list", plan.manifest)

    def test_unreadable_custom_manifest_is_reported(self) -> None:
        with self.assertRaises(FileNotFoundError):
            build_plan(manifest_path=str(Path("Z:/nope/missing.json")),
                       honor_exclusions=False)

    def test_live_manifest_falls_back_when_unreachable(self) -> None:
        dead = "http://127.0.0.1:9/manifest.json"
        with mock.patch("nulltrace.osint_engine.LIVE_MANIFEST", dead):
            plan = build_plan(live=True, honor_exclusions=False, only=["GitHub"])
        self.assertTrue(plan.manifest_error, plan.manifest_error)
        self.assertEqual(plan.source, str(BUNDLED_MANIFEST))
        self.assertTrue(plan.manifest.startswith("bundled manifest"), plan.manifest)
        self.assertEqual(site_names(plan.site_data), ["GitHub"])

    def test_error_text_never_shows_the_engines_own_hosts(self) -> None:
        from urllib.parse import urlparse

        from nulltrace.osint_engine import scrub_endpoints
        host = urlparse(LIVE_MANIFEST).netloc
        quoted = (f"HTTPSConnectionPool(host='{host}', port=443): "
                  f"Max retries exceeded with url: /data.json")
        cleaned = scrub_endpoints(quoted)
        self.assertNotIn(host, cleaned)
        self.assertIn("the manifest host", cleaned)


class ClassificationTests(unittest.TestCase):
    def test_claimed_is_found(self) -> None:
        row = classify(_result("example.com", QueryStatus.CLAIMED))
        self.assertEqual((row.status, row.verdict), ("found", "Claimed"))
        self.assertEqual(row.seconds, 0.5)

    def test_available_is_free(self) -> None:
        self.assertEqual(classify(_result("a", QueryStatus.AVAILABLE)).status, "free")

    def test_waf_and_illegal(self) -> None:
        self.assertEqual(classify(_result("b", QueryStatus.WAF)).status, "blocked")
        self.assertEqual(classify(_result("c", QueryStatus.ILLEGAL)).status, "illegal")

    def test_unknown_with_429_is_blocked(self) -> None:
        row = classify(_result("d", QueryStatus.UNKNOWN,
                               "429 Too Many Requests for url: https://d/x"))
        self.assertEqual(row.status, "blocked")
        self.assertIn("429", row.reason)

    def test_unknown_without_hint_is_error(self) -> None:
        row = classify(_result("e", QueryStatus.UNKNOWN, "Error Connecting"))
        self.assertEqual(row.status, "error")
        self.assertEqual(row.reason, "Error Connecting")

    def test_summarize_and_slowest(self) -> None:
        rows = [SiteRow("a", "found", seconds=1.0), SiteRow("b", "free", seconds=3.0),
                SiteRow("c", "error", seconds=None), SiteRow("d", "blocked")]
        self.assertEqual(summarize(rows),
                         {"found": 1, "free": 1, "blocked": 1, "error": 1, "illegal": 0})
        self.assertEqual([r.site for r in slowest(rows, 5)], ["b", "a"])


class UsernameTests(unittest.TestCase):
    def test_parse_splits_and_dedupes(self) -> None:
        self.assertEqual(parse_usernames("@a, b\nb  c"), ["a", "b", "c"])

    def test_upstream_question_mark_expansion(self) -> None:
        self.assertEqual(expand_variants("user{?}name"),
                         ["user_name", "user-name", "user.name"])
        self.assertEqual(expand_variants("plain"), ["plain"])

    def test_separator_variants(self) -> None:
        from nulltrace.modules.username_osint import _variants
        self.assertEqual(_variants("noplaces"), [])
        self.assertEqual(set(_variants("a.b")), {"a-b", "a_b"})
        many = _variants("a.b.c.d")
        self.assertTrue(many)
        self.assertNotIn("a.b.c.d", many)
        self.assertLessEqual(len(many), 8)


class CancelTests(unittest.TestCase):
    def test_collector_raises_when_cancel_is_set(self) -> None:
        from nulltrace.osint_engine import _make_collector
        cancel = threading.Event()
        cancel.set()
        collector = _make_collector(None, cancel)
        with self.assertRaises(Cancelled):
            collector.update(_result("x", QueryStatus.CLAIMED))

    def test_collector_collects_and_reports(self) -> None:
        from nulltrace.osint_engine import _make_collector
        seen: list[SiteRow] = []
        collector = _make_collector(seen.append, threading.Event())
        collector.start("tester")
        collector.update(_result("x", QueryStatus.CLAIMED))
        collector.update(_result("y", QueryStatus.AVAILABLE))
        collector.finish()
        self.assertEqual([r.status for r in seen], ["found", "free"])
        self.assertEqual(set(collector.rows), {"x", "y"})


class RateLimitTests(unittest.TestCase):
    """A refused request is not an answer about the profile."""

    def _run(self, status: QueryStatus, http_status):
        def fake(username, site_data, query_notify, **kwargs):
            site_data["Slow"]["request_future"] = "the engine leaves its futures here"
            query_notify.update(QueryResult(username, "Slow", "https://slow/tester",
                                           status, query_time=0.1))
            return {"Slow": {"url_main": "https://slow",
                             "url_user": "https://slow/tester",
                             "http_status": http_status}}

        plan = {"Slow": {"url": "https://slow/{}"}}
        with mock.patch("username_probe.probe.probe_usernames", fake):
            rows, aborted, _elapsed = probe("tester", plan)
        self.assertFalse(aborted)
        self.assertEqual(len(rows), 1)
        return rows[0], plan

    def test_rate_limited_site_is_not_counted_clear(self) -> None:
        row, _ = self._run(QueryStatus.AVAILABLE, 429)
        self.assertEqual((row.status, row.verdict), ("blocked", "Rate limited"))
        self.assertIn("429", row.reason)
        self.assertEqual(summarize([row])["blocked"], 1)

    def test_rate_limit_cannot_produce_a_false_match(self) -> None:
        row, _ = self._run(QueryStatus.CLAIMED, 429)
        self.assertEqual(row.status, "blocked")

    def test_answered_site_keeps_its_own_verdict(self) -> None:
        row, _ = self._run(QueryStatus.AVAILABLE, 404)
        self.assertEqual((row.status, row.verdict), ("free", "Available"))

    def test_plan_never_holds_the_previous_runs_futures(self) -> None:
        _, plan = self._run(QueryStatus.AVAILABLE, 200)
        self.assertNotIn("request_future", plan["Slow"])


class ExportTests(unittest.TestCase):
    rows = [
        SiteRow("GitHub", "found", "Claimed", "https://github.com/tester",
                "https://github.com", "200", "", 0.42),
        SiteRow("GitLab", "free", "Available", "https://gitlab.com/tester",
                "https://gitlab.com", "404", "", 0.31),
    ]

    def setUp(self) -> None:
        self.username = "zz_nulltrace_test"
        self.paths = write_report(self.username, self.rows, manifest="test",
                                  formats=["txt", "csv", "json", "xlsx"])

    def tearDown(self) -> None:
        for path in self.paths:
            path.unlink(missing_ok=True)

    def test_all_formats_written(self) -> None:
        self.assertEqual(sorted(p.suffix for p in self.paths),
                         [".csv", ".json", ".txt", ".xlsx"])

    def test_txt_only_lists_matches(self) -> None:
        text = next(p for p in self.paths if p.suffix == ".txt").read_text(encoding="utf-8")
        self.assertIn("[+] GitHub: https://github.com/tester", text)
        self.assertNotIn("GitLab", text)

    def test_csv_header_and_rows(self) -> None:
        path = next(p for p in self.paths if p.suffix == ".csv")
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        self.assertEqual(lines[0], "username,name,url_main,url_user,exists,"
                                   "http_status,response_time_s")
        self.assertEqual(len(lines), 3)
        self.assertIn("Claimed", lines[1])

    def test_json_round_trip(self) -> None:
        path = next(p for p in self.paths if p.suffix == ".json")
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["username"], self.username)
        self.assertEqual(payload["manifest_version"], "0.16.2")
        self.assertEqual(len(payload["results"]), 2)
        self.assertEqual(payload["results"][0]["url"], "https://github.com/tester")

    def test_no_export_carries_the_upstream_identity(self) -> None:
        """Neither the endpoint label nor the manifest address reaches a file."""
        from urllib.parse import urlparse

        from nulltrace.report_html import render
        token = urlparse(LIVE_MANIFEST).netloc.split(".")[1]
        blobs = [report.read_bytes().decode("utf-8", "replace") for report in self.paths]
        blobs.append(render(self.username, self.rows,
                            manifest="bundled manifest (data.json)"))
        for blob in blobs:
            self.assertNotIn(token, blob.casefold())

    def test_xlsx_opens(self) -> None:
        openpyxl = __import__("openpyxl")
        path = next(p for p in self.paths if p.suffix == ".xlsx")
        sheet = openpyxl.load_workbook(path).active
        rows = list(sheet.values)
        self.assertEqual(rows[0][0], "username")
        self.assertEqual(len(rows), 3)

    def test_unsafe_username_cannot_escape_the_report_folder(self) -> None:
        paths = write_report("../../evil/x", self.rows, manifest="t", formats=["txt"])
        try:
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0].parent, output_dir())
            self.assertNotIn("/", paths[0].name)
            self.assertNotIn("\\", paths[0].name)
        finally:
            for path in paths:
                path.unlink(missing_ok=True)

    def test_windows_reserved_names_stay_writable(self) -> None:
        from nulltrace.osint_engine import _safe_name
        for handle, expect in (("CON", "CON_"), ("nul.x", "nul.x_"),
                               ("com1", "com1_"), ("...", "username"),
                               ("a b/c", "abc"), ("rate_bose", "rate_bose")):
            self.assertEqual(_safe_name(handle), expect, handle)
        self.assertEqual(len(_safe_name("x" * 200)), 60)
        paths = write_report("CON", self.rows, manifest="t", formats=["txt"])
        try:
            self.assertEqual(paths[0].name, "CON_.txt")
        finally:
            for path in paths:
                path.unlink(missing_ok=True)


class HtmlReportTests(unittest.TestCase):
    rows = [
        SiteRow("GitHub", "found", "Claimed", "https://github.com/tester?a=1&b=2",
                "https://github.com", "200", "", 0.42),
        SiteRow("Some Blog", "free", "Available", "https://blog/tester",
                "https://blog", "404", "", 0.2),
        SiteRow("Guarded", "blocked", "WAF", "https://guarded/tester", "https://guarded",
                "403", "Web application firewall", 0.9),
    ]

    def _html(self, rows=None, username="tester") -> str:
        paths = write_report(username, rows or self.rows, manifest="bundled",
                             formats=["html"])
        try:
            return paths[0].read_text(encoding="utf-8")
        finally:
            for path in paths:
                path.unlink(missing_ok=True)

    def test_page_is_written_and_self_contained(self) -> None:
        page = self._html()
        self.assertTrue(page.startswith("<!DOCTYPE html"))
        self.assertIn("Username OSINT — @tester", page)
        self.assertIn("<style>", page)
        self.assertNotIn("<link ", page)
        self.assertNotIn("<script src", page)
        self.assertIn("MATCHED PROFILES", page)
        self.assertIn("INCONCLUSIVE", page)
        self.assertIn("NO PROFILE", page)

    def test_links_and_counts_render(self) -> None:
        page = self._html()
        self.assertIn("href='https://github.com/tester?a=1&amp;b=2'", page)
        self.assertIn("sites probed <b>3</b>", page)
        self.assertIn("matched <b>1</b>", page)
        self.assertIn("Web application firewall", page)
        self.assertIn("<details>", page)          # the long "no profile" list folds
        self.assertIn("legal/THIRD_PARTY.md", page)

    def test_hostile_input_is_escaped(self) -> None:
        hostile = [SiteRow("<img src=x onerror=alert(1)>", "found", "Claimed",
                           "https://x/<script>alert(2)</script>", "", "200", "", 1.0)]
        page = self._html(hostile, username="a<b>c")
        self.assertNotIn("<img src=x", page)
        self.assertNotIn("<script>alert(2)</script>", page)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", page)

    def test_non_web_address_is_not_turned_into_a_link(self) -> None:
        sneaky = [SiteRow("Odd", "found", "Claimed", "javascript:alert(1)",
                          "", "200", "", 1.0)]
        page = self._html(sneaky)
        self.assertNotIn("<a href='javascript", page)
        self.assertIn("javascript:alert(1)", page)

    def test_no_match_still_writes_a_page(self) -> None:
        page = self._html([SiteRow("Only", "free", "Available", "", "", "404", "", 0.1)])
        self.assertIn("No site reported a match", page)


class VendoringTests(unittest.TestCase):
    def test_pandas_is_not_imported_at_module_level(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "username_probe" / "probe.py").read_text(encoding="utf-8")
        head = "\n".join(source.splitlines()[:45])
        self.assertNotIn("import pandas", head)
        self.assertIn("openpyxl", source)

    def test_license_and_notice_ship_with_the_engine(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertTrue((root / "username_probe" / "LICENSE").is_file())
        self.assertTrue((root / "username_probe" / "resources" / "data.schema.json").is_file())

    def test_module_registered(self) -> None:
        from nulltrace.modules import find
        module = find("username_osint")
        self.assertIsNotNone(module)
        self.assertEqual(module.title, "Username OSINT")
        self.assertEqual(module.category, "Identity")
        names = [field.name for field in module.fields]
        for required in ("usernames", "scope", "manifest", "save", "exclusions",
                       "html"):
            self.assertIn(required, names)

    def test_probe_signature_survives_upstream(self) -> None:
        import inspect
        from username_probe.probe import probe_usernames
        parameters = inspect.signature(probe_usernames).parameters
        for name in ("username", "site_data", "query_notify", "proxy", "timeout"):
            self.assertIn(name, parameters)
        self.assertTrue(callable(probe))

    def test_request_pool_is_released_after_every_run(self) -> None:
        """Upstream abandons 20 worker threads per username; the local patch stays on."""
        root = Path(__file__).resolve().parents[1]
        source = (root / "username_probe" / "probe.py").read_text(encoding="utf-8")
        self.assertIn("_release_probe_sessions(session, underlying_session)", source)
        self.assertLess(source.index("    finally:"), source.index("return results_total"))

    def test_engine_brand_stays_out_of_readable_text(self) -> None:
        """The feature is Username OSINT; the upstream name survives only as a
        fetch address. The word is derived from the live-manifest hostname so
        this test does not contain it either."""
        import re
        from urllib.parse import urlparse

        host = urlparse(LIVE_MANIFEST).netloc.split(".", 1)[1]   # <name>project.xyz
        match = re.match(r"[a-z]+(?=project)", host)
        self.assertIsNotNone(match, LIVE_MANIFEST)
        brand = match.group()

        root = Path(__file__).resolve().parents[1]
        surfaces = sorted((root / "nulltrace" / "modules").glob("*.py"))
        surfaces += sorted((root / "nulltrace" / "gui").glob("*.py"))
        surfaces += [root / "nulltrace" / "osint_engine.py", root / "scan.py",
                     root / "README.md", root / "run.bat"]
        surfaces += sorted((root / "docs").glob("*.md"))
        surfaces += sorted((root / "username_probe").glob("*.py"))
        offenders = []
        for path in surfaces:
            for line in path.read_text(encoding="utf-8").splitlines():
                if brand in line.casefold() and "http" not in line:
                    offenders.append(f"{path.name}: {line.strip()[:70]}")
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
