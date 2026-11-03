"""Self-contained HTML report for the Username OSINT scan.

One file, inline CSS, no external assets: it is written to disk and opened in
the local browser, so it must render offline and never clip a long URL.
"""

from __future__ import annotations

import html
import time
from typing import Iterable, Sequence

from .osint_engine import SiteRow, summarize

CSS = """
:root {
  color-scheme: dark;
  --bg:#08080a; --panel:#0d0d0f; --elev:#17171b; --edge:#a8333a;
  --hair:#6b2226; --text:#ffffff; --muted:#d4d2ce; --faint:#a3a09a;
  --accent:#e23b3b; --link:#ff6b6b;
}
* { box-sizing: border-box; }
body { margin:0; padding:28px 20px 56px; background:var(--bg); color:var(--text);
  font:14px/1.55 Consolas,"Cascadia Mono",Menlo,monospace; }
.wrap { max-width:1180px; margin:0 auto; }
header { border:1px solid var(--edge); background:var(--panel); padding:20px 22px; }
.brand { font-size:11px; letter-spacing:.26em; color:var(--accent); }
h1 { margin:6px 0 0; font-size:22px; letter-spacing:.04em; word-break:break-word; }
.meta { margin-top:12px; display:grid; gap:2px 26px;
  grid-template-columns:repeat(auto-fit,minmax(0,1fr)); font-size:12.5px;
  color:var(--faint); overflow-wrap:anywhere; }
.meta span { min-width:0; overflow-wrap:anywhere; word-break:break-word; }
.meta b { color:var(--muted); font-weight:400; }
.chips { display:flex; flex-wrap:wrap; gap:8px; margin:16px 0 0; }
.chip { border:1px solid var(--hair); background:var(--elev); padding:6px 11px;
  font-size:12px; color:var(--muted); white-space:nowrap; }
.chip b { color:var(--text); font-weight:700; }
.chip.hit { border-color:var(--accent); color:var(--text); }
section { margin-top:22px; border:1px solid var(--edge); background:var(--panel);
  padding:18px 20px; }
h2 { margin:0 0 4px; font-size:13px; letter-spacing:.2em; color:var(--accent); }
.sub { margin:0 0 14px; font-size:12.5px; color:var(--faint); }
.filter { margin:0 0 12px; }
input { width:min(420px,100%); background:var(--elev); border:1px solid var(--hair);
  color:var(--text); font:inherit; font-size:13px; padding:8px 10px; }
input:focus { outline:none; border-color:var(--accent); }
table { width:100%; border-collapse:collapse; font-size:13px; table-layout:fixed; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--hair);
  vertical-align:top; overflow-wrap:anywhere; word-break:break-word; }
th { font-size:11px; letter-spacing:.12em; color:var(--faint); font-weight:400;
  border-bottom-color:var(--edge); }
tr:last-child td { border-bottom:none; }
td.site { width:23%; } td.num { width:11%; text-align:right; } td.why { width:44%; }
a { color:var(--link); text-decoration:none; }
a:hover { text-decoration:underline; }
.empty { color:var(--faint); font-size:13px; margin:6px 0 0; }
details { margin-top:8px; border:1px solid var(--hair); background:var(--elev);
  padding:10px 14px; }
summary { cursor:pointer; color:var(--muted); font-size:13px; }
.list { margin:12px 0 0; columns:3 260px; column-gap:26px; font-size:12.5px;
  color:var(--faint); }
.list div { break-inside:avoid; padding:2px 0; }
mark { background:var(--accent); color:#0b0b0d; }
footer { margin-top:22px; font-size:12px; color:var(--faint); padding:0 2px; }
@media (max-width:760px) {
  body { padding:16px 12px 40px; }
  header, section { padding:15px 14px; }
  th, td { padding:7px 6px; }
  .list { columns:2 150px; }
  table { font-size:12.5px; }
  td.site, td.num, td.why { width:auto; }
}
@media print {
  :root { color-scheme: light only; }
  body { background:#fff; color:#111; }
  header, section { border-color:#b3b3b3; background:#fff; }
  a { color:#111; }
  .filter, input { display:none; }
}
"""

JS = """
(function () {
  var box = document.getElementById('filter');
  if (!box) return;
  var rows = Array.prototype.slice.call(document.querySelectorAll('tbody tr'));
  box.addEventListener('input', function () {
    var needle = box.value.trim().toLowerCase();
    rows.forEach(function (row) {
      row.style.display = !needle || row.textContent.toLowerCase().indexOf(needle) >= 0
        ? '' : 'none';
    });
  });
})();
"""


def _cell(text: object) -> str:
    return html.escape("" if text is None else str(text), quote=True)


def _rows_table(rows: Sequence[SiteRow], kind: str) -> str:
    if kind == "found":
        head = ("Site", "Profile", "HTTP", "Seconds")
        body = []
        for row in rows:
            link = _cell(row.url)
            # Only a real web address becomes a clickable anchor; anything a
            # hand-edited manifest put in this column stays plain text.
            if row.url.startswith(("http://", "https://")):
                profile = f"<a href='{link}'>{link}</a>"
            else:
                profile = link
            body.append(
                "<tr><td class='site'>{site}</td><td>{profile}</td>"
                "<td class='num'>{code}</td><td class='num'>{secs}</td></tr>".format(
                    site=_cell(row.site), profile=profile,
                    code=_cell(row.http_status or "-"),
                    secs="—" if row.seconds is None else f"{row.seconds:.2f}"))
    elif kind == "noise":
        head = ("Site", "Verdict", "Why")
        body = []
        for row in rows:
            body.append(
                "<tr><td class='site'>{site}</td><td>{verdict}</td>"
                "<td class='why'>{why}</td></tr>".format(
                    site=_cell(row.site), verdict=_cell(row.verdict),
                    why=_cell(row.reason or "no reason returned")))
    else:  # clear
        head = ("Site", "Verdict", "HTTP")
        body = []
        for row in rows:
            body.append(
                "<tr><td class='site'>{site}</td><td>{verdict}</td>"
                "<td class='num'>{code}</td></tr>".format(
                    site=_cell(row.site), verdict=_cell(row.verdict),
                    code=_cell(row.http_status or "-")))

    columns = "".join(f"<th>{_cell(name)}</th>" for name in head)
    return (f"<table><thead><tr>{columns}</tr></thead><tbody>"
            + "".join(body) + "</tbody></table>")


def render(username: str, rows: Iterable[SiteRow], *, manifest: str = "",
           title: str = "Username OSINT") -> str:
    ordered = sorted(rows, key=lambda r: r.site.casefold())
    counts = summarize(ordered)
    found = [r for r in ordered if r.status == "found" and r.url]
    noise = [r for r in ordered if r.status in ("blocked", "error", "illegal")]
    clear = [r for r in ordered if r.status == "free"]

    chips = [
        ("sites probed", len(ordered), False),
        ("matched", counts.get("found", 0), True),
        ("clear", counts.get("free", 0), False),
        ("blocked", counts.get("blocked", 0), False),
        ("errors", counts.get("error", 0), False),
        ("rejected by site rules", counts.get("illegal", 0), False),
    ]
    chip_html = "".join(
        f"<span class='chip{' hit' if hot else ''}'>{_cell(label)} <b>{value}</b></span>"
        for label, value, hot in chips)

    if found:
        matched = ("<div class='filter'><input id='filter' type='search' "
                   "placeholder='Filter this table — site or address'></div>"
                   + _rows_table(found, "found"))
    else:
        matched = "<p class='empty'>No site reported a match for this handle.</p>"

    noise_block = _rows_table(noise, "noise") if noise else \
        "<p class='empty'>Every answer was conclusive.</p>"
    clear_block = ("<details><summary>" + str(len(clear)) +
                   " sites answered “no profile” — click to expand</summary><div class='list'>"
                   + "".join(f"<div>{_cell(r.site)}</div>" for r in clear)
                   + "</div></details>")
    if not clear:
        clear_block = "<p class='empty'>Nothing was reported clear.</p>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nosnippet">
<title>Username OSINT — @{_cell(username)}</title>
<style>{CSS}</style></head>
<body><div class="wrap">
<header>
  <div class="brand">NULL-TRACE</div>
  <h1>{_cell(title)} — @{_cell(username)}</h1>
  <div class="meta">
    <span><b>generated</b> {time.strftime('%Y-%m-%d %H:%M:%S')}</span>
    <span><b>manifest</b> {_cell(manifest or 'bundled site list')}</span>
    <span><b>method</b> public profile pages, one request per site</span>
  </div>
  <div class="chips">{chip_html}</div>
</header>

<section><h2>MATCHED PROFILES</h2>
<p class="sub">A match is a strong hint, not proof — handles are reused and some
sites answer 200 for everyone.</p>
{matched}</section>

<section><h2>INCONCLUSIVE</h2>
<p class="sub">WAF pages, rate limits, connection failures and usernames a site
refuses to accept. Reported instead of hidden.</p>
{noise_block}</section>

<section><h2>NO PROFILE</h2>
<p class="sub">Sites that answered their own "profile missing" signature.</p>
{clear_block}</section>

<footer>Built locally by Null-Trace — the page and its data never leave this
machine unless you send them. Site probe signatures come from the vendored
open-source probe engine (MIT); the full notice is in
<code>legal/THIRD_PARTY.md</code>.</footer>
</div><script>{JS}</script></body></html>
"""
