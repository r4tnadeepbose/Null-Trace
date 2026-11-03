# Architecture

Null-Trace is a single-process desktop application. There is no server, no
database service and no background daemon: the GUI, the recon modules and the
history store all live in one Python process, and every outbound request is
made directly from your machine.

```
                    ┌─────────────────────────────┐
   user input ─────▶│  nulltrace/gui/app.py       │
                    │  dashboard · forms · output │
                    └──────────────┬──────────────┘
                                   │  starts a job
                    ┌──────────────▼──────────────┐
                    │  nulltrace/job.py           │
                    │  JobRunner (worker thread)  │
                    │  Context (output + cancel)  │
                    └───────┬─────────────┬───────┘
                            │             │
             ┌──────────────▼───┐   ┌─────▼──────────────┐
             │ modules/*.py     │   │ net.py             │
             │ one per tool     │──▶│ HTTP · DNS · TLS   │
             └──────────────┬───┘   └─────┬──────────────┘
                            │             │
                    ┌───────▼─────┐  ┌────▼─────────────┐
                    │ datasets.py │  │ upstream APIs    │
                    │ data/*      │  │ (public, no proxy)│
                    └─────────────┘  └──────────────────┘
                            │
                    ┌───────▼─────┐
                    │ history.py  │
                    │ sqlite      │
                    └─────────────┘
```

## Layers

| Layer | Files | Responsibility |
|---|---|---|
| Interface | `nulltrace/gui/app.py` | Dashboard, quick recon, module forms, streaming output, settings, history, theme switch |
| Theme | `nulltrace/theme.py` | Palette, fonts and radii in one place |
| Job control | `nulltrace/job.py` | Module contract (`Module`, `Field`), `Context` output API, threaded `JobRunner`, cancellation |
| Modules | `nulltrace/modules/*.py` | One file per tool; no GUI imports, no global state |
| Orchestration | `nulltrace/modules/auto_recon.py` | Quick Recon: detects the target type and runs the matching modules through a forwarding context |
| Transport | `nulltrace/net.py` | Session reuse, retries, TLS inspection, DNS helpers, input validators |
| Reference data | `nulltrace/datasets.py`, `data/` | Wordlists and catalogues, editable without touching code |
| Storage | `nulltrace/config.py`, `history.py` | JSON config and keys, sqlite scan history |
| Entry point | `scan.py` | Dependency check, `--list`, `--run`, launches the GUI |

## The module contract

Every tool is a `Module` dataclass with declarative fields:

```python
MODULE = Module(
    id="dns_lookup",
    title="DNS Lookup",
    category="Network",
    summary="Query any record type ...",
    fields=(
        Field("domain", "Domain", placeholder="example.com", required=True),
        Field("rtype", "Record type", kind="choice", choices=RECORD_TYPES, default="ALL"),
        Field("common", "Also probe common subdomains", kind="checkbox", default="0"),
    ),
    run=run,
    keys=(),
    order=20,
)
```

`run(ctx)` produces output through `ctx`, never through `print()`:

| Call | Result in the UI |
|---|---|
| `ctx.title(text)` | bold heading |
| `ctx.section(text)` | accent sub-heading |
| `ctx.kv(label, value)` | aligned key/value pair |
| `ctx.table(headers, rows)` | monospace column-aligned table |
| `ctx.ok / warn / error` | colour-coded line |
| `ctx.link(label, url)` | clickable underlined link |
| `ctx.status(text)` | replaces the live status next to OUTPUT |
| `ctx.check_cancel()` | raises on Stop |

Because forms are generated from `fields`, a module needs no GUI code. The GUI
implements `text`, `multiline`, `choice`, `checkbox` and `file` inputs.

## Threading model

- The Tk main loop owns all widgets. Nothing else may touch them.
- `JobRunner.start()` spawns a daemon thread; the module emits `Event` objects
  into a `queue.Queue`.
- The GUI drains that queue every 80 ms and draws the lines in batches, so a
  scan that emits thousands of rows cannot flood the widget queue.
- `Stop` sets a `threading.Event`; modules call `ctx.check_cancel()` between
  network steps and `ctx.sleep()` for interruptible waits.
- History is written once, on the worker's completion event.

**Two rules keep the UI alive:**

1. *Automatic garbage collection is disabled on the worker thread.* A Tk object
   finaliser running off the UI thread issues a Tcl call and deadlocks against
   the main loop — this was the cause of scans freezing. The UI thread runs
   `gc.collect()` once a second while a job is active and re-enables GC when it
   finishes.
2. *Tk widgets are never touched from a module.* Modules only call `ctx.*`,
   which appends to a queue.

### Concurrency

`nulltrace/parallel.py` provides `map_parallel`: bounded batches (2048 tasks)
through a thread pool sized to the workload, with early stop and progress
callbacks. Port scanning, DNS resolution and username probing use it.

Each thread gets its own pooled `requests.Session` (`net.session_for_thread`) —
a shared session is not thread-safe.

There is no C or C++ extension. The work is network-bound: time is spent
waiting on sockets and DNS, not executing Python, so a C implementation would
add a build dependency for no measurable gain. The speed-ups come from more
work in flight (512 connect workers instead of 100) and from removing the
deadlock above.

## Quick Recon

`auto_recon.detect()` classifies the input (IP, domain, email, phone, VIN, hash,
username) by shape, then `PLANS` maps each kind to the modules that make sense.
A `SubContext` forwards every `ctx` call to the parent while counting rows,
warnings and errors, so a failing step degrades into a line of output instead of
aborting the sweep. The run ends with a findings table.

## Vendored username-probing engine

`username_probe/` at the repository root is the 0.16.2 username-probing engine,
carried as a separate top-level package rather than rewritten into a Null-Trace
module: the manifest and its per-site probe signatures are the value, and keeping
the probing logic as one auditable blob means a new release can be dropped in
without re-reading 900 lines. The cost is that upstream ships under its own name,
so the package, its entry module and its entry function are renamed here —
`username_probe/probe.py::probe_usernames()` — and a future drop-in needs the same
rename replayed. Five local patches are marked in the files: a pinned version
string that needs no installed package metadata, an openpyxl `.xlsx` writer
instead of pandas, the upstream promotion footer removed from the notify path, the
release check removed from the CLI entry, and the rename itself. The upstream
project and its licence are named in `legal/THIRD_PARTY.md`, in the bundled
`username_probe/LICENSE`, and nowhere a user can see them; inside the app the
feature is only ever "Username OSINT".

The same rule covers addresses. A plan reports where its sites came back as a
label — "bundled manifest (data.json)", "live upstream manifest", "your own site
list" — never as a fetch URL or a filesystem path, and manifest failures are
scrubbed of the engine's own hostnames before they reach the output pane, so
nothing the engine downloads leaves a trace in the pane, the history row or an
exported report. A test derives the endpoint label from the live-manifest constant
and asserts it appears in no export and in no app source file.

Null-Trace never calls the engine directly from a module. `nulltrace/osint_engine.py`
is the only bridge: it builds the site plan, converts an upstream `QueryResult`
into a `SiteRow`, and supplies a `QueryNotify` replacement whose `update()` raises
`Cancelled` when the Stop button is pressed — the engine's result loop does not
catch exceptions, which makes that the supported abort point. The GUI module
(`username_osint`) and `scan.py --probe-cli` both sit behind the bridge, so the
exports, statistics and cancel behaviour are identical either way.

`nulltrace/report_html.py` renders the run into a standalone page — no scripts, no
CDN, everything escaped. The module decides where the results are shown: with the
"open the HTML report" checkbox ticked (the default) the pane prints only the
summary and the page is written and opened; unticked, the full tables stream into
the pane. The page goes to `%APPDATA%\Null-Trace\username-osint\<handle>.html`.

The engine's own threads (upstream caps at 20 workers) finish inside the per-request
timeout, which bounds how long an aborted scan can still linger after the module
returns.

## Failure behaviour

Modules are expected to degrade, not crash. A missing key prints what was
skipped and continues on free sources; an unreachable provider is reported as a
warning; an unexpected exception is caught by the runner, shown in the output
pane with a short traceback, and marked as a failed run in history.

## Storage

| Path | Content |
|---|---|
| `%APPDATA%\Null-Trace\config.json` | API keys, timeouts, user agent |
| `%APPDATA%\Null-Trace\history.db` | sqlite: module, target, times, status, rendered lines |
| `%APPDATA%\Null-Trace\kev.json` | CISA KEV cache (24 h) |
| `%APPDATA%\Null-Trace\rdap_dns.json` | IANA RDAP bootstrap cache (7 days) |
| `%APPDATA%\Null-Trace\crash.log` | uncaught exceptions and hard faults, rotated at 1 MB |
| `%APPDATA%\Null-Trace\username-osint\` | HTML, txt, csv, json and xlsx reports from Username OSINT |

The folder was renamed from `NullTrace`; on first launch the old directory is
moved automatically, or reused if a running instance still holds the sqlite file.
