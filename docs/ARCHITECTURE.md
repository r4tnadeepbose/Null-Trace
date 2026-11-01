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
| Theme | `nulltrace/theme.py` | Two palettes (terminal black / white), fonts, radii; `apply()` swaps them |
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

## Theming

`theme.apply(mode)` copies one palette into module globals and rebuilds
`TAG_COLORS`. The app applies the stored preference before creating any widget;
the top-bar switch flips the palette, persists it in `config.json` and rebuilds
the shell, replaying the current output so a theme change never costs a result.

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

The folder was renamed from `NullTrace`; on first launch the old directory is
moved automatically, or reused if a running instance still holds the sqlite file.
