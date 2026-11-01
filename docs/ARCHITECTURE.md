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
| Interface | `nulltrace/gui/app.py`, `theme.py` | Dashboard, module forms, streaming output, settings, history |
| Job control | `nulltrace/job.py` | Module contract (`Module`, `Field`), `Context` output API, threaded `JobRunner`, cancellation |
| Modules | `nulltrace/modules/*.py` | One file per tool; no GUI imports, no global state |
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
- The GUI polls that queue every 80 ms in `_poll_queue` and renders events.
- `Stop` sets a `threading.Event`; modules call `ctx.check_cancel()` between
  network steps and `ctx.sleep()` for interruptible waits.
- History is written once, on the worker's completion event.

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

The folder was renamed from `NullTrace`; on first launch the old directory is
moved automatically, or reused if a running instance still holds the sqlite file.
