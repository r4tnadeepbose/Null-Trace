# Development

## Setup

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt   # Windows
source .venv/bin/activate && pip install -r requirements.txt   # macOS/Linux
```

Run the app: `python scan.py`. Run it without a display:

```bash
python scan.py --list
python scan.py --run dns_lookup -a domain=example.com -a rtype=MX
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite is offline by design: it covers validators, the module registry,
output formatting, config persistence, dataset loaders and the email-header
analyser against a fixture. Network behaviour is verified manually with
`--run` against `example.com` and your own hosts.

`scripts/dev_check.py` runs compile + tests + a registry summary in one go.

## Adding a module

1. Create `nulltrace/modules/your_tool.py` with a `run(ctx)` function and a
   `MODULE` value.
2. Import it in `nulltrace/modules/__init__.py` and add it to `all_modules()`.
3. Give it an `order` inside its category; categories are ordered by
   `CATEGORY_ORDER`.
4. Use `ctx` for all output and `ctx.check_cancel()` between network steps.
5. Put reference lists in `data/` and load them through
   `nulltrace/datasets.py` with an in-code fallback.
6. Add a row to `docs/MODULES.md` (it is generated; regenerate from the
   registry, see below).
7. Add tests if the module has parsing logic that can run offline.

### Regenerating the module reference

```bash
python - <<'PY'
import sys; sys.path.insert(0, ".")
from nulltrace.modules import all_modules
print(len(all_modules()), "modules")
PY
```

`docs/MODULES.md` is generated from the registry; keep the header identical and
commit the regenerated file with the code change.

## Style

- No comments that restate the code. Explain *why* only when it is surprising.
- Modules never import the GUI.
- Network calls go through `nulltrace/net.py` so timeouts, retries and the user
  agent stay consistent.
- Do not add a dependency unless the standard library cannot do the job.

## Release

```powershell
packaging\build_windows.ps1 -Version 1.0.0
```

The script freezes the app with PyInstaller into `dist\Null-Trace\`, builds a
zip, and leaves a portable folder that runs without Python installed.

## Scope

Keep every module inside the rules in `legal/DISCLAIMER.md`: public or
authorised data, no authentication bypass, no automated harvesting of private
individuals' relatives or contact details.
