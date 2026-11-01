# Configuration

Everything is stored in one JSON file, created on first launch:

| OS | Path |
|---|---|
| Windows | `%APPDATA%\Null-Trace\config.json` |
| Linux / macOS | `~/.null-trace/config.json` |

Override the location with the `NULLTRACE_HOME` environment variable.

## File shape

```json
{
  "api_keys": {
    "hunter": "",
    "numverify": "",
    "ipqualityscore": "",
    "newsapi": "",
    "google_cse_key": "",
    "google_cse_cx": "",
    "hibp": "",
    "opencage": "",
    "github": "",
    "shodan": "",
    "virustotal": ""
  },
  "network": {
    "timeout": 12,
    "tor_proxy": "socks5h://127.0.0.1:9050",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
  },
  "ui": {
    "appearance": "dark",
    "keep_history": true
  }
}
```

## Keys

| Key | Used by | Free tier | Get one at |
|---|---|---|---|
| `hunter` | Email Finder, Email Intel | 25 searches/month | hunter.io |
| `numverify` | Phone Intel | 100/month | apilayer.com |
| `ipqualityscore` | Phone Intel | 200/month | ipqualityscore.com |
| `newsapi` | News | developer plan | newsapi.org |
| `google_cse_key` + `google_cse_cx` | Image Search, dorks | 100 queries/day | programmablesearchengine.google.com |
| `hibp` | Email Intel, Exposure Audit | paid | haveibeenpwned.com/API/Key |
| `opencage` | reverse geocoding | 2,500/day | opencagedata.com |
| `github` | GitHub Recon | free | github.com/settings/tokens |
| `shodan` | optional host data | paid | shodan.io |
| `virustotal` | Hash Lookup | 4 lookups/min | virustotal.com/gui/my-apikey |

Modules that need a key you have not set still run. They report what was
skipped and continue with free sources.

## Network settings

- **timeout** — seconds per HTTP request. Default `12`. Raise it for slow links;
  the DNS and RDAP modules use their own longer timeouts.
- **tor_proxy** — SOCKS endpoint used by the Dark Web module when
  "route through Tor" is ticked. `socks5h` keeps DNS resolution inside Tor.
- **user_agent** — sent on every request. Some providers fingerprint it; the
  default mimics a desktop Chrome build, and RDAP registries are contacted
  directly rather than through a redirector that filters browser agents.

## Editing by hand

The Settings screen writes this file atomically (temporary file, then rename),
so editing it in a text editor while the app is closed is safe. Invalid JSON
falls back to defaults rather than crashing — but it also loses the file's
contents on the next save, so keep a copy.

## Resetting

Delete the folder:

```
%APPDATA%\Null-Trace
```

That removes keys, history and caches. The next launch recreates it empty.
