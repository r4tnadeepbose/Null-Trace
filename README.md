# Null-Trace

[![CI](https://github.com/r4tnadeepbose/Null-Trace/actions/workflows/ci.yml/badge.svg)](https://github.com/r4tnadeepbose/Null-Trace/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-7fa0c4.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-7fa0c4.svg)](https://www.python.org/downloads/)

Open-source intelligence workbench — a desktop application, written in Python, that
consolidates the recon tools from the classic X-osint terminal framework into one
dark, local-first GUI.

**Built by Ratnadeep Bose** · [github.com/r4tnadeepbose](https://github.com/r4tnadeepbose)

Everything runs on your machine. Scans go straight from your network to the upstream
source; nothing is proxied through a Null-Trace server, because there isn't one.

```
 python scan.py
```

---

## Requirements

| | |
|---|---|
| Python | 3.10+ (developed on 3.15, Windows 11) |
| GUI | tkinter, bundled with the python.org Windows/macOS installer |
| Network | outbound HTTPS; port 25 for SMTP probing; 9050 for Tor (optional) |
| Go | **not required** |

## Install

### Windows (PowerShell)

```powershell
cd C:\Users\boser\Downloads\NullTrace
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
```

Or just double-click / run `run.bat` — it creates the venv, installs dependencies
the first time, then launches.

### Linux / macOS

```bash
cd NullTrace
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scan.py
```

Debian/Ubuntu need tkinter, which is a system package, not a pip one:

```bash
sudo apt install python3-tk
```

## Run

```bash
.\.venv\Scripts\python scan.py        # Windows
python scan.py                        # venv activated
```

No arguments opens the desktop app.

### Without the GUI

Useful for scripting, cron jobs or a quick check:

```bash
python scan.py --list
python scan.py --run ip_info   -a target=1.1.1.1
python scan.py --run dns_lookup -a domain=example.com -a rtype=MX
python scan.py --run port_scan  -a host=example.com -a ports=22,80,443 -a timeout=1.5
python scan.py --run cve_research -a query=CVE-2021-44228
```

`-a key=value` maps to the same fields the GUI shows. Checkboxes accept
`1/0`, `true/false`, `yes/no`.

---

## Modules

| Category | Module | What it does | Key needed |
|---|---|---|---|
| Recon | **Quick Recon** | One input — domain, IP, email, phone, VIN, hash or username — swept across the matching modules with a findings summary | — |
| Network | IP Intel | Geolocation, ASN, PTR, open ports, CVEs | — |
| Network | DNS Lookup | A/AAAA/MX/TXT/NS/CNAME/SOA/CAA/SRV, subdomain probe | — |
| Network | DNS Reverse | PTR records for an IP | — |
| Network | Port Scan | Threaded TCP scan, banners, Shodan InternetDB cross-check | — |
| Network | MAC Vendor | OUI lookup, randomised/multicast address detection | — |
| Network | Network Map | Traceroute with city/ASN per hop | — |
| Web | WHOIS / RDAP | Registrar, dates, statuses, nameservers, contacts (no key) | — |
| Web | URL Inspector | Redirect chains, short-link expansion, phishing signals | — |
| Web | Host Search | Headers, TLS cert, tech fingerprints, exposed paths | — |
| Web | Subdomains | crt.sh, HackerTarget, optional brute force | — |
| Web | Google Dorks | Curated dork catalogue with engine links | — |
| Web | Dark Web Search | Ahmia onion index, clearnet or via Tor | — |
| Web | News | NewsAPI or Google News RSS | optional |
| Identity | Email Intel | MX, SPF/DMARC, Gravatar, ProtonMail keys, breaches | HIBP |
| Identity | Email Finder | Hunter.io search + pattern candidates + SMTP probes | Hunter |
| Identity | Exposure Audit | Self-audit: breaches, stealers, mail posture, risk score | HIBP |
| Identity | Email Headers | Hop chain, SPF/DKIM/DMARC parsing, spoofing verdict | — |
| Identity | Username Scan | Handle presence across 17 public platforms | — |
| Identity | Phone Intel | Validity, carrier, region, timezone, fraud score | Numverify/IPQS |
| Identity | Infostealer Exposure | Hudson Rock Cavalier malware-log lookups | — |
| Identity | GitHub Recon | Profile, repos, activity, commit emails | optional |
| Identity | SMTP Analysis | Live banner, ESMTP features, STARTTLS, one RCPT probe | — |
| Vulnerability | CVE / Exploits | NVD search + CISA KEV flagging | — |
| Media | Metadata | EXIF/XMP/document tags, GPS extraction | — |
| Media | Hash Lookup | MD5/SHA1/SHA256, file-type heuristics, VirusTotal | VirusTotal |
| Media | Image Search | Hashes, Google Lens/Yandex/TinEye links, Google CSE | CSE |
| Media | VIN Decoder | NHTSA vPIC decode + check-digit validation | — |
| System | Wi-Fi | Nearby networks, saved profiles, password + QR | — |
| System | Speed Test | Latency, download, upload | — |
| System | Toolkit | Environment check, install ExifTool, update check | — |
| System | About | Version, changelog, principles | — |

The app opens on a **dashboard**: run counters, quick-start tiles, recent scans, a
searchable list of every module, environment status and key coverage. The sidebar
filter (`Ctrl+F`) narrows the module list as you type.

**Quick Recon** is the fast path: press the red button in the sidebar, paste a
domain, IP, email, phone, VIN, hash or username, and the matching modules run in
sequence with a findings summary at the end.

**Window chrome**: the top bar carries the workspace views (Dashboard, History,
Settings), a `?` button that opens a walkthrough of every part of the app, a
sun/crescent theme switch and a fullscreen toggle (`F11`, `Escape` to leave). The theme is remembered between launches; light mode is
white with black borders.

Press **Run scan** (or `Ctrl+Enter`). Results stream into the output pane; click any
underlined link to open it in your browser. `Ctrl+S` exports the current output to a
text file, **Copy** puts it on the clipboard.

Every completed run is appended to local history (sqlite) and can be reopened later.

## API keys

All optional. Add them in **Settings**; they are stored at
`%APPDATA%\Null-Trace\config.json` (Linux/macOS: `~/.nulltrace/config.json`) and only
ever sent to the provider that issued them.

| Key | Unlocks | Free tier |
|---|---|---|
| Hunter.io | Email finder API search | 25 searches/month |
| Numverify | Live carrier / line type | 100/month |
| IPQualityScore | Phone fraud scoring | 200/month |
| NewsAPI | Article search | developer plan |
| Google CSE key + cx | Programmatic image / web search | 100 queries/day |
| HaveIBeenPwned | Breach lookup by email | paid |
| OpenCage | Reverse geocoding | 2,500/day |
| GitHub token | 5,000 req/h instead of 60 | free |
| Shodan | Optional; InternetDB already free | paid |
| VirusTotal | File-hash reputation in Hash Lookup | free tier |

Modules that need a key you have not set still run — they print what is skipped and
continue with the free sources.

## Project layout

```
Null-Trace/
├── .github/      CI workflow, issue forms, security policy
├── assets/       logo, banner, footer card and app icon
├── data/         wordlists and dork catalogue, editable without code changes
├── docs/         architecture, module reference, configuration, development
├── examples/     sample headers, config and exported output
├── legal/        disclaimer, privacy, third-party notices
├── nulltrace/    application package (gui, modules, transport, storage)
├── packaging/    PyInstaller spec and Windows build script
├── scripts/      developer checks
├── tests/        offline unit tests
├── scan.py       entry point (GUI and headless)
├── LICENSE       MIT
└── requirements.txt
```

## Testing

```bash
python -m unittest discover -s tests -v
python scripts/dev_check.py          # compile + tests + inventory
```

The suite is offline: validators, the module registry, output formatting, config
persistence, dataset loaders and the email-header analyser against a fixture.
CI runs it on Windows for Python 3.11–3.13 on every push.

## Data & files

| Path | Contents |
|---|---|
| `scan.py` | entry point (GUI and headless) |
| `nulltrace/modules/` | one file per module |
| `nulltrace/gui/` | application shell |
| `data/` | reference lists loaded at runtime (with built-in fallbacks) |
| `%APPDATA%\Null-Trace\config.json` | API keys and network settings |
| `%APPDATA%\Null-Trace\history.db` | sqlite scan history |
| `%APPDATA%\Null-Trace\wifi_qr.png` | last generated Wi-Fi QR code |
| `%APPDATA%\Null-Trace\rdap_dns.json` | cached IANA RDAP bootstrap |
| `%APPDATA%\Null-Trace\kev.json` | cached CISA KEV catalogue |

## Troubleshooting

**The window doesn't open / `ModuleNotFoundError: tkinter`** — tkinter is not a pip
package. On Debian/Ubuntu: `sudo apt install python3-tk`. On Windows, re-run the
python.org installer and keep the "tcl/tk" option.

**`ModuleNotFoundError: readline`** — not used by Null-Trace. That error comes from the
old X-osint script.

**SMTP module says "Could not connect on port 25"** — most consumer ISPs block
outbound 25. Run from a VPS or skip that module.

**Subdomains returns 0 from crt.sh** — crt.sh rate limits hard and returns 502.
HackerTarget usually still answers; wait a minute and retry.

**Dark Web Search returns the Ahmia landing page** — Ahmia rotates an anti-bot token.
Null-Trace fetches the token first; if it still fails you are rate limited — wait.

**Tor checkbox fails** — install `requests[socks]` and make sure the Tor service is
listening on `127.0.0.1:9050` (Tor Browser: `tor.exe`). Adjust the proxy in Settings.

**Metadata shows fewer tags than expected** — install ExifTool (Toolkit → Install
ExifTool, or `winget install OliverBetz.ExifTool`). Pillow only reads image EXIF.

**Port scan needs administrator?** No — it uses ordinary TCP connect. Some hosts
rate-limit or block SYN-less scans; that's their firewall, not a bug.

**The window closed or froze during a scan** — fixed in 1.0.x; it was a Tk
finaliser running on the worker thread. If it ever happens again, the reason is
written to `%APPDATA%\Null-Trace\crash.log`; attach that file to a bug report.

**Scans feel slow** — port scanning runs 512 connections at a time and DNS
resolution 128 lookups at a time. Lower `timeout` before widening ranges; a
/16 sweep still takes minutes because it is 65,535 round trips, not because of
Python.

## Author

**Ratnadeep Bose** (he/him) — [github.com/r4tnadeepbose](https://github.com/r4tnadeepbose?tab=repositories)

Null-Trace is an independent Python rewrite inspired by the open-source TermuxHackz
X-osint tool. Third-party data providers are credited in **About → Credits** inside
the application.

## Legal

**Use it only where you are allowed to.** Null-Trace targets public data and systems
you own or are contracted to test.

| Allowed | Not allowed |
|---|---|
| Your own hosts, domains, accounts and devices | Systems you do not own and have no permission to test |
| Authorised penetration tests and incident response | Profiling private people, their family or their contact details |
| Research on public figures and public organisations | Harassment, stalking, doxxing, credential theft |
| Exposure checks on identifiers you own | Bypassing authentication or access controls |

Breach and stealer data contains personal information. Handling it is regulated
(GDPR, DPDP Act 2023, CCPA). A finding is evidence of exposure — not proof of
wrongdoing, and not permission to use it.

**You are solely responsible for your use of this tool and for complying with the
law in your jurisdiction.** Full terms: [legal/DISCLAIMER.md](legal/DISCLAIMER.md),
[legal/PRIVACY.md](legal/PRIVACY.md), [legal/THIRD_PARTY.md](legal/THIRD_PARTY.md).

## License

MIT © 2026 Ratnadeep Bose — see [LICENSE](LICENSE).

You may use, modify and redistribute it, including commercially, provided the
copyright notice and licence text stay with the software. It comes with no warranty.

---

<div align="center">
  <img src="assets/footer.svg" alt="Use it responsibly — you are solely responsible for how you use this tool and for complying with the law where you live" width="100%">
</div>

<p align="center">
  <sub><strong>You are solely responsible</strong> for how you use Null-Trace. Investigate only what you are authorised to investigate.</sub>
</p>


