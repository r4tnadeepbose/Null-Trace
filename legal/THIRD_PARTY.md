# Third-party data and software

Null-Trace is MIT licensed. It talks to public services whose own terms apply to
the queries you send them.

## Python dependencies

| Package | Licence | Used for |
|---|---|---|
| requests | Apache-2.0 | every HTTP call |
| dnspython | ISC | DNS record queries |
| customtkinter | MIT | desktop widgets |
| Pillow | HPND | image metadata fallback |
| phonenumbers | Apache-2.0 | offline phone parsing |
| piexif | MIT | EXIF writing support |
| qrcode | BSD-3-Clause | Wi-Fi QR codes |
| beautifulsoup4 | MIT | Ahmia result parsing |
| speedtest-cli | Apache-2.0 | throughput test |
| PySocks | BSD-3-Clause | Tor SOCKS transport |
| requests-futures | Apache-2.0 | threaded probes in the Sherlock engine |
| colorama | MIT | ANSI handling inside the Sherlock engine |
| openpyxl | MIT | .xlsx report writer |

## Vendored software

### Sherlock 0.16.2 (`sherlock_project/`)

Sherlock — "Hunt down social media accounts by username across social networks" —
Copyright (c) Siddharth Dushantha and contributors, MIT licensed. The full
source, including `resources/data.json` (the 480-site manifest) and
`resources/data.schema.json`, ships unmodified in `sherlock_project/` together
with its `LICENSE`. Upstream project: <https://sherlockproject.xyz/> /
<https://github.com/sherlock-project/sherlock>.

Null-Trace applies two local patches, both marked in the code:

| File | Change |
|---|---|
| `__init__.py` | version string is pinned instead of read from installed package metadata (`tomli`) |
| `sherlock.py` | the `.xlsx` export writes with `openpyxl` rather than `pandas`, so Null-Trace does not need pandas |

Everything else runs as upstream: per-site probe methods, `soft404` handling,
`errorUrl`/`errorMsg` signatures, WAF detection, the live manifest at
`data.sherlockproject.xyz`, the false-positive exclusion list at
`raw.githubusercontent.com/sherlock-project/sherlock` and the CLI, reachable via
`python scan.py --sherlock ...`.

## Data sources

| Source | What is used | Notes |
|---|---|---|
| ipinfo.io / ip-api.com | geolocation, ASN | free tiers, rate limited |
| Shodan InternetDB | passive ports and CVEs | free, no key |
| NVD (NIST) | CVE records | public domain, 5 req/30 s without key |
| CISA KEV | exploited-vulnerability catalogue | public domain |
| crt.sh | certificate transparency | rate limited, often 502 |
| HackerTarget | passive DNS | free quota |
| Hudson Rock Cavalier | infostealer exposure | free OSINT API |
| HaveIBeenPwned | breach lookup | requires your own key |
| Hunter.io, Numverify, IPQualityScore, NewsAPI, OpenCage, VirusTotal, Google CSE | enrichment | requires your own key |
| Ahmia | onion index | clearnet mirror or via Tor |
| NHTSA vPIC | VIN decoding | US government public domain |
| macvendors.com | OUI lookup | 1 request/second |
| GitHub REST API | profile and repository data | 60 req/h unauthenticated |
| Google News RSS | news search | public feed |
| Ookla speedtest | network throughput | public endpoints |
| data.sherlockproject.xyz | live username-probe manifest | only when "Live upstream manifest" is chosen |
| sherlock-project/sherlock (GitHub raw) | false-positive exclusion list | skipped when exclusions are unticked |

## Prior art

Null-Trace is an independent Python rewrite inspired by the open-source
TermuxHackz X-osint tool. It shares no code with it; the module model, GUI,
storage and data layer were written from scratch under the MIT licence.

## Trademarks

Product and company names in the tool's output belong to their respective
owners and are used only to describe the data returned by those services.
