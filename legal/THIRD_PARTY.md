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

## Prior art

Null-Trace is an independent Python rewrite inspired by the open-source
TermuxHackz X-osint tool. It shares no code with it; the module model, GUI,
storage and data layer were written from scratch under the MIT licence.

## Trademarks

Product and company names in the tool's output belong to their respective
owners and are used only to describe the data returned by those services.
