# Module reference

Generated from `nulltrace/modules/__init__.py` — 49 modules.

| Module | ID | Category | Inputs | API key |
|---|---|---|---|---|
| **Quick Recon** | `auto_recon` | Recon | target* | — |
| **IP Intel** | `ip_info` | Network | target* | — |
| **DNS Lookup** | `dns_lookup` | Network | domain*, rtype (choice), common (checkbox) | — |
| **DNS Propagation** | `dns_propagation` | Network | domain*, rtype (choice) | — |
| **DNS Reverse** | `dns_reverse` | Network | ip* | — |
| **Port Scan** | `port_scan` | Network | host*, preset (choice), ports, timeout, banner (checkbox) | — |
| **BGP / ASN** | `bgp_asn` | Network | query* | — |
| **IP Reputation** | `dnsbl` | Network | ip* | — |
| **MAC Vendor** | `mac_lookup` | Network | macs* (multiline) | — |
| **Reverse IP** | `reverse_ip` | Network | ip* | — |
| **Network Map** | `netmap` | Network | host*, hops, geo (checkbox) | — |
| **My Connection** | `my_connection` | Network | — | — |
| **WHOIS / RDAP** | `whois_rdap` | Web | target* | — |
| **TLS Inspector** | `tls_inspector` | Web | host*, port | — |
| **TLS Versions** | `tls_versions` | Web | host*, port | — |
| **Wayback** | `wayback` | Web | target*, limit | — |
| **URL Inspector** | `url_inspector` | Web | url* | — |
| **Takeover Check** | `subdomain_takeover` | Web | host* | — |
| **Site Files** | `site_files` | Web | target* | — |
| **CORS Check** | `cors_check` | Web | url*, origin | — |
| **Cookie Audit** | `cookie_audit` | Web | url* | — |
| **Bulk URLs** | `bulk_urls` | Web | urls* (multiline) | — |
| **Host Search** | `host_search` | Web | target*, tls (checkbox) | — |
| **Subdomains** | `subdomains` | Web | domain*, resolve (checkbox), brute (checkbox) | — |
| **Google Dorks** | `dorks` | Web | domain*, terms, category (choice), engine (choice), limit | — |
| **Dark Web Search** | `darkweb` | Web | query*, tor (checkbox) | — |
| **News** | `news` | Web | query*, limit | newsapi |
| **Email Intel** | `email_intel` | Identity | email* | hibp |
| **Email Finder** | `email_finder` | Identity | domain*, first, last, smtp (checkbox) | hunter |
| **Exposure Audit** | `exposure_audit` | Identity | email, phone, name, breach (checkbox), stealer (checkbox), dns (checkbox), footprint (checkbox) | hibp |
| **Phone Intel** | `phone_info` | Identity | number*, region | numverify, ipqualityscore |
| **Username OSINT** | `username_osint` | Identity | usernames* (multiline), scope (choice), manifest (choice), custom_manifest, only_sites, skip_sites, timeout, proxy, html (checkbox), exclusions (checkbox), variants (checkbox), tor (checkbox), print_all (checkbox), list_sites (checkbox), browse (checkbox), save (checkbox), xlsx (checkbox) | — |
| **Username Scan** | `username_scan` | Identity | username*, scope (choice) | — |
| **Email Headers** | `email_headers` | Identity | raw* (multiline), geo (checkbox) | — |
| **SMTP Analysis** | `smtp` | Identity | domain*, recipient, starttls (checkbox) | — |
| **Infostealer Exposure** | `infostealer` | Identity | mode (choice), query* | — |
| **GitHub Recon** | `github` | Identity | mode (choice), target* | github |
| **JWT Inspector** | `jwt_inspector` | Utility | token* (multiline) | — |
| **Hash Identifier** | `hash_identify` | Utility | hash* | — |
| **CVE / Exploits** | `cve_research` | Vulnerability | query*, severity (choice), limit | — |
| **Metadata** | `metadata` | Media | path* (file) | — |
| **Hash Lookup** | `hash_lookup` | Media | value* (file) | virustotal |
| **File Triage** | `file_triage` | Media | path* (file) | — |
| **VIN Decoder** | `vin` | Media | vin* | — |
| **Image Search** | `image_search` | Media | target* (file) | google_cse_key, google_cse_cx |
| **Wi-Fi** | `wifi` | System | mode (choice), profile | — |
| **Speed Test** | `speedtest` | System | — | — |
| **Toolkit** | `tools` | System | mode (choice) | — |
| **About** | `about` | System | — | — |

`*` marks a required input.

## What each one gives you

### Quick Recon (`auto_recon`)

One target in — domain, IP, email, phone, VIN, hash or username — swept across the matching modules with a findings summary.

### IP Intel (`ip_info`)

Geolocation, ASN, reverse DNS, exposed ports and known CVEs for an IP or hostname.

### DNS Lookup (`dns_lookup`)

Query any record type (A/AAAA/MX/TXT/NS/CNAME/SOA/CAA/SRV) with optional subdomain probe.

### DNS Propagation (`dns_propagation`)

Ask five public resolvers for the same record and compare their answers.

### DNS Reverse (`dns_reverse`)

Resolve an IP back to hostnames (PTR records and system resolver).

### Port Scan (`port_scan`)

Multi-threaded TCP connect scan with service labels, banner grab and passive Shodan cross-check.

### BGP / ASN (`bgp_asn`)

Autonomous system holder, announced prefixes and upstreams, via RIPE Stat.

### IP Reputation (`dnsbl`)

Check an IPv4 address against six public DNS blocklists and list the reasons.

### MAC Vendor (`mac_lookup`)

Resolve MAC addresses to manufacturers, and flag randomised or multicast addresses.

### Reverse IP (`reverse_ip`)

Domains hosted on the same address, from a passive reverse-IP index.

### Network Map (`netmap`)

Traceroute to a target with city/country/ASN lookup for every responding hop.

### My Connection (`my_connection`)

Your public address, network owner, reverse DNS and whether a proxy is in front.

### WHOIS / RDAP (`whois_rdap`)

Domain or IP registration data: registrar, dates, statuses, nameservers and contacts.

### TLS Inspector (`tls_inspector`)

Certificate subject, issuer, SANs, expiry countdown and whether the chain verifies.

### TLS Versions (`tls_versions`)

Negotiate each TLS version in turn and flag deprecated protocols or weak ciphers.

### Wayback (`wayback`)

Archived snapshots of a URL or domain from the Internet Archive CDX index.

### URL Inspector (`url_inspector`)

Expand short links, follow the redirect chain, and flag homograph or phishing patterns.

### Takeover Check (`subdomain_takeover`)

Follow CNAMEs into known services and look for the 'this host is gone' page.

### Site Files (`site_files`)

robots.txt, sitemap.xml, security.txt, humans.txt and ads.txt, parsed into a summary.

### CORS Check (`cors_check`)

Send a foreign Origin and report whether the endpoint reflects it or allows credentials.

### Cookie Audit (`cookie_audit`)

Parse Set-Cookie headers and flag missing Secure, HttpOnly, SameSite or bad lifetimes.

### Bulk URLs (`bulk_urls`)

Fetch many URLs concurrently and report status, latency and page title.

### Host Search (`host_search`)

HTTP headers, redirects, TLS certificate, tech fingerprints and exposed well-known paths.

### Subdomains (`subdomains`)

Certificate transparency (crt.sh), passive DNS (HackerTarget) and optional label brute force.

### Google Dorks (`dorks`)

Generate targeted dork queries for a domain and open them in Google, Bing or DuckDuckGo.

### Dark Web Search (`darkweb`)

Query Ahmia for indexed onion services, over clearnet or through a local Tor SOCKS proxy.

### News (`news`)

Search recent coverage for a person, company or keyword; uses NewsAPI when configured.

### Email Intel (`email_intel`)

Mail infrastructure, SPF/DMARC, Gravatar, ProtonMail key directory and breach exposure.

### Email Finder (`email_finder`)

Hunter.io lookup plus name-pattern candidates, with optional SMTP RCPT verification.

### Exposure Audit (`exposure_audit`)

Self-audit: breaches, stealer logs, mail posture and public footprint in one scored report.

### Phone Intel (`phone_info`)

Offline validity, carrier, region and timezone; optional Numverify and IPQS enrichment.

### Username OSINT (`username_osint`)

The vendored 0.16.2 probing engine, end to end: the manifest's ~480 sites, each
checked against its own signature (status codes, expected strings, the redirect
target it should return, POST payloads and per-site headers). Mirrors the upstream flags —
`--site`, `--nsfw`, `--ignore-exclusions`, `--proxy`, `--timeout`, `--print-all`,
`--browse`, `{?}` variants, `--json` custom site list and txt/csv/json/xlsx export —
and adds a "never probe these" filter, local Tor detection and live progress in
the GUI.

By default the results are written to a standalone HTML page and that page opens
itself when the scan ends; the pane then shows only the summary. Untick "Open the
HTML report when the scan ends" to print the full tables in the pane instead. The
page is self-contained (inline CSS, no scripts fetched, every cell escaped), groups
sites as matched / clear / inconclusive with the reason for each inconclusive
answer, and has a live filter box.

Reports land in `%APPDATA%/Null-Trace/username-osint/`. The full upstream CLI is
also reachable with `python scan.py --probe-cli user123 --site github --csv`.

### Username Scan (`username_scan`)

Check whether a handle exists on 20 developer and social platforms, with profile links.

### Email Headers (`email_headers`)

Paste raw headers to trace the hop chain, read SPF/DKIM/DMARC and spot spoofing.

### SMTP Analysis (`smtp`)

MX records, SPF/DMARC, live SMTP banner, ESMTP capabilities, STARTTLS and one RCPT probe.

### Infostealer Exposure (`infostealer`)

Check whether an email, username or domain appears in infostealer malware logs (Hudson Rock).

### GitHub Recon (`github`)

Profile and repository intel, recent activity, and commit-history email discovery.

### JWT Inspector (`jwt_inspector`)

Decode a JSON Web Token locally, list claims and flag alg=none, weak algorithms and long lifetimes.

### Hash Identifier (`hash_identify`)

Name the likely algorithm from a digest's shape, with a warning for weak and short hashes.

### CVE / Exploits (`cve_research`)

Search NVD by CVE ID, product or keyword and flag entries in CISA's Known Exploited catalogue.

### Metadata (`metadata`)

Read EXIF/XMP/document metadata, highlight device fingerprints and extract GPS coordinates.

### Hash Lookup (`hash_lookup`)

MD5/SHA1/SHA256 for a file or text, file-type heuristics and VirusTotal reputation.

### File Triage (`file_triage`)

Entropy, header type, printable strings and URL/IP/email indicators in a suspicious file.

### VIN Decoder (`vin`)

Decode a 17-character VIN into make, model, engine, plant and check-digit validity.

### Image Search (`image_search`)

Hash a local image or run a URL through Google Lens, Yandex, Bing, TinEye and Google CSE.

### Wi-Fi (`wifi`)

Enumerate nearby networks, list saved profiles, or reveal a saved password and generate a QR code.

### Speed Test (`speedtest`)

Measure latency, download and upload throughput against the nearest Ookla server.

### Toolkit (`tools`)

Check the runtime, Python packages, external tools and API keys; install ExifTool; check updates.

### About (`about`)

Version, changelog and the rules of engagement this tool is built around.

