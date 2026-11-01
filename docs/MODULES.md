# Module reference

Generated from `nulltrace/modules/__init__.py` — 32 modules.

| Module | ID | Category | Inputs | API key |
|---|---|---|---|---|
| **Quick Recon** | `auto_recon` | Recon | target* | — |
| **IP Intel** | `ip_info` | Network | target* | — |
| **DNS Lookup** | `dns_lookup` | Network | domain*, rtype (choice), common (checkbox) | — |
| **DNS Reverse** | `dns_reverse` | Network | ip* | — |
| **Port Scan** | `port_scan` | Network | host*, preset (choice), ports, timeout, banner (checkbox) | — |
| **MAC Vendor** | `mac_lookup` | Network | macs* (multiline) | — |
| **Network Map** | `netmap` | Network | host*, hops, geo (checkbox) | — |
| **WHOIS / RDAP** | `whois_rdap` | Web | target* | — |
| **URL Inspector** | `url_inspector` | Web | url* | — |
| **Host Search** | `host_search` | Web | target*, tls (checkbox) | — |
| **Subdomains** | `subdomains` | Web | domain*, resolve (checkbox), brute (checkbox) | — |
| **Google Dorks** | `dorks` | Web | domain*, terms, category (choice), engine (choice), limit | — |
| **Dark Web Search** | `darkweb` | Web | query*, tor (checkbox) | — |
| **News** | `news` | Web | query*, limit | newsapi |
| **Email Intel** | `email_intel` | Identity | email* | hibp |
| **Email Finder** | `email_finder` | Identity | domain*, first, last, smtp (checkbox) | hunter |
| **Exposure Audit** | `exposure_audit` | Identity | email, phone, name, breach (checkbox), stealer (checkbox), dns (checkbox), footprint (checkbox) | hibp |
| **Phone Intel** | `phone_info` | Identity | number*, region | numverify, ipqualityscore |
| **Username Scan** | `username_scan` | Identity | username*, scope (choice) | — |
| **Email Headers** | `email_headers` | Identity | raw* (multiline), geo (checkbox) | — |
| **SMTP Analysis** | `smtp` | Identity | domain*, recipient, starttls (checkbox) | — |
| **Infostealer Exposure** | `infostealer` | Identity | mode (choice), query* | — |
| **GitHub Recon** | `github` | Identity | mode (choice), target* | github |
| **CVE / Exploits** | `cve_research` | Vulnerability | query*, severity (choice), limit | — |
| **Metadata** | `metadata` | Media | path* (file) | — |
| **Hash Lookup** | `hash_lookup` | Media | value* (file) | virustotal |
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

### DNS Reverse (`dns_reverse`)

Resolve an IP back to hostnames (PTR records and system resolver).

### Port Scan (`port_scan`)

Multi-threaded TCP connect scan with service labels, banner grab and passive Shodan cross-check.

### MAC Vendor (`mac_lookup`)

Resolve MAC addresses to manufacturers, and flag randomised or multicast addresses.

### Network Map (`netmap`)

Traceroute to a target with city/country/ASN lookup for every responding hop.

### WHOIS / RDAP (`whois_rdap`)

Domain or IP registration data: registrar, dates, statuses, nameservers and contacts.

### URL Inspector (`url_inspector`)

Expand short links, follow the redirect chain, and flag homograph or phishing patterns.

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

### CVE / Exploits (`cve_research`)

Search NVD by CVE ID, product or keyword and flag entries in CISA's Known Exploited catalogue.

### Metadata (`metadata`)

Read EXIF/XMP/document metadata, highlight device fingerprints and extract GPS coordinates.

### Hash Lookup (`hash_lookup`)

MD5/SHA1/SHA256 for a file or text, file-type heuristics and VirusTotal reputation.

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

