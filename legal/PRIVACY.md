# Privacy

## What Null-Trace collects about you

Nothing. There is no telemetry, no analytics, no crash reporting and no update
beacon. The application does not contact the author's infrastructure because
none exists.

## What is stored on your machine

| File | Content | Protection |
|---|---|---|
| `config.json` | API keys, timeouts, user agent | plain text, user profile permissions |
| `history.db` | module, target, timestamps, rendered output | plain text, user profile permissions |
| `kev.json`, `rdap_dns.json` | caches of public feeds | public data |
| `wifi_qr.png` | last generated Wi-Fi QR | contains the Wi-Fi password — delete after use |

`history.db` can contain sensitive findings. Export only what you need, and
delete runs from the History screen when you are done with them.

## Who sees your queries

Every module talks directly to the provider it uses. Your IP address, user
agent and query are visible to that provider under their own terms and retention
policy. There is no intermediate hop.

Providers contacted, depending on the module:

- ipinfo.io, ip-api.com, Shodan InternetDB
- public DNS resolvers (system resolver and, for RDAP, the registry endpoints)
- certificate transparency logs (crt.sh), HackerTarget
- NVD, CISA
- Hudson Rock Cavalier
- HaveIBeenPwned (only if you configured a key)
- Hunter.io, Numverify, IPQualityScore, NewsAPI, OpenCage, VirusTotal,
  Google Custom Search (only if you configured a key)
- GitHub (public API; with a token if configured)
- Ahmia (and Tor, only if you enable routing)
- NHTSA vPIC, macvendors.com
- Ookla speedtest endpoints

To hide your origin from these providers, run the application behind a VPN or a
proxy you trust. The Dark Web module can route through Tor when enabled.

## Deleting your data

Delete `%APPDATA%\Null-Trace` (Windows) or `~/.null-trace` (Linux/macOS). Keys,
history and caches are all inside that folder.
