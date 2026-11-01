# Examples

| File | Use |
|---|---|
| `sample_email_headers.txt` | paste into **Email Headers** — a deliberate phishing pattern, flagged as high risk |
| `sample_config.json` | reference shape of `config.json`; copy it to `%APPDATA%\Null-Trace\config.json` if you prefer editing by hand |
| `sample_output.txt` | what an exported scan looks like |

## Try the header analyser

```bash
python scan.py --run email_headers -a "raw=$(cat examples/sample_email_headers.txt)"
```

Expected verdict: `high risk`, with SPF failure, DMARC failure, and a Reply-To
domain that does not match the From domain.

## Try a normal scan

```bash
python scan.py --run ip_info    -a target=1.1.1.1
python scan.py --run dns_lookup -a domain=example.com -a rtype=MX
python scan.py --run whois_rdap -a target=example.com
python scan.py --run hash_lookup -a value="hello world"
```

All four use free sources and need no API key.
