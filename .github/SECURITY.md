# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | yes |

## Reporting a vulnerability

Open a private advisory at
https://github.com/r4tnadeepbose/Null-Trace/security/advisories/new

Please do not open a public issue for anything that could put users at risk.
Useful reports include:

- credential or key leakage from the config store;
- a module that writes outside its data folder;
- command injection through user-supplied values;
- TLS verification being weakened without warning;
- dependency vulnerabilities with a practical attack path.

## Out of scope

- Findings that require the user to run the tool against a target they do not
  own. That is a misuse of the tool, not a vulnerability in it.
- Rate limits, blocked requests or captchas from third-party data providers.
- The accuracy of third-party data (breach lists, stealer logs, RDAP records).

## What the tool stores

Credentials live in `%APPDATA%\Null-Trace\config.json` in plain text, readable
by the current user only. Scan history lives in `history.db` next to it. There
is no telemetry, no update beacon and no Null-Trace server.
