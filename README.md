# Website security check

A small command-line tool that grades a website's basic security setup (A–F) and
writes a client-friendly report with prioritised fixes — the kind of quick audit a
small business, agency or WordPress site owner can act on the same day.

It is **passive**: it only makes the ordinary requests a browser makes when opening the
homepage (plus `/.well-known/security.txt`). No scanning, fuzzing or login attempts.
Use it on sites you own or are authorised to assess.

## What it checks

| Area | Check |
|---|---|
| Transport | HTTP → HTTPS redirect, certificate validity and days to expiry, TLS version |
| Headers | HSTS (and its max-age), Content-Security-Policy (incl. `unsafe-inline` in scripts), clickjacking protection, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` |
| Disclosure | Software versions in `Server` / `X-Powered-By`, WordPress generator tag |
| Cookies | `Secure`, `HttpOnly`, `SameSite` on cookies set by the homepage |
| Disclosure policy | `security.txt` |

Each problem lowers the score by its severity (high / medium / low), and the report
lists fixes in priority order, with the exact header to add.

## Run it

```bash
pip install -r requirements.txt
python sitecheck.py example.com
python sitecheck.py https://example.com --report sample-reports   # + Markdown and HTML report
python -m pytest -q
```

Example terminal output:

```
Security check: wordpress.org   score 70/100   grade C

  ✔ HTTP → HTTPS redirect      http:// redirects to https://wordpress.org/
  ✔ TLS certificate            Valid for 75 more days, issuer Let's Encrypt.
  ! Strict-Transport-Security  max-age=3600 is under 6 months.
  ✘ Content-Security-Policy    Header missing.
  ...
Recommended fixes (most important first):
  1. [medium] Content-Security-Policy: Define a CSP; start with Content-Security-Policy-Report-Only ...
```

A sample HTML/Markdown report is in [`sample-reports/`](sample-reports/).

## Limits

This is a configuration check, not a penetration test: it cannot find bugs in the
application's code, plugins or business logic.
