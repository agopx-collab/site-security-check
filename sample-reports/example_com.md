# Security check — example.com

**Score:** 34/100 · **Grade:** F · **Date:** 2026-10-08 · **Final URL:** https://example.com/

| | Check | Result |
|---|---|---|
| ✘ | HTTP → HTTPS redirect | The site is served over plain HTTP without redirecting. |
| ✔ | TLS certificate | Valid for 78 more days, issuer SSL Corporation. |
| ✔ | TLS version | Negotiated TLSv1.3. |
| ✘ | Strict-Transport-Security | Header missing. |
| ✘ | Content-Security-Policy | Header missing. |
| ✘ | Clickjacking protection | Pages can be framed by any site. |
| ✘ | X-Content-Type-Options | Header missing. |
| ✘ | Referrer-Policy | Header missing (full URLs may leak to other sites). |
| ✘ | Permissions-Policy | Header missing. |
| ✔ | Version disclosure | No version numbers in server headers. |
| · | Cookie flags | The homepage sets no cookies. |
| ! | security.txt | No /.well-known/security.txt. |

## Recommended fixes

1. **HTTP → HTTPS redirect** (high) — Redirect all http:// requests to https:// with a 301.
2. **Strict-Transport-Security** (medium) — Add: Strict-Transport-Security: max-age=31536000; includeSubDomains
3. **Content-Security-Policy** (medium) — Define a CSP; start with Content-Security-Policy-Report-Only to avoid breaking the site.
4. **Clickjacking protection** (medium) — Add: X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors 'self').
5. **X-Content-Type-Options** (low) — Add: X-Content-Type-Options: nosniff
6. **Referrer-Policy** (low) — Add: Referrer-Policy: strict-origin-when-cross-origin
7. **Permissions-Policy** (low) — Add e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=()
8. **security.txt** (low) — Publish a security.txt so researchers know how to report problems (securitytxt.org).

_Passive check: only standard page requests were made. It does not replace a full penetration test._
