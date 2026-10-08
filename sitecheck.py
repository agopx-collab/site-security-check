#!/usr/bin/env python3
"""
Passive website security check -> graded report (terminal, Markdown, HTML).

Makes only a handful of ordinary GET requests, the same a browser makes when it opens
the homepage: no scanning, fuzzing or login attempts. Use it on sites you own or are
authorised to assess.

Checks: HTTPS redirect, TLS certificate, security headers, cookie flags,
version disclosure, WordPress generator tag, security.txt.

Usage:
    python sitecheck.py example.com
    python sitecheck.py https://example.com --report reports/
"""

from __future__ import annotations

import argparse
import html
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

import requests

USER_AGENT = "sitecheck/1.0 (passive security header check)"
TIMEOUT = 15

# Severity -> points deducted from 100.
WEIGHTS = {"high": 20, "medium": 10, "low": 4, "info": 0}


@dataclass
class Finding:
    check: str
    status: str            # "pass" | "fail" | "warn" | "info"
    severity: str          # key of WEIGHTS; only counted when status != "pass"
    detail: str
    fix: str = ""


@dataclass
class Report:
    target: str
    final_url: str = ""
    findings: list[Finding] = field(default_factory=list)

    def add(self, *args, **kwargs) -> None:
        self.findings.append(Finding(*args, **kwargs))

    @property
    def score(self) -> int:
        lost = sum(WEIGHTS[f.severity] for f in self.findings if f.status in ("fail", "warn"))
        return max(0, 100 - lost)

    @property
    def grade(self) -> str:
        for limit, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
            if self.score >= limit:
                return letter
        return "F"


# --------------------------------------------------------------------------- checks

def check_https_redirect(host: str, report: Report, session: requests.Session) -> None:
    try:
        response = session.get(f"http://{host}/", allow_redirects=True, timeout=TIMEOUT)
    except requests.RequestException as error:
        report.add("HTTP → HTTPS redirect", "info", "info", f"Plain HTTP not reachable ({type(error).__name__}).")
        return
    if response.url.startswith("https://"):
        report.add("HTTP → HTTPS redirect", "pass", "high", f"http:// redirects to {response.url}")
    else:
        report.add("HTTP → HTTPS redirect", "fail", "high", "The site is served over plain HTTP without redirecting.",
                   "Redirect all http:// requests to https:// with a 301.")


def check_certificate(host: str, report: Report) -> None:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert, version = tls.getpeercert(), tls.version()
    except ssl.SSLCertVerificationError as error:
        report.add("TLS certificate", "fail", "high", f"Certificate is not valid: {error.verify_message}.",
                   "Install a valid certificate for this hostname (e.g. free from Let's Encrypt).")
        return
    except (OSError, ssl.SSLError) as error:
        report.add("TLS certificate", "fail", "high", f"HTTPS connection failed: {error}.",
                   "Make sure HTTPS is enabled on port 443.")
        return

    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days
    issuer = dict(item[0] for item in cert.get("issuer", ())).get("organizationName", "unknown")
    if days < 14:
        report.add("TLS certificate", "fail", "high", f"Expires in {days} days ({expires:%Y-%m-%d}), issuer {issuer}.",
                   "Renew the certificate now and enable automatic renewal.")
    elif days < 30:
        report.add("TLS certificate", "warn", "low", f"Expires in {days} days ({expires:%Y-%m-%d}), issuer {issuer}.",
                   "Check that automatic renewal is working.")
    else:
        report.add("TLS certificate", "pass", "high", f"Valid for {days} more days, issuer {issuer}.")

    if version in ("TLSv1", "TLSv1.1"):
        report.add("TLS version", "fail", "medium", f"Negotiated {version}.", "Disable TLS 1.0/1.1; allow TLS 1.2+.")
    else:
        report.add("TLS version", "pass", "medium", f"Negotiated {version}.")


def check_headers(headers: requests.structures.CaseInsensitiveDict, report: Report) -> None:
    hsts = headers.get("Strict-Transport-Security", "")
    max_age = int(m.group(1)) if (m := re.search(r"max-age=(\d+)", hsts)) else 0
    if not hsts:
        report.add("Strict-Transport-Security", "fail", "medium", "Header missing.",
                   "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    elif max_age < 15552000:
        report.add("Strict-Transport-Security", "warn", "low", f"max-age={max_age} is under 6 months.",
                   "Raise max-age to at least 15552000 (180 days), ideally 31536000.")
    else:
        report.add("Strict-Transport-Security", "pass", "medium", hsts)

    csp = headers.get("Content-Security-Policy", "")
    directives = {d.split()[0].lower(): d for d in (part.strip() for part in csp.split(";")) if d}
    scripts = directives.get("script-src") or directives.get("default-src", "")
    if not csp:
        report.add("Content-Security-Policy", "fail", "medium", "Header missing.",
                   "Define a CSP; start with Content-Security-Policy-Report-Only to avoid breaking the site.")
    elif "'unsafe-inline'" in scripts and "'nonce-" not in scripts and "'strict-dynamic'" not in scripts:
        report.add("Content-Security-Policy", "warn", "low", "Present, but script-src allows 'unsafe-inline'.",
                   "Replace 'unsafe-inline' scripts with nonces or hashes.")
    else:
        report.add("Content-Security-Policy", "pass", "medium", shorten(csp))

    if "frame-ancestors" in directives or headers.get("X-Frame-Options", "").upper() in ("DENY", "SAMEORIGIN"):
        report.add("Clickjacking protection", "pass", "medium", "X-Frame-Options or CSP frame-ancestors set.")
    else:
        report.add("Clickjacking protection", "fail", "medium", "Pages can be framed by any site.",
                   "Add: X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors 'self').")

    if headers.get("X-Content-Type-Options", "").lower() == "nosniff":
        report.add("X-Content-Type-Options", "pass", "low", "nosniff")
    else:
        report.add("X-Content-Type-Options", "fail", "low", "Header missing.", "Add: X-Content-Type-Options: nosniff")

    if headers.get("Referrer-Policy"):
        report.add("Referrer-Policy", "pass", "low", headers["Referrer-Policy"])
    else:
        report.add("Referrer-Policy", "fail", "low", "Header missing (full URLs may leak to other sites).",
                   "Add: Referrer-Policy: strict-origin-when-cross-origin")

    if headers.get("Permissions-Policy"):
        report.add("Permissions-Policy", "pass", "low", shorten(headers["Permissions-Policy"]))
    else:
        report.add("Permissions-Policy", "fail", "low", "Header missing.",
                   "Add e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=()")

    leaks = [f"{name}: {headers[name]}" for name in ("Server", "X-Powered-By", "X-AspNet-Version")
             if name in headers and re.search(r"\d", headers[name])]
    if leaks:
        report.add("Version disclosure", "warn", "low", "; ".join(leaks),
                   "Hide software versions in server headers (helps attackers pick exploits).")
    else:
        report.add("Version disclosure", "pass", "low", "No version numbers in server headers.")


def check_cookies(raw_cookies: list[str], report: Report) -> None:
    if not raw_cookies:
        report.add("Cookie flags", "info", "info", "The homepage sets no cookies.")
        return
    problems, severity = [], "low"
    for raw in raw_cookies:
        name = raw.split("=", 1)[0].strip()
        lower = raw.lower()
        missing = [flag for flag, present in (("Secure", "; secure" in lower),
                                              ("HttpOnly", "; httponly" in lower),
                                              ("SameSite", "; samesite=" in lower)) if not present]
        if "Secure" in missing or "SameSite" in missing:
            severity = "medium"          # HttpOnly alone may be intentional (cookie read by JavaScript)
        if missing:
            problems.append(f"{name} (missing {', '.join(missing)})")
    if problems:
        report.add("Cookie flags", "warn", severity, "; ".join(problems),
                   "Set Secure, HttpOnly (unless JavaScript needs the cookie) and SameSite=Lax on cookies.")
    else:
        report.add("Cookie flags", "pass", "medium", f"{len(raw_cookies)} cookie(s) with Secure, HttpOnly, SameSite.")


def check_wordpress(body: str, report: Report) -> None:
    match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)', body, re.I)
    if match:
        version = match.group(1) or "unknown version"
        report.add("WordPress version tag", "warn", "low", f"Generator tag reveals WordPress {version}.",
                   "Remove the generator meta tag and keep WordPress, themes and plugins updated.")
    elif "/wp-content/" in body:
        report.add("WordPress version tag", "info", "info", "WordPress site; version not disclosed.")


def check_security_txt(base: str, report: Report, session: requests.Session) -> None:
    try:
        response = session.get(f"{base}/.well-known/security.txt", timeout=TIMEOUT)
        found = response.ok and "contact:" in response.text.lower()
    except requests.RequestException:
        found = False
    if found:
        report.add("security.txt", "pass", "low", "Published at /.well-known/security.txt.")
    else:
        report.add("security.txt", "warn", "low", "No /.well-known/security.txt.",
                   "Publish a security.txt so researchers know how to report problems (securitytxt.org).")


def shorten(text: str, limit: int = 90) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "…"


# --------------------------------------------------------------------------- orchestration

def run(target: str) -> Report:
    if "://" not in target:
        target = "https://" + target
    host = urlsplit(target).hostname
    if not host:
        sys.exit(f"Invalid target: {target}")
    report = Report(target=host)
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    check_https_redirect(host, report, session)
    check_certificate(host, report)
    session.cookies.clear()  # load the homepage as a first-time visitor so it sends its Set-Cookie headers
    try:
        response = session.get(f"https://{host}/", timeout=TIMEOUT)
    except requests.RequestException as error:
        report.add("Homepage over HTTPS", "fail", "high", f"Could not load https://{host}/ ({error}).")
        return report
    report.final_url = response.url
    check_headers(response.headers, report)
    check_cookies(response.raw.headers.getlist("Set-Cookie"), report)
    check_wordpress(response.text, report)
    final = urlsplit(response.url)
    check_security_txt(f"{final.scheme}://{final.netloc}", report, session)
    return report


# --------------------------------------------------------------------------- output

ICONS = {"pass": "✔", "fail": "✘", "warn": "!", "info": "·"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def to_do(report: Report) -> list[Finding]:
    return sorted((f for f in report.findings if f.status in ("fail", "warn")),
                  key=lambda f: SEVERITY_ORDER[f.severity])


def print_report(report: Report) -> None:
    print(f"\nSecurity check: {report.target}   score {report.score}/100   grade {report.grade}\n")
    width = max(len(f.check) for f in report.findings)
    for f in report.findings:
        print(f"  {ICONS[f.status]} {f.check.ljust(width)}  {f.detail}")
    actions = to_do(report)
    if actions:
        print("\nRecommended fixes (most important first):")
        for i, f in enumerate(actions, start=1):
            print(f"  {i}. [{f.severity}] {f.check}: {f.fix}")
    print()


def markdown_report(report: Report) -> str:
    lines = [f"# Security check — {report.target}", "",
             f"**Score:** {report.score}/100 · **Grade:** {report.grade} · "
             f"**Date:** {datetime.now():%Y-%m-%d} · **Final URL:** {report.final_url or '-'}", "",
             "| | Check | Result |", "|---|---|---|"]
    lines += [f"| {ICONS[f.status]} | {f.check} | {f.detail.replace('|', '/')} |" for f in report.findings]
    actions = to_do(report)
    if actions:
        lines += ["", "## Recommended fixes", ""]
        lines += [f"{i}. **{f.check}** ({f.severity}) — {f.fix}" for i, f in enumerate(actions, start=1)]
    lines += ["", "_Passive check: only standard page requests were made. "
                  "It does not replace a full penetration test._", ""]
    return "\n".join(lines)


def html_report(report: Report) -> str:
    colour = {"A": "#1a7f37", "B": "#4d8a1f", "C": "#b58100", "D": "#c4570c", "F": "#c62828"}[report.grade]
    rows = "".join(
        f'<tr class="{f.status}"><td>{ICONS[f.status]}</td><td>{html.escape(f.check)}</td>'
        f"<td>{html.escape(f.detail)}</td></tr>" for f in report.findings)
    fixes = "".join(f"<li><b>{html.escape(f.check)}</b> <span class='sev'>{f.severity}</span> — "
                    f"{html.escape(f.fix)}</li>" for f in to_do(report))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security check — {html.escape(report.target)}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:880px;margin:2rem auto;padding:0 1rem;color:#1f2328;background:#fff}}
.grade{{display:inline-block;font-size:2.2rem;font-weight:700;color:#fff;background:{colour};border-radius:10px;padding:.2rem 1rem}}
table{{border-collapse:collapse;width:100%;margin:1.5rem 0}}td{{border-bottom:1px solid #d0d7de;padding:.5rem;vertical-align:top}}
td:first-child{{width:1.5rem;text-align:center;font-weight:700}}tr.pass td:first-child{{color:#1a7f37}}
tr.fail td:first-child{{color:#c62828}}tr.warn td:first-child{{color:#b58100}}
.sev{{font-size:.8rem;background:#eaeef2;border-radius:4px;padding:0 .35rem}}li{{margin:.4rem 0}}small{{color:#59636e}}
</style></head><body>
<h1>Security check — {html.escape(report.target)}</h1>
<p><span class="grade">{report.grade}</span> &nbsp; Score <b>{report.score}/100</b> · {datetime.now():%Y-%m-%d}</p>
<table>{rows}</table>
{"<h2>Recommended fixes</h2><ol>" + fixes + "</ol>" if fixes else "<p>No fixes needed.</p>"}
<p><small>Passive check: only standard page requests were made. It does not replace a full penetration test.</small></p>
</body></html>
"""


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="domain or URL, e.g. example.com")
    parser.add_argument("--report", metavar="DIR", help="also write Markdown and HTML reports to DIR")
    args = parser.parse_args(argv)

    report = run(args.target)
    print_report(report)
    if args.report:
        out = Path(args.report)
        out.mkdir(parents=True, exist_ok=True)
        stem = report.target.replace(".", "_")
        (out / f"{stem}.md").write_text(markdown_report(report), encoding="utf-8")
        (out / f"{stem}.html").write_text(html_report(report), encoding="utf-8")
        print(f"Reports written to {out}/{stem}.md and .html")


if __name__ == "__main__":
    main()
