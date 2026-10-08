"""Unit tests for the header, cookie and WordPress checks (no network)."""

from requests.structures import CaseInsensitiveDict

import sitecheck


def statuses(report):
    return {f.check: f.status for f in report.findings}


def test_hardened_headers_pass():
    report = sitecheck.Report("example.com")
    sitecheck.check_headers(CaseInsensitiveDict({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "Server": "nginx",
    }), report)
    assert set(statuses(report).values()) == {"pass"}
    assert report.score == 100 and report.grade == "A"


def test_bare_headers_fail_and_lower_the_grade():
    report = sitecheck.Report("example.com")
    sitecheck.check_headers(CaseInsensitiveDict({"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"}), report)
    result = statuses(report)
    assert result["Strict-Transport-Security"] == "fail"
    assert result["Clickjacking protection"] == "fail"
    assert result["Version disclosure"] == "warn"
    assert report.grade in ("C", "D")


def test_short_hsts_and_unsafe_inline_are_warnings():
    report = sitecheck.Report("example.com")
    sitecheck.check_headers(CaseInsensitiveDict({
        "Strict-Transport-Security": "max-age=300",
        "Content-Security-Policy": "script-src 'self' 'unsafe-inline'",
    }), report)
    result = statuses(report)
    assert result["Strict-Transport-Security"] == "warn"
    assert result["Content-Security-Policy"] == "warn"


def test_cookie_flags():
    report = sitecheck.Report("example.com")
    sitecheck.check_cookies(["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
                             "tracker=1; Path=/"], report)
    finding = report.findings[0]
    assert finding.status == "warn"
    assert "tracker" in finding.detail and "session" not in finding.detail


def test_wordpress_generator_tag():
    report = sitecheck.Report("example.com")
    sitecheck.check_wordpress('<meta name="generator" content="WordPress 6.4.2" />', report)
    assert report.findings[0].status == "warn"
    assert "6.4.2" in report.findings[0].detail


def test_reports_render():
    report = sitecheck.Report("example.com", final_url="https://example.com/")
    sitecheck.check_headers(CaseInsensitiveDict({}), report)
    assert "Recommended fixes" in sitecheck.markdown_report(report)
    page = sitecheck.html_report(report)
    assert page.startswith("<!doctype html>") and "example.com" in page


def test_unsafe_inline_in_style_src_only_is_fine():
    report = sitecheck.Report("example.com")
    sitecheck.check_headers(CaseInsensitiveDict({
        "Content-Security-Policy": "default-src 'none'; script-src github.githubassets.com; style-src 'unsafe-inline'",
    }), report)
    assert statuses(report)["Content-Security-Policy"] == "pass"


def test_missing_httponly_alone_is_low_severity():
    report = sitecheck.Report("example.com")
    sitecheck.check_cookies(["_octo=1; path=/; secure; SameSite=Lax"], report)
    assert report.findings[0].severity == "low"
