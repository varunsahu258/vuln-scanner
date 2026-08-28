import requests
import responses

from backend.modules.headers import check_headers


TARGET_URL = "https://example.test/"


@responses.activate
def test_all_correctly_configured_headers_receive_grade_a():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        },
        status=200,
    )

    result = check_headers(TARGET_URL)

    assert result.score == "A"
    assert all(finding.passed for finding in result.findings)


@responses.activate
def test_all_missing_headers_receive_grade_d():
    responses.add(responses.GET, TARGET_URL, status=200)

    result = check_headers(TARGET_URL)

    assert result.score == "D"
    assert len(result.findings) == 6
    assert sum(finding.severity == "high" for finding in result.findings) == 2


@responses.activate
def test_csp_unsafe_inline_is_a_medium_finding():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'"},
        status=200,
    )

    result = check_headers(TARGET_URL)

    csp_finding = next(
        finding for finding in result.findings if finding.check_name == "Content-Security-Policy"
    )
    assert csp_finding.severity == "medium"
    assert not csp_finding.passed


@responses.activate
def test_unreachable_url_returns_failure_grade_without_raising():
    responses.add(responses.GET, TARGET_URL, body=requests.ConnectionError("DNS failure"))

    result = check_headers(TARGET_URL)

    assert result.score == "F"
    assert len(result.findings) == 1
    assert not result.findings[0].passed
    assert "Could not reach target" in result.findings[0].detail
