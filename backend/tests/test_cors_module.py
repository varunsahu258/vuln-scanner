import requests
import responses

from backend.modules.cors import check_cors


TARGET_URL = "https://example.test/"


def _mock_get_and_options(headers):
    responses.add(responses.GET, TARGET_URL, headers=headers, status=200)
    responses.add(responses.OPTIONS, TARGET_URL, headers=headers, status=204)


@responses.activate
def test_reflected_origin_creates_a_high_finding():
    _mock_get_and_options(
        {"Access-Control-Allow-Origin": "https://vuln-scanner-test-origin.example.com"}
    )

    result = check_cors(TARGET_URL)

    assert result.score == "D"
    assert any(
        finding.check_name == "reflected_origin" and finding.severity == "high"
        for finding in result.findings
    )


@responses.activate
def test_wildcard_origin_with_credentials_creates_a_high_finding():
    _mock_get_and_options(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

    result = check_cors(TARGET_URL)

    assert result.score == "D"
    assert any(
        finding.check_name == "wildcard_origin_with_credentials"
        and finding.severity == "high"
        for finding in result.findings
    )


@responses.activate
def test_allowlist_that_ignores_test_origin_receives_grade_a():
    _mock_get_and_options(
        {"Access-Control-Allow-Origin": "https://known-application.example.com"}
    )

    result = check_cors(TARGET_URL)

    assert result.score == "A"
    assert all(finding.passed for finding in result.findings)


@responses.activate
def test_no_cors_headers_receives_grade_a():
    _mock_get_and_options({})

    result = check_cors(TARGET_URL)

    assert result.score == "A"
    assert result.findings[0].detail == "No CORS configuration detected."


@responses.activate
def test_unreachable_target_returns_grade_f():
    responses.add(responses.GET, TARGET_URL, body=requests.ConnectionError("DNS failure"))

    result = check_cors(TARGET_URL)

    assert result.score == "F"
    assert len(result.findings) == 1
    assert not result.findings[0].passed
