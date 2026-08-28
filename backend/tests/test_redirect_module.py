import requests
import responses

from backend.modules.redirect import check_open_redirect


@responses.activate
def test_vulnerable_redirect_parameter_is_reported():
    target_url = "https://example.test/login?next=/home"
    responses.add(
        responses.GET,
        "https://example.test/login?next=https%3A%2F%2Fvuln-scanner-redirect-test.example.com",
        headers={"Location": "https://vuln-scanner-redirect-test.example.com/"},
        status=302,
    )

    result = check_open_redirect(target_url)

    assert result.score == "D"
    assert result.findings[0].severity == "high"


@responses.activate
def test_safe_redirect_parameter_receives_grade_a():
    target_url = "https://example.test/login?redirect=/home"
    responses.add(
        responses.GET,
        "https://example.test/login?redirect=https%3A%2F%2Fvuln-scanner-redirect-test.example.com",
        headers={"Location": "/login"},
        status=302,
    )

    result = check_open_redirect(target_url)

    assert result.score == "A"
    assert result.findings[0].passed


def test_url_without_redirect_parameters_receives_info_finding():
    result = check_open_redirect("https://example.test/search?q=widgets")

    assert result.score == "A"
    assert result.findings[0].severity == "info"
    assert result.findings[0].passed


@responses.activate
def test_unreachable_target_returns_grade_f():
    target_url = "https://example.test/login?next=/home"
    responses.add(
        responses.GET,
        "https://example.test/login?next=https%3A%2F%2Fvuln-scanner-redirect-test.example.com",
        body=requests.ConnectionError("connection failed"),
    )

    result = check_open_redirect(target_url)

    assert result.score == "F"
    assert len(result.findings) == 1
