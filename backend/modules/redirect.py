"""Shallow URL-parameter checks for open redirects."""

from typing import List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from .base import Finding, ModuleResult


_REDIRECT_PARAMETERS = {
    "url",
    "next",
    "redirect",
    "return",
    "dest",
    "destination",
    "continue",
    "redir",
}
_TEST_REDIRECT_URL = "https://vuln-scanner-redirect-test.example.com"
_TEST_REDIRECT_HOST = "vuln-scanner-redirect-test.example.com"


def _finding(check_name: str, severity: str, passed: bool, detail: str) -> Finding:
    return Finding(
        check_name=check_name,
        severity=severity,
        passed=passed,
        detail=detail,
    )


def _replace_query_value(target_url: str, index: int) -> str:
    parsed = urlsplit(target_url)
    query_parameters = parse_qsl(parsed.query, keep_blank_values=True)
    query_parameters[index] = (query_parameters[index][0], _TEST_REDIRECT_URL)
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query_parameters),
            parsed.fragment,
        )
    )


def _points_to_test_domain(location: str) -> bool:
    return urlsplit(location).hostname == _TEST_REDIRECT_HOST


def check_open_redirect(target_url: str) -> ModuleResult:
    """Probe common redirect parameters without following the redirect response."""
    parsed = urlsplit(target_url)
    query_parameters = parse_qsl(parsed.query, keep_blank_values=True)
    redirect_parameters = [
        (index, name)
        for index, (name, _) in enumerate(query_parameters)
        if name.lower() in _REDIRECT_PARAMETERS
    ]

    if not redirect_parameters:
        return ModuleResult(
            module_name="redirect",
            findings=[
                _finding(
                    "redirect_parameters",
                    "info",
                    True,
                    "No obvious redirect parameters found in URL; this is a shallow "
                    "URL-parameter check, not a full crawl.",
                )
            ],
            score="A",
        )

    findings: List[Finding] = []
    try:
        for index, parameter_name in redirect_parameters:
            probe_url = _replace_query_value(target_url, index)
            response = requests.get(probe_url, allow_redirects=False, timeout=10)
            location = response.headers.get("Location")
            if 300 <= response.status_code < 400 and location and _points_to_test_domain(location):
                findings.append(
                    _finding(
                        "open_redirect",
                        "high",
                        False,
                        f"Parameter '{parameter_name}' redirects to the injected test domain.",
                    )
                )
    except requests.RequestException as exc:
        return ModuleResult(
            module_name="redirect",
            findings=[
                _finding(
                    "redirect_connection",
                    "high",
                    False,
                    f"Could not reach target: {exc}",
                )
            ],
            score="F",
        )

    if not findings:
        findings.append(
            _finding(
                "open_redirect",
                "info",
                True,
                "Redirect parameters did not redirect to the injected test domain.",
            )
        )
    return ModuleResult(
        module_name="redirect",
        findings=findings,
        score="D" if any(finding.severity == "high" for finding in findings) else "A",
    )
