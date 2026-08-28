"""Cross-Origin Resource Sharing (CORS) configuration checks."""

from typing import List

import requests

from .base import Finding, ModuleResult


_TEST_ORIGIN = "https://vuln-scanner-test-origin.example.com"
_REQUEST_HEADERS = {
    "User-Agent": "vuln-scanner-bot/1.0 (portfolio project)",
    "Origin": _TEST_ORIGIN,
}


def _finding(check_name: str, severity: str, passed: bool, detail: str) -> Finding:
    return Finding(
        check_name=check_name,
        severity=severity,
        passed=passed,
        detail=detail,
    )


def _score(findings: List[Finding]) -> str:
    if any(finding.severity == "high" and not finding.passed for finding in findings):
        return "D"
    if any(finding.severity == "info" and not finding.passed for finding in findings):
        return "B"
    return "A"


def _findings_for_response(headers: requests.structures.CaseInsensitiveDict) -> List[Finding]:
    """Evaluate the CORS response headers returned for one request."""
    allowed_origin = headers.get("Access-Control-Allow-Origin")
    allow_credentials = headers.get("Access-Control-Allow-Credentials", "").lower()

    if allowed_origin == "*" and allow_credentials == "true":
        return [
            _finding(
                "wildcard_origin_with_credentials",
                "high",
                False,
                "Access-Control-Allow-Origin is '*' while credentials are allowed.",
            )
        ]
    if allowed_origin == _TEST_ORIGIN:
        return [
            _finding(
                "reflected_origin",
                "high",
                False,
                "Access-Control-Allow-Origin reflects the injected Origin header.",
            )
        ]
    if allowed_origin == "*":
        return [
            _finding(
                "wildcard_origin",
                "info",
                False,
                "Access-Control-Allow-Origin is '*' without credential support.",
            )
        ]
    if allowed_origin is None and not allow_credentials:
        return [
            _finding(
                "cors_configuration",
                "info",
                True,
                "No CORS configuration detected.",
            )
        ]
    if allowed_origin is None:
        return [
            _finding(
                "cors_origin_restriction",
                "info",
                True,
                "Credentials are configured, but the injected Origin was not allowed.",
            )
        ]
    return [
        _finding(
            "cors_origin_restriction",
            "info",
            True,
            f"Access-Control-Allow-Origin is restricted to {allowed_origin}.",
        )
    ]


def _deduplicate(findings: List[Finding]) -> List[Finding]:
    """Preserve first-seen findings while removing identical results."""
    deduplicated: List[Finding] = []
    seen = set()
    for finding in findings:
        key = (
            finding.check_name,
            finding.severity,
            finding.passed,
            finding.detail,
        )
        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)
    return deduplicated


def check_cors(target_url: str) -> ModuleResult:
    """Check GET and preflight responses for unsafe CORS configuration."""
    try:
        get_response = requests.get(
            target_url, headers=_REQUEST_HEADERS, timeout=10
        )
        options_response = requests.options(
            target_url, headers=_REQUEST_HEADERS, timeout=10
        )
    except requests.RequestException as exc:
        return ModuleResult(
            module_name="cors",
            findings=[
                _finding("cors_connection", "high", False, f"Could not reach target: {exc}")
            ],
            score="F",
        )

    findings = _deduplicate(
        _findings_for_response(get_response.headers)
        + _findings_for_response(options_response.headers)
    )
    return ModuleResult(module_name="cors", findings=findings, score=_score(findings))
