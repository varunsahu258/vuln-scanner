"""HTTP security-header checks."""

import re
from typing import List

import requests

from .base import Finding, ModuleResult


_REQUEST_HEADERS = {"User-Agent": "vuln-scanner-bot/1.0 (portfolio project)"}
_HSTS_MIN_MAX_AGE = 31_536_000


def _finding(check_name: str, severity: str, passed: bool, detail: str) -> Finding:
    return Finding(
        check_name=check_name,
        severity=severity,
        passed=passed,
        detail=detail,
    )


def _score(findings: List[Finding]) -> str:
    high_count = sum(
        finding.severity == "high" and not finding.passed for finding in findings
    )
    has_medium = any(
        finding.severity == "medium" and not finding.passed for finding in findings
    )

    if high_count >= 2:
        return "D"
    if high_count == 1:
        return "C"
    if has_medium:
        return "B"
    return "A"


def _hsts_max_age(value: str) -> int | None:
    """Return an HSTS max-age directive, or None when it is absent/invalid."""
    match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


def check_headers(target_url: str) -> ModuleResult:
    """Fetch *target_url* and evaluate its HTTP security headers.

    Network and request errors are converted into an ``F`` result so callers never
    need to handle exceptions from this scanner.
    """
    try:
        response = requests.get(
            target_url,
            timeout=10,
            allow_redirects=True,
            headers=_REQUEST_HEADERS,
        )
    except requests.RequestException as exc:
        return ModuleResult(
            module_name="headers",
            findings=[
                _finding(
                    "Target reachable",
                    "high",
                    False,
                    f"Could not reach target: {exc}",
                )
            ],
            score="F",
        )

    headers = response.headers
    findings: List[Finding] = []

    csp = headers.get("Content-Security-Policy")
    if not csp:
        findings.append(
            _finding("Content-Security-Policy", "high", False, "Header is missing.")
        )
    elif "unsafe-inline" in csp.lower() or "unsafe-eval" in csp.lower():
        findings.append(
            _finding(
                "Content-Security-Policy",
                "medium",
                False,
                "Policy contains unsafe-inline or unsafe-eval.",
            )
        )
    else:
        findings.append(
            _finding("Content-Security-Policy", "info", True, "Header is configured.")
        )

    hsts = headers.get("Strict-Transport-Security")
    hsts_max_age = _hsts_max_age(hsts) if hsts else None
    if not hsts:
        findings.append(
            _finding("Strict-Transport-Security", "high", False, "Header is missing.")
        )
    elif hsts_max_age is None or hsts_max_age < _HSTS_MIN_MAX_AGE:
        findings.append(
            _finding(
                "Strict-Transport-Security",
                "medium",
                False,
                "max-age is missing, invalid, or less than 31536000.",
            )
        )
    else:
        findings.append(
            _finding(
                "Strict-Transport-Security",
                "info",
                True,
                f"Header is configured with max-age={hsts_max_age}.",
            )
        )

    x_frame_options = headers.get("X-Frame-Options")
    if not x_frame_options:
        findings.append(
            _finding("X-Frame-Options", "medium", False, "Header is missing.")
        )
    else:
        findings.append(
            _finding(
                "X-Frame-Options",
                "info",
                True,
                f"Header is configured as {x_frame_options}.",
            )
        )

    content_type_options = headers.get("X-Content-Type-Options")
    if not content_type_options or content_type_options.lower().strip() != "nosniff":
        findings.append(
            _finding(
                "X-Content-Type-Options",
                "medium",
                False,
                "Header is missing or is not set to nosniff.",
            )
        )
    else:
        findings.append(
            _finding(
                "X-Content-Type-Options",
                "info",
                True,
                "Header is configured as nosniff.",
            )
        )

    referrer_policy = headers.get("Referrer-Policy")
    if not referrer_policy:
        findings.append(
            _finding("Referrer-Policy", "low", False, "Header is missing.")
        )
    elif referrer_policy.lower().strip() == "unsafe-url":
        findings.append(
            _finding("Referrer-Policy", "medium", False, "Header is set to unsafe-url.")
        )
    else:
        findings.append(
            _finding(
                "Referrer-Policy",
                "info",
                True,
                f"Header is configured as {referrer_policy}.",
            )
        )

    permissions_policy = headers.get("Permissions-Policy")
    if not permissions_policy:
        findings.append(
            _finding(
                "Permissions-Policy",
                "info",
                False,
                "Header is missing; it is not universally adopted yet.",
            )
        )
    else:
        findings.append(_finding("Permissions-Policy", "info", True, "Header is configured."))

    return ModuleResult(module_name="headers", findings=findings, score=_score(findings))
