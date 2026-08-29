"""Offline vulnerability checks for raw JSON Web Tokens."""

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List

import jwt

from .base import Finding, ModuleResult


_WEAK_SECRETS_PATH = Path(__file__).parent / "wordlists" / "weak_jwt_secrets.txt"
_HMAC_ALGORITHMS = {"HS256", "HS384", "HS512"}
_SENSITIVE_KEY_PATTERN = re.compile(r"(?:password|secret|ssn|credit_card)", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b")
_MAX_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60


def _finding(check_name: str, severity: str, passed: bool, detail: str) -> Finding:
    return Finding(
        check_name=check_name,
        severity=severity,
        passed=passed,
        detail=detail,
    )


def _score(findings: List[Finding]) -> str:
    if any(
        not finding.passed
        and finding.check_name in {"algorithm_none", "weak_signing_secret"}
        for finding in findings
    ):
        return "F"
    if any(finding.severity == "high" and not finding.passed for finding in findings):
        return "D"
    if any(
        finding.severity in {"low", "medium"} and not finding.passed
        for finding in findings
    ):
        return "B"
    return "A"


def _contains_sensitive_data(value: Any) -> bool:
    """Return whether JSON-like payload data contains sensitive names or emails."""
    if isinstance(value, dict):
        return any(
            _SENSITIVE_KEY_PATTERN.search(str(key))
            or _contains_sensitive_data(nested_value)
            for key, nested_value in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive_data(item) for item in value)
    return isinstance(value, str) and bool(_EMAIL_PATTERN.search(value))


def _weak_secrets() -> Iterable[str]:
    with _WEAK_SECRETS_PATH.open(encoding="utf-8") as wordlist:
        for line in wordlist:
            secret = line.strip()
            if secret:
                yield secret


def _uses_weak_secret(token: str, algorithm: str) -> bool:
    for secret in _weak_secrets():
        try:
            jwt.decode(
                token,
                secret,
                algorithms=[algorithm],
                options={
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except jwt.PyJWTError:
            continue
        return True
    return False


def _timestamp(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def check_jwt(token: str) -> ModuleResult:
    """Analyze a JWT's structure and common signing-secret weaknesses offline."""
    try:
        header: Dict[str, Any] = jwt.get_unverified_header(token)
        payload: Dict[str, Any] = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError as exc:
        return ModuleResult(
            module_name="jwt",
            findings=[
                _finding("jwt_parse", "high", False, f"Could not parse JWT: {exc}")
            ],
            score="F",
        )

    algorithm = header.get("alg")
    findings: List[Finding] = [
        _finding("algorithm", "info", True, f"Token algorithm is {algorithm!r}.")
    ]

    if algorithm == "none":
        findings.append(
            _finding(
                "algorithm_none",
                "high",
                False,
                "Token uses alg=none. This describes the token's structure, not "
                "whether a server accepts unsigned tokens; endpoint testing is out of scope.",
            )
        )

    expires_at = _timestamp(payload.get("exp"))
    issued_at = _timestamp(payload.get("iat"))
    if expires_at is None:
        findings.append(
            _finding("expiration", "high", False, "Token is missing a valid exp claim.")
        )
    elif issued_at is None or expires_at - issued_at > _MAX_TOKEN_LIFETIME_SECONDS:
        findings.append(
            _finding(
                "expiration",
                "medium",
                False,
                "Token expiry exceeds 24 hours after iat or has no iat bound.",
            )
        )
    else:
        expiry_time = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()
        findings.append(
            _finding("expiration", "info", True, f"Token expires at {expiry_time}.")
        )

    if issued_at is None:
        findings.append(
            _finding("issued_at", "low", False, "Token is missing a valid iat claim.")
        )
    else:
        findings.append(_finding("issued_at", "info", True, "Token includes an iat claim."))

    if _contains_sensitive_data(payload):
        findings.append(
            _finding(
                "sensitive_payload_data",
                "medium",
                False,
                "JWT payloads are base64-encoded, not encrypted, and are readable by "
                "anyone who has the token.",
            )
        )
    else:
        findings.append(
            _finding("sensitive_payload_data", "info", True, "No sensitive payload patterns found.")
        )

    if algorithm in _HMAC_ALGORITHMS and _uses_weak_secret(token, algorithm):
        findings.append(
            _finding(
                "weak_signing_secret",
                "high",
                False,
                "Token can be forged using a common weak secret.",
            )
        )
    elif algorithm in _HMAC_ALGORITHMS:
        findings.append(
            _finding(
                "weak_signing_secret",
                "info",
                True,
                "Token signature did not match the common-secret wordlist.",
            )
        )

    return ModuleResult(module_name="jwt", findings=findings, score=_score(findings))
