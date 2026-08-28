from datetime import datetime, timedelta, timezone
import secrets

import jwt

from backend.modules.jwt_check import check_jwt


def _claims(**overrides):
    now = datetime.now(timezone.utc)
    claims = {"sub": "scanner-test", "iat": now, "exp": now + timedelta(hours=1)}
    claims.update(overrides)
    return claims


def test_weak_secret_token_receives_failure_grade():
    token = jwt.encode(_claims(), "secret", algorithm="HS256")

    result = check_jwt(token)

    assert result.score == "F"
    assert any(
        finding.check_name == "weak_signing_secret" and not finding.passed
        for finding in result.findings
    )


def test_none_algorithm_token_receives_failure_grade():
    token = jwt.encode(_claims(), key="", algorithm="none")

    result = check_jwt(token)

    assert result.score == "F"
    assert any(
        finding.check_name == "algorithm_none" and not finding.passed
        for finding in result.findings
    )


def test_missing_exp_claim_is_reported():
    token = jwt.encode({"sub": "scanner-test", "iat": datetime.now(timezone.utc)}, "strong", algorithm="HS256")

    result = check_jwt(token)

    assert any(
        finding.check_name == "expiration" and finding.severity == "high"
        for finding in result.findings
    )


def test_well_formed_strong_token_receives_grade_a():
    token = jwt.encode(_claims(), secrets.token_urlsafe(48), algorithm="HS512")

    result = check_jwt(token)

    assert result.score == "A"
    assert all(finding.passed for finding in result.findings)


def test_garbage_token_returns_graceful_failure():
    result = check_jwt("not-a-jwt")

    assert result.score == "F"
    assert len(result.findings) == 1
    assert result.findings[0].check_name == "jwt_parse"
