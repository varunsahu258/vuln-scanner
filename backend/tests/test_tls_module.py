import time

import pytest

from backend.modules.tls import _evaluate_certificate, _score, check_tls


def test_grading_logic_reports_a_medium_grade_without_network_access():
    now = time.time()
    certificate = {
        "notAfter": time.strftime(
            "%b %d %H:%M:%S %Y GMT", time.gmtime(now + (10 * 24 * 60 * 60))
        ),
        "subject": (("commonName", "example.test"),),
        "issuer": (("commonName", "Example Test CA"),),
        "subjectAltName": (("DNS", "example.test"),),
    }

    findings = _evaluate_certificate(certificate, "example.test", "TLSv1.2", now)

    assert _score(findings) == "B"


@pytest.mark.integration
def test_expired_badssl_certificate_is_reported():
    result = check_tls("https://expired.badssl.com")

    expiry = next(finding for finding in result.findings if finding.check_name == "certificate_expiry")
    assert expiry.severity == "high"
    assert not expiry.passed


@pytest.mark.integration
def test_self_signed_badssl_certificate_is_reported():
    result = check_tls("https://self-signed.badssl.com")

    self_signed = next(finding for finding in result.findings if finding.check_name == "self_signed")
    assert self_signed.severity == "high"
    assert not self_signed.passed


@pytest.mark.integration
def test_tls_v1_0_badssl_protocol_is_reported():
    result = check_tls("https://tls-v1-0.badssl.com")

    protocol = next(finding for finding in result.findings if finding.check_name == "protocol_version")
    assert protocol.severity == "high"
    assert not protocol.passed
