"""TLS/SSL configuration checks for HTTPS targets."""

import ipaddress
import socket
import ssl
import tempfile
import time
from typing import Any, Dict, List
from urllib.parse import urlparse

from .base import Finding, ModuleResult


_SOCKET_TIMEOUT_SECONDS = 10
_EXPIRY_WARNING_SECONDS = 30 * 24 * 60 * 60


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


def _decode_certificate(certificate_der: bytes) -> Dict[str, Any]:
    """Decode a DER certificate using only Python's standard-library TLS support."""
    certificate_pem = ssl.DER_cert_to_PEM_cert(certificate_der)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem") as certificate_file:
        certificate_file.write(certificate_pem)
        certificate_file.flush()
        return ssl._ssl._test_decode_cert(certificate_file.name)


def _hostname_matches(certificate: Dict[str, Any], hostname: str) -> bool:
    """Match a hostname against certificate SANs, falling back to its CN."""
    try:
        requested_ip = ipaddress.ip_address(hostname)
    except ValueError:
        requested_ip = None

    subject_alt_names = certificate.get("subjectAltName", ())
    if requested_ip is not None:
        return any(
            name_type == "IP Address" and value == str(requested_ip)
            for name_type, value in subject_alt_names
        )

    dns_names = [
        value for name_type, value in subject_alt_names if name_type == "DNS"
    ]
    if not dns_names:
        dns_names = [
            value
            for relative_distinguished_name in certificate.get("subject", ())
            for name_type, value in relative_distinguished_name
            if name_type == "commonName"
        ]

    for dns_name in dns_names:
        try:
            if ssl._dnsname_match(dns_name, hostname):
                return True
        except ssl.CertificateError:
            continue
    return False


def _evaluate_certificate(
    certificate: Dict[str, Any], hostname: str, protocol: str, now: float | None = None
) -> List[Finding]:
    """Evaluate decoded certificate and negotiated protocol data.

    Keeping this pure makes the scanner's security and grading rules easy to test
    without opening a network connection.
    """
    current_time = time.time() if now is None else now
    expires_at = ssl.cert_time_to_seconds(certificate["notAfter"])
    remaining_seconds = expires_at - current_time
    findings: List[Finding] = []

    if remaining_seconds < 0:
        findings.append(
            _finding(
                "certificate_expiry",
                "high",
                False,
                f"Certificate expired on {certificate['notAfter']}.",
            )
        )
    elif remaining_seconds <= _EXPIRY_WARNING_SECONDS:
        findings.append(
            _finding(
                "certificate_expiry",
                "medium",
                False,
                f"Certificate expires within 30 days ({certificate['notAfter']}).",
            )
        )
    else:
        findings.append(
            _finding(
                "certificate_expiry",
                "info",
                True,
                f"Certificate is valid until {certificate['notAfter']}.",
            )
        )

    if not _hostname_matches(certificate, hostname):
        findings.append(
            _finding(
                "hostname_match",
                "high",
                False,
                f"Certificate does not match hostname {hostname}.",
            )
        )
    else:
        findings.append(
            _finding("hostname_match", "info", True, "Certificate matches the hostname.")
        )

    if protocol in {"TLSv1", "TLSv1.1"}:
        findings.append(
            _finding(
                "protocol_version",
                "high",
                False,
                f"Negotiated deprecated protocol {protocol}.",
            )
        )
    else:
        findings.append(
            _finding(
                "protocol_version",
                "info",
                True,
                f"Negotiated protocol {protocol}.",
            )
        )

    if certificate.get("issuer") == certificate.get("subject"):
        findings.append(
            _finding(
                "self_signed",
                "high",
                False,
                "Certificate issuer and subject are identical (self-signed).",
            )
        )
    else:
        findings.append(
            _finding("self_signed", "info", True, "Certificate is not self-signed.")
        )

    return findings


def _failure_result(detail: str) -> ModuleResult:
    return ModuleResult(
        module_name="tls",
        findings=[_finding("tls_connection", "high", False, detail)],
        score="F",
    )


def check_tls(target_url: str) -> ModuleResult:
    """Inspect the TLS certificate and negotiated protocol for *target_url*."""
    normalized_url = target_url if "://" in target_url else f"https://{target_url}"

    try:
        parsed_url = urlparse(normalized_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
    except ValueError as exc:
        return _failure_result(f"Invalid target URL: {exc}")

    if parsed_url.scheme.lower() == "http":
        return ModuleResult(
            module_name="tls",
            findings=[
                _finding(
                    "https_enforced", "high", False, "Site does not use HTTPS"
                )
            ],
            score="D",
        )

    if not hostname:
        return _failure_result("Invalid target URL: hostname is missing.")

    try:
        context = ssl.create_default_context()
        # Validation is performed explicitly below so certificates with security
        # issues can be reported as findings rather than aborting the handshake.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1

        with socket.create_connection(
            (hostname, port), timeout=_SOCKET_TIMEOUT_SECONDS
        ) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                certificate_der = tls_socket.getpeercert(binary_form=True)
                if not certificate_der:
                    raise ssl.SSLError("The server did not provide a certificate.")
                certificate = _decode_certificate(certificate_der)
                findings = _evaluate_certificate(
                    certificate, hostname, tls_socket.version() or "unknown"
                )
    except (
        socket.timeout,
        ssl.SSLError,
        socket.gaierror,
        ConnectionRefusedError,
        OSError,
        ValueError,
    ) as exc:
        return _failure_result(f"Could not establish TLS connection: {exc}")

    return ModuleResult(module_name="tls", findings=findings, score=_score(findings))
