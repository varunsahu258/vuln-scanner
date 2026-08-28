"""Passive certificate-transparency and dangling-CNAME reconnaissance."""

from typing import Iterable, List
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
import requests

from .base import Finding, ModuleResult


_CNAME_LIMIT = 15
_DISPLAY_LIMIT = 20
_VULNERABLE_CNAME_SUFFIXES = (".github.io", ".herokuapp.com", ".s3.amazonaws.com")


def _finding(check_name: str, severity: str, passed: bool, detail: str) -> Finding:
    return Finding(
        check_name=check_name,
        severity=severity,
        passed=passed,
        detail=detail,
    )


def _base_domain(target_url: str) -> str | None:
    normalized_url = target_url if "://" in target_url else f"https://{target_url}"
    hostname = urlsplit(normalized_url).hostname
    if not hostname:
        return None
    labels = hostname.lower().rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname


def _subdomains(certificates: Iterable[dict], domain: str) -> List[str]:
    discovered = set()
    for certificate in certificates:
        for name in certificate.get("name_value", "").splitlines():
            normalized_name = name.lower().strip().lstrip("*.").rstrip(".")
            if normalized_name.endswith(f".{domain}"):
                discovered.add(normalized_name)
    return sorted(discovered)


def _cname_target(subdomain: str) -> str | None:
    try:
        answer = dns.resolver.resolve(subdomain, "CNAME")
    except dns.exception.DNSException:
        return None
    return str(answer[0].target).rstrip(".").lower()


def _target_resolves(target: str) -> bool:
    try:
        dns.resolver.resolve(target, "A")
    except dns.resolver.NXDOMAIN:
        return False
    except dns.exception.DNSException:
        return True
    return True


def _is_dangling_cname(subdomain: str) -> str | None:
    target = _cname_target(subdomain)
    if target is None:
        return None
    if target.endswith(_VULNERABLE_CNAME_SUFFIXES):
        return f"CNAME points to takeover-prone service {target}."
    if not _target_resolves(target):
        return f"CNAME target {target} does not resolve."
    return None


def check_subdomain_recon(target_url: str) -> ModuleResult:
    """Use crt.sh and DNS-only checks to identify possible dangling CNAMEs."""
    domain = _base_domain(target_url)
    if not domain:
        return ModuleResult(
            module_name="recon",
            findings=[
                _finding(
                    "recon_skipped",
                    "info",
                    True,
                    "Recon skipped - certificate transparency lookup unavailable: invalid domain.",
                )
            ],
            score="B",
        )

    try:
        response = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15
        )
        if response.status_code != 200:
            raise requests.RequestException(f"crt.sh returned HTTP {response.status_code}")
        certificates = response.json()
    except (requests.RequestException, ValueError) as exc:
        return ModuleResult(
            module_name="recon",
            findings=[
                _finding(
                    "recon_skipped",
                    "info",
                    True,
                    "Recon skipped - certificate transparency lookup unavailable."
                    f" ({exc})",
                )
            ],
            score="B",
        )

    subdomains = _subdomains(certificates, domain)
    display_names = ", ".join(subdomains[:_DISPLAY_LIMIT]) or "none"
    findings: List[Finding] = [
        _finding(
            "certificate_transparency_subdomains",
            "info",
            True,
            f"Found {len(subdomains)} unique subdomains: {display_names}.",
        )
    ]

    for subdomain in subdomains[:_CNAME_LIMIT]:
        dangling_detail = _is_dangling_cname(subdomain)
        if dangling_detail:
            findings.append(
                _finding(
                    "dangling_cname",
                    "high",
                    False,
                    f"Possible dangling CNAME / subdomain takeover risk for {subdomain}: "
                    f"{dangling_detail}",
                )
            )

    return ModuleResult(
        module_name="recon",
        findings=findings,
        score="D" if any(finding.severity == "high" for finding in findings) else "A",
    )
