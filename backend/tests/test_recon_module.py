from unittest.mock import Mock, patch

import pytest
import requests
import responses

dns = pytest.importorskip("dns")
import dns.resolver

from backend.modules.recon import check_subdomain_recon


def _cname_answer(target):
    record = Mock()
    record.target = target
    return [record]


@responses.activate
@patch("backend.modules.recon.dns.resolver.resolve")
def test_dangling_cname_is_reported(mock_resolve):
    responses.add(
        responses.GET,
        "https://crt.sh/?q=%25.example.com&output=json",
        json=[{"name_value": "safe.example.com\ndangling.example.com"}],
        status=200,
    )
    def resolve(name, record_type):
        if name == "safe.example.com" and record_type == "CNAME":
            return _cname_answer("safe.provider.example.")
        if name == "safe.provider.example" and record_type == "A":
            return [Mock()]
        if name == "dangling.example.com" and record_type == "CNAME":
            return _cname_answer("missing.example.")
        if name == "missing.example" and record_type == "A":
            raise dns.resolver.NXDOMAIN()
        raise AssertionError(f"Unexpected DNS lookup: {name} {record_type}")

    mock_resolve.side_effect = resolve

    result = check_subdomain_recon("https://www.example.com")

    assert result.score == "D"
    assert any(
        finding.check_name == "dangling_cname" and "dangling.example.com" in finding.detail
        for finding in result.findings
    )


@responses.activate
@patch("backend.modules.recon.dns.resolver.resolve")
def test_subdomains_without_dangling_cnames_receive_grade_a(mock_resolve):
    responses.add(
        responses.GET,
        "https://crt.sh/?q=%25.example.com&output=json",
        json=[{"name_value": "safe.example.com"}],
        status=200,
    )
    mock_resolve.side_effect = [_cname_answer("safe.provider.example."), [Mock()]]

    result = check_subdomain_recon("https://www.example.com")

    assert result.score == "A"
    assert all(finding.passed for finding in result.findings)


@responses.activate
def test_unavailable_crt_sh_returns_grade_b():
    responses.add(
        responses.GET,
        "https://crt.sh/?q=%25.example.com&output=json",
        body=requests.ConnectionError("crt.sh unavailable"),
    )

    result = check_subdomain_recon("https://www.example.com")

    assert result.score == "B"
    assert result.findings[0].check_name == "recon_skipped"
