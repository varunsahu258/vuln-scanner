import socket
from unittest.mock import patch

import pytest

from backend.security.ssrf_guard import is_safe_target


def _address(ip_address):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip_address, 0))]


@patch("backend.security.ssrf_guard.socket.getaddrinfo", return_value=_address("8.8.8.8"))
def test_public_ip_is_allowed(mock_getaddrinfo):
    assert is_safe_target("https://public.example") == (True, "")


@pytest.mark.parametrize(
    "private_ip", ["10.1.2.3", "172.16.1.1", "192.168.1.1", "127.0.0.1", "169.254.1.1"]
)
def test_private_ipv4_ranges_are_rejected(private_ip):
    with patch(
        "backend.security.ssrf_guard.socket.getaddrinfo", return_value=_address(private_ip)
    ):
        is_safe, reason = is_safe_target("https://private.example")

    assert not is_safe
    assert "private or local" in reason


def test_localhost_is_rejected_without_dns_lookup():
    with patch("backend.security.ssrf_guard.socket.getaddrinfo") as getaddrinfo:
        is_safe, reason = is_safe_target("https://localhost")

    assert not is_safe
    assert "localhost" in reason
    getaddrinfo.assert_not_called()


def test_dns_failure_is_rejected_gracefully():
    with patch(
        "backend.security.ssrf_guard.socket.getaddrinfo", side_effect=socket.gaierror()
    ):
        assert is_safe_target("https://unresolvable.example") == (
            False,
            "could not resolve hostname",
        )
