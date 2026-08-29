"""DNS-aware SSRF target validation."""

import ipaddress
import socket
from urllib.parse import urlsplit


_BLOCKED_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)


def is_safe_target(url: str) -> tuple[bool, str]:
    """Return whether *url* resolves only to publicly routable IP addresses."""
    hostname = urlsplit(url).hostname
    if not hostname:
        return False, "could not resolve hostname"
    if hostname.lower() == "localhost":
        return False, "localhost is not an allowed scan target"

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, "could not resolve hostname"
    if not addresses:
        return False, "could not resolve hostname"

    for address in addresses:
        try:
            resolved_ip = ipaddress.ip_address(address[4][0])
        except ValueError:
            return False, "could not resolve hostname"

        comparison_ip = (
            resolved_ip.ipv4_mapped
            if isinstance(resolved_ip, ipaddress.IPv6Address) and resolved_ip.ipv4_mapped
            else resolved_ip
        )
        if any(comparison_ip in network for network in _BLOCKED_NETWORKS):
            return False, "target resolves to a private or local IP address"

    return True, ""
