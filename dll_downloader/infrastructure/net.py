"""Shared network-address helpers for SSRF protection.

Centralises the private/loopback/reserved address checks used by the HTTP
transport, the VirusTotal client, and configuration validation so the SSRF
policy cannot drift between call sites.
"""

import ipaddress
import socket
from urllib.parse import urlparse

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def normalize_ip(addr: IpAddress) -> IpAddress:
    """Convert IPv4-mapped IPv6 addresses to their IPv4 equivalent.

    ``::ffff:127.0.0.1`` is NOT private under ``IPv6Address.is_private``,
    but its embedded IPv4 address IS private.  Normalise before checking.
    """
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def is_private_address(addr: IpAddress) -> bool:
    """Return True for private, loopback, link-local, reserved, or multicast IPs."""
    normalized = normalize_ip(addr)
    return (
        normalized.is_private
        or normalized.is_loopback
        or normalized.is_link_local
        or normalized.is_reserved
        or normalized.is_multicast
    )


def host_port_netloc(hostname: str, port: int | None) -> str:
    """Build a netloc, bracketing IPv6 literals and appending an optional port."""
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port is None:
        return host
    return f"{host}:{port}"


def strip_url_credentials(location: str) -> str:
    """Return *location* with any embedded userinfo removed.

    Raises :class:`ValueError` if the URL carries an invalid port; callers
    translate this into their own transport-specific error type.
    """
    parsed = urlparse(location)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Redirect URL has invalid port: {location}") from exc
    if not parsed.username and not parsed.password:
        return location
    hostname = parsed.hostname or ""
    return parsed._replace(netloc=host_port_netloc(hostname, port)).geturl()


def hostname_resolves_to_private_ip(hostname: str) -> bool:
    """Return True when *hostname* is, or resolves to, a non-public IP.

    Loopback addresses are included so SSRF protection is consistent with
    configuration-time validation, which also blocks loopback URLs.

    Returns True on DNS resolution failure (fail-closed) to prevent
    DNS-rebinding attacks where an attacker returns NXDOMAIN during the SSRF
    check but resolves to a private IP during the actual request.
    """
    try:
        return is_private_address(ipaddress.ip_address(hostname))
    except ValueError:
        pass

    try:
        resolved = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except (socket.gaierror, socket.herror, OSError):
        return True

    for _family, _type, _proto, _canonname, sockaddr in resolved:
        try:
            resolved_addr = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if is_private_address(resolved_addr):
            return True
    return False
