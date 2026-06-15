"""Tests for the shared SSRF network-address helpers."""

import ipaddress
import socket

import pytest

from dll_downloader.infrastructure.net import (
    hostname_resolves_to_private_ip,
    is_private_address,
    normalize_ip,
    strip_url_credentials,
)

_AddrInfoList = list[tuple[object, object, object, object, list[object]]]


@pytest.mark.unit
def test_normalize_ip_unwraps_ipv4_mapped_ipv6() -> None:
    mapped = ipaddress.IPv6Address("::ffff:127.0.0.1")

    normalized = normalize_ip(mapped)

    assert normalized == ipaddress.IPv4Address("127.0.0.1")
    # And the helper therefore treats the mapped form as private/loopback.
    assert is_private_address(mapped) is True


@pytest.mark.unit
def test_normalize_ip_leaves_plain_addresses_untouched() -> None:
    addr = ipaddress.IPv6Address("2606:4700:4700::1111")

    assert normalize_ip(addr) == addr


@pytest.mark.unit
def test_strip_url_credentials_returns_url_unchanged_without_userinfo() -> None:
    location = "https://example.com:8443/path?q=1"

    assert strip_url_credentials(location) == location


@pytest.mark.unit
def test_strip_url_credentials_removes_userinfo() -> None:
    stripped = strip_url_credentials("https://user:pass@example.com/p")

    assert "user" not in stripped
    assert "pass" not in stripped
    assert stripped.startswith("https://example.com/")


@pytest.mark.unit
def test_strip_url_credentials_rejects_invalid_port() -> None:
    with pytest.raises(ValueError, match="invalid port"):
        strip_url_credentials("https://example.com:99999/")


@pytest.mark.unit
def test_hostname_resolves_to_private_ip_for_literal_loopback() -> None:
    assert hostname_resolves_to_private_ip("127.0.0.1") is True


@pytest.mark.unit
def test_hostname_resolves_to_private_ip_skips_unparseable_resolved_address() -> None:
    # A resolver may yield an address string ipaddress cannot parse; such
    # entries are skipped, and a following private entry still triggers block.
    def resolver(_hostname: str) -> _AddrInfoList:
        return [
            (socket.AF_INET, 0, 0, "", ["not-an-ip-address", 0]),
            (socket.AF_INET, 0, 0, "", ["10.0.0.5", 0]),
        ]

    assert hostname_resolves_to_private_ip("host.invalid", resolver=resolver) is True


@pytest.mark.unit
def test_hostname_resolves_to_public_ip_returns_false() -> None:
    def resolver(_hostname: str) -> _AddrInfoList:
        return [(socket.AF_INET, 0, 0, "", ["93.184.216.34", 0])]

    assert hostname_resolves_to_private_ip("host.invalid", resolver=resolver) is False


@pytest.mark.unit
def test_hostname_resolves_to_private_ip_fails_closed_on_resolution_error() -> None:
    def resolver(_hostname: str) -> _AddrInfoList:
        raise socket.gaierror("nope")

    assert hostname_resolves_to_private_ip("host.invalid", resolver=resolver) is True
