"""
Settings model for the DLL Downloader application.
"""

import ipaddress
from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path
from urllib.parse import ParseResult, urlparse

from ...domain.validation import validate_is_bool
from ..net import is_private_address
from ..validation import validate_non_negative_number

_VALID_LOG_LEVELS = frozenset(
    {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
)


def _validate_number(value: object, field_name: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a number")
    return value


def _validate_positive_number(value: object, field_name: str) -> None:
    value = _validate_number(value, field_name)
    if not isfinite(value):
        raise ValueError(f"{field_name} must be finite")
    if value <= 0:
        raise ValueError(f"{field_name} must be positive")


def _validate_integer(value: object, field_name: str) -> int:
    value = _validate_number(value, field_name)
    if not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    return value


def _validate_positive_integer(value: object, field_name: str) -> None:
    value = _validate_integer(value, field_name)
    if value <= 0:
        raise ValueError(f"{field_name} must be positive")


def _validate_string(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _validate_https_url(value: object, field_name: str) -> None:
    validated = _validate_string(value, field_name)
    parsed = urlparse(validated)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"{field_name} must use HTTPS")
    _validate_not_private_url(validated, field_name)


def _validated_url_hostname(parsed: ParseResult, field_name: str) -> str:
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field_name} must have a valid port") from exc
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field_name} must not include credentials")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"{field_name} must have a valid hostname")
    return hostname


def _validate_not_private_url(value: str, field_name: str) -> None:
    """Reject URLs that resolve to private or loopback IP ranges (SSRF protection).

    Fails closed on DNS resolution errors to prevent DNS-rebinding attacks.
    Consistent with transport-layer SSRF checks.
    """
    import socket

    parsed = urlparse(value)
    hostname = _validated_url_hostname(parsed, field_name)
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        pass  # hostname is not an IP literal; proceed to DNS resolution
    else:
        if is_private_address(addr):
            raise ValueError(
                f"{field_name} must not point to a private, loopback, reserved, or multicast address"
            )
        return
    # Not an IP literal; resolve hostname to check for DNS rebinding.
    # Fail closed on DNS errors (consistent with transport layer).
    try:
        resolved = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        for _family, _type, _proto, _canonname, sockaddr in resolved:
            ip_str = sockaddr[0]
            try:
                resolved_addr = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if is_private_address(resolved_addr):
                raise ValueError(
                    f"{field_name} must not resolve to a private, loopback, reserved, or multicast address"
                )
    except (socket.gaierror, socket.herror, OSError) as exc:
        raise ValueError(
            f"{field_name} hostname does not resolve; cannot verify it is not private"
        ) from exc


def _validate_log_level(value: object) -> None:
    if not isinstance(value, str):
        raise ValueError("log_level must be a string")
    if value.upper() not in _VALID_LOG_LEVELS:
        allowed = ", ".join(sorted(_VALID_LOG_LEVELS))
        raise ValueError(f"log_level must be one of: {allowed}")


def _validate_optional_string(value: object, field_name: str) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or null")
    if not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string or null")


def _validate_user_agent_pool(value: object) -> None:
    if value is None:
        return
    if not isinstance(value, tuple):
        raise ValueError("user_agent_pool must be a tuple of strings")
    if not value:
        raise ValueError("user_agent_pool must contain at least one value")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError("user_agent_pool must contain non-empty string values")


@dataclass
class Settings:
    """
    Application configuration values plus local validation helpers.
    """

    virustotal_api_key: str | None = field(default=None, repr=False)
    download_directory: str = field(
        default_factory=lambda: str(Path.cwd() / "downloads")
    )
    download_base_url: str = "https://es.dll-files.com"
    http_timeout: int = 60
    virustotal_timeout: float = 60.0
    http_max_retries: int = 5
    http_retry_backoff_seconds: float = 0.0
    http_retry_jitter_seconds: float = 0.0
    verify_ssl: bool = True
    user_agent: str | None = None
    user_agent_pool: tuple[str, ...] | None = None
    scan_before_save: bool = True
    malicious_threshold: int = 5
    suspicious_threshold: int = 1
    log_level: str = "INFO"

    def validate(self) -> bool:
        """Validate the current settings."""
        _validate_optional_string(self.virustotal_api_key, "virustotal_api_key")
        _validate_string(self.download_directory, "download_directory")
        _validate_https_url(self.download_base_url, "download_base_url")
        _validate_optional_string(self.user_agent, "user_agent")
        _validate_user_agent_pool(self.user_agent_pool)
        validate_is_bool(self.verify_ssl, "verify_ssl")
        validate_is_bool(self.scan_before_save, "scan_before_save")
        _validate_log_level(self.log_level)

        _validate_positive_integer(self.http_timeout, "http_timeout")
        _validate_positive_number(self.virustotal_timeout, "virustotal_timeout")
        _validate_positive_integer(self.http_max_retries, "http_max_retries")
        validate_non_negative_number(
            self.http_retry_backoff_seconds,
            "http_retry_backoff_seconds",
        )
        validate_non_negative_number(
            self.http_retry_jitter_seconds,
            "http_retry_jitter_seconds",
        )

        _validate_positive_integer(self.malicious_threshold, "malicious_threshold")
        _validate_positive_integer(self.suspicious_threshold, "suspicious_threshold")

        if self.suspicious_threshold >= self.malicious_threshold:
            raise ValueError(
                "suspicious_threshold must be less than malicious_threshold"
            )

        return True

    @property
    def downloads_path(self) -> Path:
        """Get the downloads directory as a Path object."""
        return Path(self.download_directory).expanduser().absolute()
