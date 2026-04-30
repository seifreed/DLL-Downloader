"""
Settings model for the DLL Downloader application.
"""

from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path

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


def _validate_non_negative_number(value: object, field_name: str) -> None:
    value = _validate_number(value, field_name)
    if not isfinite(value):
        raise ValueError(f"{field_name} must be finite")
    if value < 0:
        raise ValueError(f"{field_name} cannot be negative")


def _validate_bool(value: object, field_name: str) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")


def _validate_string(value: object, field_name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


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

    virustotal_api_key: str | None = None
    download_directory: str = field(default_factory=lambda: str(Path.cwd() / "downloads"))
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
        _validate_string(self.download_base_url, "download_base_url")
        _validate_optional_string(self.user_agent, "user_agent")
        _validate_user_agent_pool(self.user_agent_pool)
        _validate_bool(self.verify_ssl, "verify_ssl")
        _validate_bool(self.scan_before_save, "scan_before_save")
        _validate_log_level(self.log_level)

        _validate_positive_integer(self.http_timeout, "http_timeout")
        _validate_positive_number(self.virustotal_timeout, "virustotal_timeout")
        _validate_positive_integer(self.http_max_retries, "http_max_retries")
        _validate_non_negative_number(
            self.http_retry_backoff_seconds,
            "http_retry_backoff_seconds",
        )
        _validate_non_negative_number(
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
        return Path(self.download_directory).expanduser().resolve()
