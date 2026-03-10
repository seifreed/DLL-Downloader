"""
Settings model for the DLL Downloader application.
"""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    """
    Application configuration values plus local validation helpers.
    """

    virustotal_api_key: str | None = None
    download_directory: str = field(default_factory=lambda: str(Path.cwd() / "downloads"))
    download_base_url: str = "https://es.dll-files.com"
    http_timeout: int = 60
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
        if self.http_timeout <= 0:
            raise ValueError("http_timeout must be positive")

        if self.http_max_retries <= 0:
            raise ValueError("http_max_retries must be positive")

        if self.http_retry_backoff_seconds < 0:
            raise ValueError("http_retry_backoff_seconds cannot be negative")

        if self.http_retry_jitter_seconds < 0:
            raise ValueError("http_retry_jitter_seconds cannot be negative")

        if self.user_agent_pool is not None and not self.user_agent_pool:
            raise ValueError("user_agent_pool must contain at least one value")

        if self.malicious_threshold <= 0:
            raise ValueError("malicious_threshold must be positive")

        if self.suspicious_threshold <= 0:
            raise ValueError("suspicious_threshold must be positive")

        if self.suspicious_threshold >= self.malicious_threshold:
            raise ValueError(
                "suspicious_threshold must be less than malicious_threshold"
            )

        return True

    @property
    def downloads_path(self) -> Path:
        """Get the downloads directory as a Path object."""
        return Path(self.download_directory).expanduser().resolve()
