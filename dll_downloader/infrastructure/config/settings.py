"""
Application Settings

Configuration management for the DLL Downloader application.
Supports loading from environment variables and JSON config files.
"""

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, ClassVar


@dataclass
class Settings:
    """
    Application configuration settings.

    Settings can be loaded from:
    1. Environment variables (prefixed with DLL_)
    2. JSON configuration file (.config.json)
    3. Default values

    Priority: Environment variables > Config file > Defaults

    Attributes:
        virustotal_api_key: API key for VirusTotal integration
        download_directory: Local directory for storing downloaded DLLs
        download_base_url: Base URL for DLL download service
        http_timeout: HTTP request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        scan_before_save: Default setting for security scanning
        malicious_threshold: VT detections to mark as malicious
        suspicious_threshold: VT detections to mark as suspicious
        log_level: Application logging level
        user_agent: Custom User-Agent for HTTP requests
    """

    # VirusTotal settings
    virustotal_api_key: str | None = None

    # Download settings
    download_directory: str = field(default_factory=lambda: str(Path.cwd() / "downloads"))
    download_base_url: str = "https://es.dll-files.com"

    # HTTP settings
    http_timeout: int = 60
    verify_ssl: bool = True
    user_agent: str | None = None

    # Security settings
    scan_before_save: bool = True
    malicious_threshold: int = 5
    suspicious_threshold: int = 1

    # Logging
    log_level: str = "INFO"

    DEFAULT_CONFIG_PATHS: ClassVar[tuple[str, ...]] = (
        ".config.json",
        "config.json",
        "~/.dll_downloader/config.json",
    )

    ENV_MAPPING: ClassVar[dict[str, str]] = {
        'DLL_VIRUSTOTAL_API_KEY': 'virustotal_api_key',
        'DLL_DOWNLOAD_DIRECTORY': 'download_directory',
        'DLL_DOWNLOAD_BASE_URL': 'download_base_url',
        'DLL_HTTP_TIMEOUT': 'http_timeout',
        'DLL_VERIFY_SSL': 'verify_ssl',
        'DLL_SCAN_BEFORE_SAVE': 'scan_before_save',
        'DLL_MALICIOUS_THRESHOLD': 'malicious_threshold',
        'DLL_SUSPICIOUS_THRESHOLD': 'suspicious_threshold',
        'DLL_LOG_LEVEL': 'log_level',
        'DLL_USER_AGENT': 'user_agent',
    }

    JSON_MAPPING: ClassVar[dict[str, str]] = {
        'virustotal_api_key': 'virustotal_api_key',
        'download_directory': 'download_directory',
        'download_base_url': 'download_base_url',
        'http_timeout': 'http_timeout',
        'verify_ssl': 'verify_ssl',
        'scan_before_save': 'scan_before_save',
        'malicious_threshold': 'malicious_threshold',
        'suspicious_threshold': 'suspicious_threshold',
        'log_level': 'log_level',
        'user_agent': 'user_agent',
    }

    ENV_CONVERTERS: ClassVar[dict[str, Callable[[str], object]]] = {
        'http_timeout': int,
        'malicious_threshold': int,
        'suspicious_threshold': int,
        'verify_ssl': lambda value: value.lower() in ('true', '1', 'yes'),
        'scan_before_save': lambda value: value.lower() in ('true', '1', 'yes'),
    }

    @classmethod
    def from_env(cls) -> "Settings":
        """
        Create settings from environment variables.

        Environment variables are prefixed with DLL_ and converted to lowercase.
        Example: DLL_VIRUSTOTAL_API_KEY -> virustotal_api_key

        Returns:
            Settings instance with values from environment
        """
        return cls(**cls._mapped_kwargs_from_env(cls.ENV_MAPPING))

    @classmethod
    def from_json(cls, config_path: str) -> "Settings":
        """
        Load settings from a JSON configuration file.

        Args:
            config_path: Path to the JSON config file

        Returns:
            Settings instance with values from file

        Raises:
            FileNotFoundError: If config file doesn't exist
            json.JSONDecodeError: If config file is invalid JSON
        """
        with open(config_path) as f:
            config_data = json.load(f)

        # Map JSON keys to settings attributes
        return cls(**cls._mapped_kwargs(config_data, cls.JSON_MAPPING))

    @classmethod
    def load(cls, config_path: str | None = None) -> "Settings":
        """
        Load settings with priority: env vars > config file > defaults.

        Args:
            config_path: Optional path to JSON config file

        Returns:
            Settings instance with merged configuration
        """
        # Start with defaults
        settings = cls()

        # Load from config file if it exists
        if config_path is None:
            config_path = cls._find_config_path()

        if config_path and os.path.exists(config_path):
            try:
                file_settings = cls.from_json(config_path)
                settings = cls._merge(settings, file_settings)
            except (json.JSONDecodeError, FileNotFoundError) as e:
                import logging
                logging.warning(f"Failed to load config from {config_path}: {e}")

        # Load VirusTotal API key from ~/.vt.toml if not already set
        if settings.virustotal_api_key is None:
            vt_key = cls._load_vt_toml_key()
            if vt_key:
                settings = replace(settings, virustotal_api_key=vt_key)

        # Override with environment variables
        env_settings = cls.from_env()
        settings = cls._merge(settings, env_settings)

        return settings

    @staticmethod
    def _mapped_kwargs(
        source: dict[str, Any],
        mapping: dict[str, str],
    ) -> dict[str, Any]:
        """Map keys from a source dict into Settings kwargs."""
        return {
            attr_name: source[json_key]
            for json_key, attr_name in mapping.items()
            if json_key in source
        }

    @classmethod
    def _mapped_kwargs_from_env(cls, mapping: dict[str, str]) -> dict[str, Any]:
        """Map environment variables into Settings kwargs with conversions."""
        def _identity(value: str) -> object:
            return value

        return {
            attr_name: cls.ENV_CONVERTERS.get(attr_name, _identity)(value)
            for env_var, attr_name in mapping.items()
            if (value := os.environ.get(env_var)) is not None
        }

    @classmethod
    def _find_config_path(cls) -> str | None:
        for path in map(os.path.expanduser, cls.DEFAULT_CONFIG_PATHS):
            if os.path.exists(path):
                return path
        return None

    @staticmethod
    def _load_vt_toml_key() -> str | None:
        home_override = os.environ.get("HOME")
        if home_override:
            vt_path = Path(home_override) / ".vt.toml"
        else:
            vt_path = Path("~/.vt.toml").expanduser()
        if not vt_path.exists():
            return None

        try:
            contents = vt_path.read_text()
        except OSError:
            return None

        match = re.search(r"apikey\s*=\s*['\"]([^'\"]+)['\"]", contents)
        if not match:
            return None
        return match.group(1)

    @classmethod
    def _merge(cls, base: "Settings", override: "Settings") -> "Settings":
        """
        Merge two settings objects, preferring non-None values from override.

        Args:
            base: Base settings
            override: Settings to override base values

        Returns:
            Merged settings
        """
        defaults = cls()
        overrides = {
            field_name: getattr(override, field_name)
            for field_name in base.__dataclass_fields__
            if getattr(override, field_name) != getattr(defaults, field_name)
            and getattr(override, field_name) is not None
        }
        return replace(base, **overrides)

    def validate(self) -> bool:
        """
        Validate the current settings.

        Returns:
            True if settings are valid

        Raises:
            ValueError: If any setting is invalid
        """
        if self.http_timeout <= 0:
            raise ValueError("http_timeout must be positive")

        if self.malicious_threshold <= 0:
            raise ValueError("malicious_threshold must be positive")

        if self.suspicious_threshold <= 0:
            raise ValueError("suspicious_threshold must be positive")

        if self.suspicious_threshold >= self.malicious_threshold:
            raise ValueError("suspicious_threshold must be less than malicious_threshold")

        return True

    @property
    def downloads_path(self) -> Path:
        """Get the downloads directory as a Path object."""
        return Path(self.download_directory).expanduser().resolve()
