"""
Load settings from external configuration sources.
"""

import json
import logging
import os
import re
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import ClassVar, TypedDict

from .settings import Settings

RawSettingsMap = Mapping[str, object]
ConvertedSettingValue = str | int | float | bool | tuple[str, ...]


class SettingsInitKwargs(TypedDict, total=False):
    virustotal_api_key: str | None
    download_directory: str
    download_base_url: str
    http_timeout: int
    http_max_retries: int
    http_retry_backoff_seconds: float
    http_retry_jitter_seconds: float
    verify_ssl: bool
    user_agent: str | None
    user_agent_pool: tuple[str, ...] | None
    scan_before_save: bool
    malicious_threshold: int
    suspicious_threshold: int
    log_level: str


class _JSONSettingsSource:
    """Read typed settings overrides from a JSON configuration file."""

    @staticmethod
    def load(config_path: str) -> SettingsInitKwargs:
        with open(config_path) as file_handle:
            config_data = json.load(file_handle)
        if not isinstance(config_data, Mapping):
            raise ValueError("Configuration file must contain a JSON object")
        return SettingsLoader._mapped_kwargs(config_data, SettingsLoader.JSON_MAPPING)


class _EnvironmentSettingsSource:
    """Read typed settings overrides from environment variables."""

    @staticmethod
    def load() -> SettingsInitKwargs:
        return SettingsLoader._mapped_kwargs_from_env(SettingsLoader.ENV_MAPPING)


class _VTTomlSettingsSource:
    """Read a fallback VirusTotal API key from ~/.vt.toml."""

    @staticmethod
    def load(home_override: str | None = None) -> str | None:
        vt_path = (
            Path(home_override) / ".vt.toml"
            if home_override
            else Path("~/.vt.toml").expanduser()
        )
        if not vt_path.exists():
            return None

        try:
            contents = vt_path.read_text()
        except OSError:
            return None

        match = re.search(r"apikey\s*=\s*['\"]([^'\"]+)['\"]", contents)
        return match.group(1) if match else None


class SettingsLoader:
    """Compose settings from defaults, files, env vars and local VT config."""

    DEFAULT_CONFIG_PATHS: ClassVar[tuple[str, ...]] = (
        ".config.json",
        "config.json",
        "~/.dll_downloader/config.json",
    )

    ENV_MAPPING: ClassVar[dict[str, str]] = {
        "DLL_VIRUSTOTAL_API_KEY": "virustotal_api_key",
        "DLL_DOWNLOAD_DIRECTORY": "download_directory",
        "DLL_DOWNLOAD_BASE_URL": "download_base_url",
        "DLL_HTTP_TIMEOUT": "http_timeout",
        "DLL_HTTP_MAX_RETRIES": "http_max_retries",
        "DLL_HTTP_RETRY_BACKOFF_SECONDS": "http_retry_backoff_seconds",
        "DLL_HTTP_RETRY_JITTER_SECONDS": "http_retry_jitter_seconds",
        "DLL_VERIFY_SSL": "verify_ssl",
        "DLL_SCAN_BEFORE_SAVE": "scan_before_save",
        "DLL_MALICIOUS_THRESHOLD": "malicious_threshold",
        "DLL_SUSPICIOUS_THRESHOLD": "suspicious_threshold",
        "DLL_LOG_LEVEL": "log_level",
        "DLL_USER_AGENT": "user_agent",
        "DLL_USER_AGENT_POOL": "user_agent_pool",
    }

    JSON_MAPPING: ClassVar[dict[str, str]] = {
        "virustotal_api_key": "virustotal_api_key",
        "download_directory": "download_directory",
        "download_base_url": "download_base_url",
        "http_timeout": "http_timeout",
        "http_max_retries": "http_max_retries",
        "http_retry_backoff_seconds": "http_retry_backoff_seconds",
        "http_retry_jitter_seconds": "http_retry_jitter_seconds",
        "verify_ssl": "verify_ssl",
        "scan_before_save": "scan_before_save",
        "malicious_threshold": "malicious_threshold",
        "suspicious_threshold": "suspicious_threshold",
        "log_level": "log_level",
        "user_agent": "user_agent",
        "user_agent_pool": "user_agent_pool",
    }

    @classmethod
    def from_env(cls) -> Settings:
        """Create settings from environment variables."""
        return Settings(**_EnvironmentSettingsSource.load())

    @classmethod
    def from_json(cls, config_path: str) -> Settings:
        """Load settings from a JSON configuration file."""
        return Settings(**_JSONSettingsSource.load(config_path))

    @classmethod
    def load(cls, config_path: str | None = None) -> Settings:
        """Load settings with precedence env > config > ~/.vt.toml > defaults."""
        settings = Settings()
        resolved_config_path = config_path or cls._find_config_path()

        if resolved_config_path and os.path.exists(resolved_config_path):
            try:
                settings = cls._merge(settings, cls.from_json(resolved_config_path))
            except (json.JSONDecodeError, FileNotFoundError, ValueError) as exc:
                logging.warning(
                    "Failed to load config from %s: %s",
                    resolved_config_path,
                    exc,
                )

        if settings.virustotal_api_key is None:
            vt_key = _VTTomlSettingsSource.load(os.environ.get("HOME"))
            if vt_key:
                settings = replace(settings, virustotal_api_key=vt_key)

        return cls._merge(settings, cls.from_env())

    @classmethod
    def _mapped_kwargs(
        cls,
        source: RawSettingsMap,
        mapping: dict[str, str],
    ) -> SettingsInitKwargs:
        mapped: SettingsInitKwargs = {}
        for source_name, attr_name in mapping.items():
            if source_name not in source:
                continue
            value = source[source_name]
            if value is None or isinstance(value, (str, int, float, bool, tuple)):
                cls._assign_mapped_value(mapped, attr_name, value)
                continue
            if isinstance(value, list) and all(isinstance(item, str) for item in value):
                cls._assign_mapped_value(mapped, attr_name, tuple(value))
        return mapped

    @classmethod
    def _mapped_kwargs_from_env(cls, mapping: dict[str, str]) -> SettingsInitKwargs:
        mapped: SettingsInitKwargs = {}
        for env_name, attr_name in mapping.items():
            value = os.environ.get(env_name)
            if value is None:
                continue
            cls._assign_mapped_value(mapped, attr_name, cls._convert_env_value(attr_name, value))
        return mapped

    @staticmethod
    def _convert_env_value(attr_name: str, value: str) -> ConvertedSettingValue:
        if attr_name in {
            "http_timeout",
            "http_max_retries",
            "malicious_threshold",
            "suspicious_threshold",
        }:
            return int(value)
        if attr_name in {"http_retry_backoff_seconds", "http_retry_jitter_seconds"}:
            return float(value)
        if attr_name == "user_agent_pool":
            return tuple(
                item.strip()
                for item in value.split(",")
                if item.strip()
            )
        if attr_name in {"verify_ssl", "scan_before_save"}:
            return value.lower() in ("true", "1", "yes")
        return value

    @staticmethod
    def _assign_mapped_value(
        mapped: SettingsInitKwargs,
        attr_name: str,
        value: str | int | float | bool | tuple[str, ...] | None,
    ) -> None:
        if SettingsLoader._assign_optional_string(mapped, attr_name, value):
            return
        if SettingsLoader._assign_string(mapped, attr_name, value):
            return
        if SettingsLoader._assign_int(mapped, attr_name, value):
            return
        if SettingsLoader._assign_float(mapped, attr_name, value):
            return
        if SettingsLoader._assign_string_tuple(mapped, attr_name, value):
            return
        SettingsLoader._assign_bool(mapped, attr_name, value)

    @staticmethod
    def _assign_optional_string(
        mapped: SettingsInitKwargs,
        attr_name: str,
        value: ConvertedSettingValue | None,
    ) -> bool:
        normalized = value if value is None or isinstance(value, str) else str(value)
        if attr_name == "virustotal_api_key":
            mapped["virustotal_api_key"] = normalized
            return True
        if attr_name == "user_agent":
            mapped["user_agent"] = normalized
            return True
        return False

    @staticmethod
    def _assign_string_tuple(
        mapped: SettingsInitKwargs,
        attr_name: str,
        value: str | int | float | bool | tuple[str, ...] | None,
    ) -> bool:
        if not isinstance(value, tuple):
            return False
        if not all(isinstance(item, str) for item in value):
            return False
        if attr_name == "user_agent_pool":
            mapped["user_agent_pool"] = value
            return True
        return False

    @staticmethod
    def _assign_string(
        mapped: SettingsInitKwargs,
        attr_name: str,
        value: str | int | float | bool | tuple[str, ...] | None,
    ) -> bool:
        if not isinstance(value, str):
            return False
        if attr_name == "download_directory":
            mapped["download_directory"] = value
            return True
        if attr_name == "download_base_url":
            mapped["download_base_url"] = value
            return True
        if attr_name == "log_level":
            mapped["log_level"] = value
            return True
        return False

    @staticmethod
    def _assign_int(
        mapped: SettingsInitKwargs,
        attr_name: str,
        value: str | int | float | bool | tuple[str, ...] | None,
    ) -> bool:
        if not isinstance(value, int):
            return False
        if attr_name == "http_timeout":
            mapped["http_timeout"] = value
            return True
        if attr_name == "http_max_retries":
            mapped["http_max_retries"] = value
            return True
        if attr_name == "malicious_threshold":
            mapped["malicious_threshold"] = value
            return True
        if attr_name == "suspicious_threshold":
            mapped["suspicious_threshold"] = value
            return True
        return False

    @staticmethod
    def _assign_float(
        mapped: SettingsInitKwargs,
        attr_name: str,
        value: str | int | float | bool | tuple[str, ...] | None,
    ) -> bool:
        if not isinstance(value, float):
            return False
        if attr_name == "http_retry_backoff_seconds":
            mapped["http_retry_backoff_seconds"] = value
            return True
        if attr_name == "http_retry_jitter_seconds":
            mapped["http_retry_jitter_seconds"] = value
            return True
        return False

    @staticmethod
    def _assign_bool(
        mapped: SettingsInitKwargs,
        attr_name: str,
        value: str | int | float | bool | tuple[str, ...] | None,
    ) -> bool:
        if not isinstance(value, bool):
            return False
        if attr_name == "verify_ssl":
            mapped["verify_ssl"] = value
            return True
        if attr_name == "scan_before_save":
            mapped["scan_before_save"] = value
            return True
        return False

    @classmethod
    def _find_config_path(cls) -> str | None:
        for candidate in map(os.path.expanduser, cls.DEFAULT_CONFIG_PATHS):
            if os.path.exists(candidate):
                return candidate
        return None

    @staticmethod
    def _merge(base: Settings, override: Settings) -> Settings:
        defaults = Settings()
        overrides = {
            field_name: getattr(override, field_name)
            for field_name in base.__dataclass_fields__
            if getattr(override, field_name) != getattr(defaults, field_name)
            and getattr(override, field_name) is not None
        }
        return replace(base, **overrides)
