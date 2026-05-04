"""
Load settings from external configuration sources.
"""

import contextlib
import errno
import json
import logging
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, ClassVar, TypedDict, cast

from .settings import Settings

RawSettingsMap = Mapping[str, object]
ConvertedSettingValue = str | int | float | bool | tuple[str, ...]
_FALSE_BOOLEAN_VALUES = {"false", "0", "no"}
_TRUE_BOOLEAN_VALUES = {"true", "1", "yes"}
_VT_API_KEY_LINE_PATTERN = re.compile(
    r"^\s*apikey\s*=\s*(['\"])(?P<api_key>[^'\"]+)\1\s*(?:#.*)?$"
)


class SettingsInitKwargs(TypedDict, total=False):
    virustotal_api_key: str | None
    download_directory: str
    download_base_url: str
    http_timeout: int
    virustotal_timeout: float
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
        path = Path(config_path)
        fd = -1
        try:
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise OSError(f"Refusing to read configuration from symlink: {config_path}") from exc
            raise OSError(f"Cannot open configuration file: {config_path}") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                os.close(fd)
                fd = -1
                raise OSError(f"Configuration path is not a regular file: {config_path}")
            # Clear O_NONBLOCK for regular files so read() works normally.
            os.set_blocking(fd, True)
            with os.fdopen(fd, encoding="utf-8") as file_handle:
                fd = -1
                config_data = json.load(file_handle)
        finally:
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)
        if not isinstance(config_data, Mapping):
            raise ValueError("Configuration file must contain a JSON object")
        return SettingsLoader._mapped_kwargs(
            config_data,
            SettingsLoader.JSON_MAPPING,
            strict=True,
        )


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
            if home_override is not None and home_override.strip()
            else Path("~/.vt.toml").expanduser()
        )
        fd = -1
        try:
            fd = os.open(str(vt_path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise OSError(f"Refusing to read VT configuration from symlink: {vt_path}") from exc
            return None
        try:
            # Clear O_NONBLOCK for regular files so read() works normally.
            os.set_blocking(fd, True)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                os.close(fd)
                fd = -1
                return None
            if st.st_mode & 0o077:
                logging.warning(
                    "VT config file %s has overly permissive permissions (%o); "
                    "consider restricting to 0600",
                    vt_path,
                    st.st_mode & 0o777,
                )
            with os.fdopen(fd, encoding="utf-8") as f:
                fd = -1
                contents = f.read()
        except (OSError, UnicodeDecodeError):
            return None
        finally:
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)

        for line in contents.splitlines():
            match = _VT_API_KEY_LINE_PATTERN.fullmatch(line)
            if match:
                return match.group("api_key")
        return None


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
        "DLL_VIRUSTOTAL_TIMEOUT": "virustotal_timeout",
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
        "virustotal_timeout": "virustotal_timeout",
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
        return cls._validated_settings(_EnvironmentSettingsSource.load())

    @classmethod
    def from_json(cls, config_path: str) -> Settings:
        """Load settings from a JSON configuration file."""
        return cls._validated_settings(_JSONSettingsSource.load(config_path))

    @classmethod
    def load(cls, config_path: str | None = None) -> Settings:
        """Load settings with precedence env > config > ~/.vt.toml > defaults."""
        settings = Settings()
        config_disables_vt_fallback = False
        resolved_config_path: str | None
        if config_path is not None:
            resolved_config_path = os.path.expanduser(config_path)
            if not os.path.exists(resolved_config_path):
                raise ValueError(f"Configuration file not found: {config_path}")
        else:
            resolved_config_path = cls._find_config_path()

        if resolved_config_path and os.path.exists(resolved_config_path):
            try:
                config_values = _JSONSettingsSource.load(resolved_config_path)
                config_disables_vt_fallback = (
                    "virustotal_api_key" in config_values
                    and config_values["virustotal_api_key"] is None
                )
                settings = cls._merge(
                    settings,
                    config_values,
                    allow_none_overrides=True,
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                logging.warning(
                    "Failed to load config from %s: %s",
                    resolved_config_path,
                    exc,
                )

        if settings.virustotal_api_key is None and not config_disables_vt_fallback:
            vt_key = _VTTomlSettingsSource.load(os.environ.get("HOME"))
            if vt_key:
                settings = cls._merge(settings, {"virustotal_api_key": vt_key})

        settings = cls._merge(settings, _EnvironmentSettingsSource.load())
        settings.validate()
        return settings

    @classmethod
    def _mapped_kwargs(
        cls,
        source: RawSettingsMap,
        mapping: dict[str, str],
        *,
        strict: bool = False,
    ) -> SettingsInitKwargs:
        mapped: SettingsInitKwargs = {}
        for source_name, attr_name in mapping.items():
            if source_name not in source:
                continue
            value = source[source_name]
            assigned = False
            if value is None or isinstance(value, (str, int, float, bool, tuple)):
                assigned = cls._assign_mapped_value(mapped, attr_name, value)
            elif isinstance(value, list) and all(isinstance(item, str) for item in value):
                assigned = cls._assign_mapped_value(mapped, attr_name, tuple(value))
            if strict and not assigned:
                raise ValueError(f"Invalid value for {source_name}")
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
            try:
                return int(value)
            except ValueError:
                raise ValueError(
                    f"Environment variable for {attr_name} must be an integer, got: {value!r}"
                ) from None
        if attr_name in {
            "virustotal_timeout",
            "http_retry_backoff_seconds",
            "http_retry_jitter_seconds",
        }:
            try:
                return float(value)
            except ValueError:
                raise ValueError(
                    f"Environment variable for {attr_name} must be a float, got: {value!r}"
                ) from None
        if attr_name == "user_agent_pool":
            return tuple(
                item.strip()
                for item in value.split(",")
                if item.strip()
            )
        if attr_name in {"verify_ssl", "scan_before_save"}:
            return SettingsLoader._convert_env_bool(attr_name, value)
        return value

    @staticmethod
    def _convert_env_bool(attr_name: str, value: str) -> bool:
        normalized = value.strip().lower()
        if normalized in _TRUE_BOOLEAN_VALUES:
            return True
        if normalized in _FALSE_BOOLEAN_VALUES:
            return False
        raise ValueError(f"{attr_name} must be a boolean value")

    @staticmethod
    def _assign_mapped_value(
        mapped: SettingsInitKwargs,
        attr_name: str,
        value: str | int | float | bool | tuple[str, ...] | None,
    ) -> bool:
        if SettingsLoader._assign_optional_string(mapped, attr_name, value):
            return True
        if SettingsLoader._assign_string(mapped, attr_name, value):
            return True
        if SettingsLoader._assign_int(mapped, attr_name, value):
            return True
        if SettingsLoader._assign_float(mapped, attr_name, value):
            return True
        if SettingsLoader._assign_string_tuple(mapped, attr_name, value):
            return True
        return SettingsLoader._assign_bool(mapped, attr_name, value)

    @staticmethod
    def _assign_optional_string(
        mapped: SettingsInitKwargs,
        attr_name: str,
        value: ConvertedSettingValue | None,
    ) -> bool:
        if attr_name == "virustotal_api_key":
            if value is not None and not isinstance(value, str):
                return False
            mapped["virustotal_api_key"] = value
            return True
        if attr_name == "user_agent":
            if value is not None and not isinstance(value, str):
                return False
            mapped["user_agent"] = value
            return True
        return False

    @staticmethod
    def _assign_string_tuple(
        mapped: SettingsInitKwargs,
        attr_name: str,
        value: str | int | float | bool | tuple[str, ...] | None,
    ) -> bool:
        if attr_name == "user_agent_pool" and value is None:
            mapped["user_agent_pool"] = None
            return True
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
        if isinstance(value, bool):
            return False
        if isinstance(value, float):
            if not value.is_integer():
                return False
            value = int(value)
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
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return False
        if attr_name == "http_retry_backoff_seconds":
            mapped["http_retry_backoff_seconds"] = float(value)
            return True
        if attr_name == "virustotal_timeout":
            mapped["virustotal_timeout"] = float(value)
            return True
        if attr_name == "http_retry_jitter_seconds":
            mapped["http_retry_jitter_seconds"] = float(value)
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
            try:
                st = os.lstat(candidate)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                logging.warning("Skipping symlink configuration path: %s", candidate)
                continue
            if stat.S_ISREG(st.st_mode):
                return candidate
        return None

    @staticmethod
    def _merge(
        base: Settings,
        override: SettingsInitKwargs,
        *,
        allow_none_overrides: bool = False,
    ) -> Settings:
        overrides = {
            field_name: value
            for field_name, value in override.items()
            if allow_none_overrides or value is not None
        }
        return replace(base, **cast(dict[str, Any], overrides))

    @staticmethod
    def _validated_settings(values: SettingsInitKwargs) -> Settings:
        settings = Settings(**values)
        settings.validate()
        return settings
