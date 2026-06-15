# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for application settings.

This module tests the Settings configuration management including loading
from environment variables, JSON files, and defaults. Tests use real file
I/O and environment manipulation.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

import pytest

from dll_downloader.infrastructure.config.loader import (
    SettingsLoader,
    _VTTomlSettingsSource,
)
from dll_downloader.infrastructure.config.settings import Settings


@contextmanager
def _temporary_env(updates: Mapping[str, str | None]) -> Iterator[None]:
    original: dict[str, str | None] = {key: os.environ.get(key) for key in updates}
    try:
        for key, value in updates.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def _temporary_cwd(path: Path) -> Iterator[None]:
    original = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(original)


_PUBLIC_IP = "93.184.216.34"


@contextmanager
def _mock_dns_resolution() -> Iterator[None]:
    """Patch socket.getaddrinfo so unresolvable test URLs resolve to a public IP."""
    original_getaddrinfo = socket.getaddrinfo

    def _patched_getaddrinfo(
        host: str | bytes | None,
        port: bytes | str | int | None,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[Any, ...]]:
        if isinstance(host, str) and not _is_ip_address(host):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    (_PUBLIC_IP, port),
                )
            ]
        return original_getaddrinfo(host, port, family, type, proto, flags)

    socket.getaddrinfo = cast(Any, _patched_getaddrinfo)
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo


def _is_ip_address(host: str) -> bool:
    try:
        import ipaddress

        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ============================================================================
# Settings Initialization Tests
# ============================================================================


@pytest.mark.unit
def test_settings_creation_with_defaults() -> None:
    """
    Test Settings dataclass creation with default values.

    Purpose:
        Verify that Settings initializes with sensible defaults.

    Expected Behavior:
        - All fields have appropriate default values
        - No configuration sources needed
    """
    settings = Settings()

    assert settings.virustotal_api_key is None
    assert settings.download_directory == str(Path.cwd() / "downloads")
    assert settings.download_base_url == "https://es.dll-files.com"
    assert settings.http_timeout == 60
    assert settings.http_max_retries == 5
    assert settings.virustotal_timeout == 60.0
    assert settings.verify_ssl is True
    assert settings.user_agent is None
    assert settings.scan_before_save is True
    assert settings.malicious_threshold == 5
    assert settings.suspicious_threshold == 1
    assert settings.log_level == "INFO"


@pytest.mark.unit
def test_settings_creation_with_custom_values() -> None:
    """
    Test Settings creation with explicit values.

    Purpose:
        Verify that all fields can be customized.

    Expected Behavior:
        All provided values are stored correctly.
    """
    settings = Settings(
        virustotal_api_key="my_api_key",
        download_directory="/custom/path",
        download_base_url="https://custom.url",
        http_timeout=30,
        http_max_retries=7,
        virustotal_timeout=15.5,
        verify_ssl=False,
        user_agent="CustomAgent/1.0",
        scan_before_save=False,
        malicious_threshold=10,
        suspicious_threshold=3,
        log_level="DEBUG",
    )

    assert settings.virustotal_api_key == "my_api_key"
    assert settings.download_directory == "/custom/path"
    assert settings.download_base_url == "https://custom.url"
    assert settings.http_timeout == 30
    assert settings.http_max_retries == 7
    assert settings.virustotal_timeout == 15.5
    assert settings.verify_ssl is False
    assert settings.user_agent == "CustomAgent/1.0"
    assert settings.scan_before_save is False
    assert settings.malicious_threshold == 10
    assert settings.suspicious_threshold == 3
    assert settings.log_level == "DEBUG"


# ============================================================================
# Settings from Environment Tests
# ============================================================================


@pytest.mark.unit
def test_settings_from_env_all_variables() -> None:
    """
    Test loading Settings from environment variables.

    Purpose:
        Verify that all environment variables are correctly mapped.

    Expected Behavior:
        Environment variables override defaults with correct types.
    """
    with (
        _temporary_env(
            {
                "DLL_VIRUSTOTAL_API_KEY": "env_api_key",
                "DLL_DOWNLOAD_DIRECTORY": "/env/downloads",
                "DLL_DOWNLOAD_BASE_URL": "https://env.url",
                "DLL_HTTP_TIMEOUT": "45",
                "DLL_HTTP_MAX_RETRIES": "6",
                "DLL_VIRUSTOTAL_TIMEOUT": "12.5",
                "DLL_HTTP_RETRY_BACKOFF_SECONDS": "0.5",
                "DLL_HTTP_RETRY_JITTER_SECONDS": "0.1",
                "DLL_VERIFY_SSL": "false",
                "DLL_SCAN_BEFORE_SAVE": "no",
                "DLL_MALICIOUS_THRESHOLD": "8",
                "DLL_SUSPICIOUS_THRESHOLD": "2",
                "DLL_LOG_LEVEL": "WARNING",
                "DLL_USER_AGENT": "EnvAgent/1.0",
                "DLL_USER_AGENT_POOL": "AgentA, AgentB",
            }
        ),
        _mock_dns_resolution(),
    ):
        settings = SettingsLoader.from_env()

    assert settings.virustotal_api_key == "env_api_key"
    assert settings.download_directory == "/env/downloads"
    assert settings.download_base_url == "https://env.url"
    assert settings.http_timeout == 45
    assert settings.http_max_retries == 6
    assert settings.virustotal_timeout == 12.5
    assert settings.http_retry_backoff_seconds == 0.5
    assert settings.http_retry_jitter_seconds == 0.1
    assert settings.verify_ssl is False
    assert settings.scan_before_save is False
    assert settings.malicious_threshold == 8
    assert settings.suspicious_threshold == 2
    assert settings.log_level == "WARNING"
    assert settings.user_agent == "EnvAgent/1.0"
    assert settings.user_agent_pool == ("AgentA", "AgentB")


@pytest.mark.unit
def test_settings_from_env_partial_variables() -> None:
    """
    Test loading with only some environment variables set.

    Purpose:
        Verify that unset variables use defaults.

    Expected Behavior:
        - Set variables override defaults
        - Unset variables use default values
    """
    with _temporary_env(
        {
            "DLL_VIRUSTOTAL_API_KEY": "partial_key",
            "DLL_HTTP_TIMEOUT": "90",
        }
    ):
        settings = SettingsLoader.from_env()

    assert settings.virustotal_api_key == "partial_key"
    assert settings.http_timeout == 90
    # Unset values should use defaults
    assert settings.download_directory == str(Path.cwd() / "downloads")
    assert settings.verify_ssl is True


@pytest.mark.unit
def test_settings_from_env_boolean_parsing() -> None:
    """
    Test boolean value parsing from environment.

    Purpose:
        Verify that various boolean representations are handled correctly.

    Expected Behavior:
        'true', '1', 'yes' -> True; 'false', '0', 'no' -> False.
    """
    # Test True values
    for true_value in ["true", "True", "TRUE", "1", "yes", "Yes"]:
        with _temporary_env({"DLL_VERIFY_SSL": true_value}):
            settings = SettingsLoader.from_env()
            assert settings.verify_ssl is True, f"Failed for value: {true_value}"

    # Test False values
    for false_value in ["false", "False", "FALSE", "0", "no", "No"]:
        with _temporary_env({"DLL_VERIFY_SSL": false_value}):
            settings = SettingsLoader.from_env()
            assert settings.verify_ssl is False, f"Failed for value: {false_value}"


@pytest.mark.unit
def test_settings_from_env_rejects_invalid_boolean_values() -> None:
    with (
        _temporary_env({"DLL_VERIFY_SSL": "treu"}),
        pytest.raises(ValueError, match="verify_ssl must be a boolean value"),
    ):
        SettingsLoader.from_env()

    with (
        _temporary_env({"DLL_SCAN_BEFORE_SAVE": "treu"}),
        pytest.raises(ValueError, match="scan_before_save must be a boolean value"),
    ):
        SettingsLoader.from_env()


@pytest.mark.unit
def test_settings_from_env_integer_parsing() -> None:
    """
    Test integer value parsing from environment.

    Purpose:
        Verify that string numbers are converted to integers.

    Expected Behavior:
        Numeric strings are converted to int type.
    """
    with _temporary_env(
        {
            "DLL_HTTP_TIMEOUT": "120",
            "DLL_MALICIOUS_THRESHOLD": "15",
            "DLL_SUSPICIOUS_THRESHOLD": "5",
        }
    ):
        settings = SettingsLoader.from_env()

    assert settings.http_timeout == 120
    assert isinstance(settings.http_timeout, int)
    assert settings.malicious_threshold == 15
    assert isinstance(settings.malicious_threshold, int)
    assert settings.suspicious_threshold == 5
    assert isinstance(settings.suspicious_threshold, int)


@pytest.mark.unit
def test_settings_from_env_validates_values() -> None:
    with (
        _temporary_env({"DLL_HTTP_TIMEOUT": "0"}),
        pytest.raises(ValueError, match="http_timeout must be positive"),
    ):
        SettingsLoader.from_env()


@pytest.mark.unit
def test_settings_loader_load_reads_vt_toml_when_api_key_missing(
    tmp_path: Path,
) -> None:
    vt_file = tmp_path / ".vt.toml"
    vt_file.write_text("apikey = 'vt-test-key'")

    with _temporary_env({"HOME": str(tmp_path)}), _temporary_cwd(tmp_path):
        settings = SettingsLoader.load(config_path=None)

    assert settings.virustotal_api_key == "vt-test-key"


@pytest.mark.unit
def test_settings_loader_ignores_symlink_vt_toml(tmp_path: Path) -> None:
    target = tmp_path / "real-vt.toml"
    target.write_text("apikey = 'vt-test-key'")
    (tmp_path / ".vt.toml").symlink_to(target)

    with (
        _temporary_env(
            {
                "HOME": str(tmp_path),
                "USERPROFILE": str(tmp_path),
                "DLL_VIRUSTOTAL_API_KEY": None,
            }
        ),
        _temporary_cwd(tmp_path),
    ):
        settings = SettingsLoader.load(config_path=None)

    assert _VTTomlSettingsSource.load(str(tmp_path)) is None
    assert settings.virustotal_api_key is None


@pytest.mark.unit
def test_settings_loader_json_null_api_key_disables_vt_toml_fallback(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"virustotal_api_key": None}))
    (tmp_path / ".vt.toml").write_text("apikey = 'vt-test-key'")

    with _temporary_env({"HOME": str(tmp_path)}), _temporary_cwd(tmp_path):
        settings = SettingsLoader.load(config_path=str(config_path))

    assert settings.virustotal_api_key is None


@pytest.mark.unit
def test_settings_loader_from_json_rejects_non_object_payload(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text('["not", "an", "object"]')

    with pytest.raises(ValueError, match="JSON object"):
        SettingsLoader.from_json(str(config_path))


@pytest.mark.unit
def test_settings_loader_from_json_validates_positive_values(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"http_timeout": 0}))

    with pytest.raises(ValueError, match="http_timeout must be positive"):
        SettingsLoader.from_json(str(config_path))


@pytest.mark.unit
def test_settings_loader_from_json_validates_threshold_order(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "suspicious_threshold": 90,
                "malicious_threshold": 80,
            }
        )
    )

    with pytest.raises(
        ValueError,
        match="suspicious_threshold must be less than malicious_threshold",
    ):
        SettingsLoader.from_json(str(config_path))


@pytest.mark.unit
def test_settings_loader_mapped_kwargs_ignores_unsupported_value_types() -> None:
    mapped = SettingsLoader._mapped_kwargs(
        {
            "download_directory": ["not", "valid"],
            "http_timeout": {"bad": "type"},
            "http_max_retries": True,
            "http_retry_backoff_seconds": False,
            "verify_ssl": object(),
            "virustotal_api_key": True,
            "user_agent": False,
        },
        SettingsLoader.JSON_MAPPING,
    )

    assert mapped == {}


@pytest.mark.unit
def test_settings_loader_assign_helpers_return_false_for_non_matching_inputs() -> None:
    mapped = SettingsLoader._mapped_kwargs({}, SettingsLoader.JSON_MAPPING)

    assert SettingsLoader._assign_string(mapped, "unknown", "value") is False
    assert SettingsLoader._assign_int(mapped, "http_timeout", "10") is False
    assert SettingsLoader._assign_int(mapped, "http_max_retries", "10") is False
    assert SettingsLoader._assign_int(mapped, "http_timeout", True) is False
    assert SettingsLoader._assign_int(mapped, "unknown", 10) is False
    assert (
        SettingsLoader._assign_float(mapped, "http_retry_backoff_seconds", True)
        is False
    )
    assert SettingsLoader._assign_float(mapped, "unknown", 0.2) is False
    assert (
        SettingsLoader._assign_string_tuple(
            mapped,
            "user_agent_pool",
            cast(tuple[str, ...], ("ua-1", 2)),
        )
        is False
    )
    assert SettingsLoader._assign_bool(mapped, "verify_ssl", "true") is False
    assert SettingsLoader._assign_bool(mapped, "unknown", True) is False


@pytest.mark.unit
def test_settings_loader_assign_helpers_accept_supported_float_and_tuple_values() -> (
    None
):
    mapped = SettingsLoader._mapped_kwargs({}, SettingsLoader.JSON_MAPPING)

    assert (
        SettingsLoader._assign_float(
            mapped,
            "virustotal_timeout",
            1,
        )
        is True
    )
    assert mapped["virustotal_timeout"] == 1.0
    assert (
        SettingsLoader._assign_string_tuple(
            mapped,
            "user_agent_pool",
            ("ua-1", "ua-2"),
        )
        is True
    )

    assert mapped["user_agent_pool"] == ("ua-1", "ua-2")
    assert (
        SettingsLoader._assign_string_tuple(
            mapped,
            "user_agent_pool",
            None,
        )
        is True
    )
    assert mapped["user_agent_pool"] is None


@pytest.mark.unit
def test_settings_from_env_no_variables_set() -> None:
    """
    Test from_env when no environment variables are set.

    Purpose:
        Verify behavior when environment is empty.

    Expected Behavior:
        Returns Settings with all default values.
    """
    dll_keys = {key: None for key in os.environ if key.startswith("DLL_")}
    with _temporary_env(dll_keys):
        settings = SettingsLoader.from_env()

    assert settings.virustotal_api_key is None
    assert settings.http_timeout == 60
    assert settings.verify_ssl is True


# ============================================================================
# Settings from JSON Tests
# ============================================================================


@pytest.mark.unit
def test_settings_from_json_all_fields() -> None:
    """
    Test loading Settings from JSON file with all fields.

    Purpose:
        Verify JSON deserialization works correctly.

    Expected Behavior:
        All JSON fields are mapped to Settings attributes.
    """
    config_data = {
        "virustotal_api_key": "json_api_key",
        "download_directory": "/json/downloads",
        "download_base_url": "https://json.url",
        "http_timeout": 75,
        "http_max_retries": 9,
        "virustotal_timeout": 22.5,
        "http_retry_backoff_seconds": 0.2,
        "http_retry_jitter_seconds": 0.05,
        "verify_ssl": False,
        "user_agent": "JsonAgent/1.0",
        "user_agent_pool": ["Agent1", "Agent2"],
        "scan_before_save": False,
        "malicious_threshold": 12,
        "suspicious_threshold": 4,
        "log_level": "ERROR",
    }

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(config_data, f)
        temp_path = f.name

    try:
        with _mock_dns_resolution():
            settings = SettingsLoader.from_json(temp_path)

        assert settings.virustotal_api_key == "json_api_key"
        assert settings.download_directory == "/json/downloads"
        assert settings.download_base_url == "https://json.url"
        assert settings.http_timeout == 75
        assert settings.http_max_retries == 9
        assert settings.virustotal_timeout == 22.5
        assert settings.http_retry_backoff_seconds == 0.2
        assert settings.http_retry_jitter_seconds == 0.05
        assert settings.verify_ssl is False
        assert settings.user_agent == "JsonAgent/1.0"
        assert settings.user_agent_pool == ("Agent1", "Agent2")
        assert settings.scan_before_save is False
        assert settings.malicious_threshold == 12
        assert settings.suspicious_threshold == 4
        assert settings.log_level == "ERROR"
    finally:
        os.unlink(temp_path)


@pytest.mark.unit
def test_settings_from_json_rejects_non_string_sensitive_values(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "virustotal_api_key": True,
                "user_agent": False,
            }
        )
    )

    with pytest.raises(ValueError, match="Invalid value for virustotal_api_key"):
        SettingsLoader.from_json(str(config_path))


@pytest.mark.unit
def test_settings_from_json_accepts_null_user_agent_pool(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"user_agent_pool": None}))

    settings = SettingsLoader.from_json(str(config_path))

    assert settings.user_agent_pool is None


@pytest.mark.unit
def test_settings_from_json_rejects_fractional_integer_values(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "http_max_retries": 1.5,
                "malicious_threshold": 5.5,
            }
        )
    )

    with pytest.raises(ValueError, match="Invalid value for http_max_retries"):
        SettingsLoader.from_json(str(config_path))


@pytest.mark.unit
def test_settings_load_rejects_fractional_integer_values(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"http_max_retries": 1.5}))

    with pytest.raises(ValueError, match="Invalid value for http_max_retries"):
        SettingsLoader.load(config_path=str(config_path))


@pytest.mark.unit
def test_settings_from_json_partial_fields() -> None:
    """
    Test JSON loading with only some fields present.

    Purpose:
        Verify that missing fields use defaults.

    Expected Behavior:
        - Present fields override defaults
        - Missing fields use default values
    """
    config_data = {"virustotal_api_key": "partial_json_key", "http_timeout": 100}

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(config_data, f)
        temp_path = f.name

    try:
        settings = SettingsLoader.from_json(temp_path)

        assert settings.virustotal_api_key == "partial_json_key"
        assert settings.http_timeout == 100
        # Unspecified fields should use defaults
        assert settings.verify_ssl is True
        assert settings.malicious_threshold == 5
    finally:
        os.unlink(temp_path)


@pytest.mark.unit
def test_settings_from_json_nonexistent_file_raises_error() -> None:
    """
    Test loading from non-existent JSON file.

    Purpose:
        Verify proper error handling for missing files.

    Expected Behavior:
        OSError is raised (FileNotFoundError is a subclass).
    """
    with pytest.raises(OSError):
        SettingsLoader.from_json("/nonexistent/config.json")


@pytest.mark.unit
def test_settings_from_json_invalid_json_raises_error() -> None:
    """
    Test loading from malformed JSON file.

    Purpose:
        Verify error handling for invalid JSON.

    Expected Behavior:
        json.JSONDecodeError is raised.
    """
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        f.write("{invalid json content")
        temp_path = f.name

    try:
        with pytest.raises(json.JSONDecodeError):
            SettingsLoader.from_json(temp_path)
    finally:
        os.unlink(temp_path)


# ============================================================================
# Settings Merge Tests
# ============================================================================


@pytest.mark.unit
def test_settings_merge_override_values() -> None:
    """
    Test merging two Settings objects.

    Purpose:
        Verify that override values take precedence.

    Expected Behavior:
        Explicit override values replace base values.
    """
    base = Settings(virustotal_api_key="base_key", http_timeout=60)
    merged = SettingsLoader._merge(
        base,
        {
            "virustotal_api_key": "override_key",
            "malicious_threshold": 10,
        },
    )

    assert merged.virustotal_api_key == "override_key"
    assert merged.malicious_threshold == 10
    assert merged.http_timeout == 60  # From base


@pytest.mark.unit
def test_settings_merge_preserves_base_when_override_is_default() -> None:
    """
    Test that merge preserves base values when no override keys are present.

    Purpose:
        Verify that default values don't override explicit base values.

    Expected Behavior:
        Base values retained when override mapping is empty.
    """
    base = Settings(http_timeout=120, malicious_threshold=15)
    merged = SettingsLoader._merge(base, {})

    assert merged.http_timeout == 120
    assert merged.malicious_threshold == 15


@pytest.mark.unit
def test_settings_merge_handles_none_values() -> None:
    """
    Test merge behavior with None values.

    Purpose:
        Verify None handling in merge logic.

    Expected Behavior:
        None values in override don't override non-None base values.
    """
    base = Settings(virustotal_api_key="base_key")
    merged = SettingsLoader._merge(base, {"virustotal_api_key": None})

    assert merged.virustotal_api_key == "base_key"


# ============================================================================
# Settings Load with Priority Tests
# ============================================================================


@pytest.mark.unit
def test_settings_load_priority_env_over_file() -> None:
    """
    Test that environment variables override JSON config.

    Purpose:
        Verify configuration priority: env > file > defaults.

    Expected Behavior:
        Environment variables take precedence over file values.
    """
    # Create JSON config
    config_data = {"virustotal_api_key": "file_key", "http_timeout": 50}

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(config_data, f)
        temp_path = f.name

    try:
        with _temporary_env({"DLL_VIRUSTOTAL_API_KEY": "env_key"}):
            settings = SettingsLoader.load(config_path=temp_path)

        # Env should override file
        assert settings.virustotal_api_key == "env_key"
        # File value used when no env override
        assert settings.http_timeout == 50
    finally:
        os.unlink(temp_path)


@pytest.mark.unit
def test_settings_load_env_default_value_overrides_file_value() -> None:
    config_data = {
        "http_timeout": 10,
        "scan_before_save": False,
        "verify_ssl": False,
    }

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(config_data, f)
        temp_path = f.name

    try:
        with _temporary_env(
            {
                "DLL_HTTP_TIMEOUT": "60",
                "DLL_SCAN_BEFORE_SAVE": "true",
                "DLL_VERIFY_SSL": "true",
            }
        ):
            settings = SettingsLoader.load(config_path=temp_path)

        assert settings.http_timeout == 60
        assert settings.scan_before_save is True
        assert settings.verify_ssl is True
    finally:
        os.unlink(temp_path)


@pytest.mark.unit
def test_settings_load_validates_final_merged_settings(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"http_timeout": 0}))

    with pytest.raises(ValueError, match="http_timeout must be positive"):
        SettingsLoader.load(config_path=str(config_path))


@pytest.mark.unit
def test_settings_from_json_rejects_non_finite_float_values(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"virustotal_timeout": float("nan")}))

    with pytest.raises(ValueError, match="virustotal_timeout must be finite"):
        SettingsLoader.from_json(str(config_path))


@pytest.mark.unit
def test_settings_from_env_rejects_non_finite_float_values() -> None:
    with (
        _temporary_env({"DLL_VIRUSTOTAL_TIMEOUT": "nan"}),
        pytest.raises(
            ValueError,
            match="virustotal_timeout must be finite",
        ),
    ):
        SettingsLoader.from_env()


@pytest.mark.unit
def test_settings_validate_rejects_infinite_retry_backoff() -> None:
    settings = Settings(http_retry_backoff_seconds=float("inf"))

    with pytest.raises(ValueError, match="http_retry_backoff_seconds must be finite"):
        settings.validate()


@pytest.mark.unit
def test_settings_load_validates_threshold_relationship(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "suspicious_threshold": 10,
                "malicious_threshold": 5,
            }
        )
    )

    with pytest.raises(
        ValueError,
        match="suspicious_threshold must be less than malicious_threshold",
    ):
        SettingsLoader.load(config_path=str(config_path))


@pytest.mark.unit
def test_settings_load_validates_after_env_precedence(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"http_timeout": 0}))

    with _temporary_env({"DLL_HTTP_TIMEOUT": "60"}):
        settings = SettingsLoader.load(config_path=str(config_path))

    assert settings.http_timeout == 60


@pytest.mark.unit
def test_settings_load_explicit_unreadable_config_raises_error(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.mkdir()

    with pytest.raises(OSError, match="[Cc]onfiguration"):
        SettingsLoader.load(config_path=str(config_path))


@pytest.mark.unit
def test_settings_load_default_search_skips_non_regular_candidate(
    tmp_path: Path,
) -> None:
    (tmp_path / ".config.json").mkdir()
    (tmp_path / "config.json").write_text(json.dumps({"http_timeout": 123}))

    with _temporary_env({"HOME": str(tmp_path)}), _temporary_cwd(tmp_path):
        settings = SettingsLoader.load(config_path=None)

    assert settings.http_timeout == 123


@pytest.mark.unit
def test_settings_load_fifo_config_does_not_block(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO files are not supported on this platform")

    config_path = tmp_path / "config.json"
    os.mkfifo(config_path)
    code = (
        "from dll_downloader.infrastructure.config.loader import SettingsLoader\n"
        "import sys\n"
        "try:\n"
        f"    SettingsLoader.load(config_path={str(config_path)!r})\n"
        "except OSError:\n"
        "    print('failed-fast')\n"
        "    sys.exit(0)\n"
        "print('unexpected')\n"
        "sys.exit(1)\n"
    )

    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == "failed-fast"


@pytest.mark.unit
def test_settings_load_with_no_discovered_config_file() -> None:
    """
    Test loading with no config file specified.

    Purpose:
        Verify fallback to defaults when no file exists.

    Expected Behavior:
        Returns Settings with default values.
    """
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        _temporary_env({"HOME": temp_dir, "USERPROFILE": temp_dir}),
        _temporary_cwd(Path(temp_dir)),
    ):
        settings = SettingsLoader.load(config_path=None)

    # Should have default values (no file, no env)
    assert settings.http_timeout == 60
    assert settings.verify_ssl is True


@pytest.mark.unit
def test_settings_load_explicit_missing_config_raises_error() -> None:
    with pytest.raises(ValueError, match="Configuration file not found"):
        SettingsLoader.load(config_path="/nonexistent/config.json")


@pytest.mark.unit
def test_settings_load_vt_toml_key() -> None:
    """
    Test loading VirusTotal API key from ~/.vt.toml.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        with _temporary_env(
            {
                "HOME": temp_dir,
                "USERPROFILE": temp_dir,
                "DLL_VIRUSTOTAL_API_KEY": None,
            }
        ):
            vt_path = Path(temp_dir) / ".vt.toml"
            vt_path.write_text('apikey="vt_file_key"')

            with _temporary_cwd(Path(temp_dir)):
                settings = SettingsLoader.load(config_path=None)

        assert settings.virustotal_api_key == "vt_file_key"


@pytest.mark.unit
def test_settings_load_env_over_vt_toml() -> None:
    """
    Test that environment variable overrides ~/.vt.toml.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        with _temporary_env(
            {
                "HOME": temp_dir,
                "USERPROFILE": temp_dir,
                "DLL_VIRUSTOTAL_API_KEY": "env_key",
            }
        ):
            vt_path = Path(temp_dir) / ".vt.toml"
            vt_path.write_text('apikey="vt_file_key"')

            with _temporary_cwd(Path(temp_dir)):
                settings = SettingsLoader.load(config_path=None)

        assert settings.virustotal_api_key == "env_key"


@pytest.mark.unit
def test_settings_load_without_vt_toml() -> None:
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        _temporary_env(
            {
                "HOME": temp_dir,
                "USERPROFILE": temp_dir,
                "DLL_VIRUSTOTAL_API_KEY": None,
            }
        ),
        _temporary_cwd(Path(temp_dir)),
    ):
        settings = SettingsLoader.load(config_path=None)

    assert settings.virustotal_api_key is None


@pytest.mark.unit
def test_load_vt_toml_key_missing_file() -> None:
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        _temporary_env({"HOME": temp_dir, "USERPROFILE": temp_dir}),
    ):
        assert _VTTomlSettingsSource.load(temp_dir) is None


@pytest.mark.unit
def test_load_vt_toml_key_invalid_contents() -> None:
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        _temporary_env({"HOME": temp_dir, "USERPROFILE": temp_dir}),
    ):
        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.write_text("not_a_key=true")
        assert _VTTomlSettingsSource.load(temp_dir) is None


@pytest.mark.unit
def test_load_vt_toml_key_invalid_encoding_returns_none() -> None:
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        _temporary_env({"HOME": temp_dir, "USERPROFILE": temp_dir}),
    ):
        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.write_bytes(b"\xff\xfe\x00")
        assert _VTTomlSettingsSource.load(temp_dir) is None


@pytest.mark.unit
def test_load_vt_toml_key_ignores_commented_key() -> None:
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        _temporary_env({"HOME": temp_dir, "USERPROFILE": temp_dir}),
    ):
        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.write_text('# apikey = "commented-key"\n')
        assert _VTTomlSettingsSource.load(temp_dir) is None


@pytest.mark.unit
def test_load_vt_toml_key_accepts_active_key_with_comment() -> None:
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        _temporary_env({"HOME": temp_dir, "USERPROFILE": temp_dir}),
    ):
        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.write_text('apikey = "real-key" # active key\n')
        assert _VTTomlSettingsSource.load(temp_dir) == "real-key"


@pytest.mark.unit
def test_load_vt_toml_key_read_error() -> None:
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        _temporary_env({"HOME": temp_dir, "USERPROFILE": temp_dir}),
    ):
        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.mkdir()
        assert _VTTomlSettingsSource.load(temp_dir) is None


@pytest.mark.unit
def test_settings_load_config_over_vt_toml() -> None:
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        _temporary_env(
            {
                "HOME": temp_dir,
                "USERPROFILE": temp_dir,
                "DLL_VIRUSTOTAL_API_KEY": None,
            }
        ),
    ):
        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.write_text('apikey="vt_file_key"')

        config_data = {"virustotal_api_key": "file_key"}
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            settings = SettingsLoader.load(config_path=temp_path)
            assert settings.virustotal_api_key == "file_key"
        finally:
            os.unlink(temp_path)


@pytest.mark.unit
def test_settings_load_searches_default_locations() -> None:
    """
    Test that load() searches default config file locations.

    Purpose:
        Verify automatic discovery of config files.

    Expected Behavior:
        Checks .config.json, config.json, ~/.dll_downloader/config.json
    """
    # Create config in current directory
    config_data = {"http_timeout": 999}

    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / ".config.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        with _temporary_cwd(Path(temp_dir)):
            settings = SettingsLoader.load(config_path=None)
            # Should find .config.json in current directory
            assert settings.http_timeout == 999


@pytest.mark.unit
def test_settings_load_invalid_json_raises_error(tmp_download_dir: Path) -> None:
    """
    Verify Settings.load fails fast on invalid explicit JSON.
    """
    bad_config = tmp_download_dir / "bad_config.json"
    bad_config.write_text("{invalid json")

    with pytest.raises(json.JSONDecodeError):
        SettingsLoader.load(config_path=str(bad_config))


@pytest.mark.unit
def test_settings_load_discovered_invalid_json_raises_error(tmp_path: Path) -> None:
    (tmp_path / ".config.json").write_text("{invalid json")

    with (
        _temporary_env({"HOME": str(tmp_path)}),
        _temporary_cwd(tmp_path),
        pytest.raises(
            json.JSONDecodeError,
        ),
    ):
        SettingsLoader.load(config_path=None)


@pytest.mark.unit
def test_settings_load_invalid_encoding_raises_error(tmp_download_dir: Path) -> None:
    bad_config = tmp_download_dir / "bad_encoding.json"
    bad_config.write_bytes(b"\xff\xfe\x00")

    with pytest.raises(UnicodeDecodeError):
        SettingsLoader.load(config_path=str(bad_config))


@pytest.mark.unit
def test_settings_loader_finds_home_config_when_cwd_has_none() -> None:
    with (
        tempfile.TemporaryDirectory() as temp_home,
        tempfile.TemporaryDirectory() as temp_cwd,
    ):
        home_config_dir = Path(temp_home) / ".dll_downloader"
        home_config_dir.mkdir()
        (home_config_dir / "config.json").write_text(json.dumps({"http_timeout": 777}))

        with (
            _temporary_env({"HOME": temp_home, "USERPROFILE": temp_home}),
            _temporary_cwd(Path(temp_cwd)),
        ):
            settings = SettingsLoader.load(config_path=None)

        assert settings.http_timeout == 777


@pytest.mark.unit
def test_settings_loader_find_config_path_returns_none_when_defaults_missing() -> None:
    with (
        tempfile.TemporaryDirectory() as temp_home,
        tempfile.TemporaryDirectory() as temp_cwd,
        _temporary_env({"HOME": temp_home, "USERPROFILE": temp_home}),
        _temporary_cwd(Path(temp_cwd)),
    ):
        assert SettingsLoader._find_config_path() is None


# ============================================================================
# Settings Validation Tests
# ============================================================================


@pytest.mark.unit
def test_settings_validate_success() -> None:
    """
    Test validation with valid settings.

    Purpose:
        Verify that valid configuration passes validation.

    Expected Behavior:
        validate() returns True for valid settings.
    """
    settings = Settings(http_timeout=60, malicious_threshold=5, suspicious_threshold=1)

    result = settings.validate()

    assert result is True


@pytest.mark.unit
def test_settings_validate_negative_timeout_raises_error() -> None:
    """
    Test validation rejects negative timeout.

    Purpose:
        Verify timeout validation.

    Expected Behavior:
        ValueError is raised for non-positive timeout.
    """
    settings = Settings(http_timeout=0)

    with pytest.raises(ValueError, match="http_timeout must be positive"):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_negative_http_max_retries_raises_error() -> None:
    settings = Settings(http_max_retries=0)

    with pytest.raises(ValueError, match="http_max_retries must be positive"):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_negative_http_retry_backoff_raises_error() -> None:
    settings = Settings(http_retry_backoff_seconds=-0.1)

    with pytest.raises(
        ValueError,
        match="http_retry_backoff_seconds cannot be negative",
    ):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_negative_http_retry_jitter_raises_error() -> None:
    settings = Settings(http_retry_jitter_seconds=-0.1)

    with pytest.raises(
        ValueError,
        match="http_retry_jitter_seconds cannot be negative",
    ):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_negative_virustotal_timeout_raises_error() -> None:
    settings = Settings(virustotal_timeout=0)

    with pytest.raises(ValueError, match="virustotal_timeout must be positive"):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_empty_user_agent_pool_raises_error() -> None:
    settings = Settings(user_agent_pool=())

    with pytest.raises(
        ValueError, match="user_agent_pool must contain at least one value"
    ):
        settings.validate()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("settings", "field_name"),
    [
        (Settings(download_directory=""), "download_directory"),
        (Settings(download_directory="   "), "download_directory"),
        (Settings(download_base_url=""), "download_base_url"),
        (Settings(download_base_url="   "), "download_base_url"),
    ],
)
def test_settings_validate_rejects_blank_required_strings(
    settings: Settings,
    field_name: str,
) -> None:
    with pytest.raises(ValueError, match=f"{field_name} must be a non-empty string"):
        settings.validate()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("download_base_url", "message"),
    [
        ("https://user:pass@example.com", "must not include credentials"),
        ("https://user@example.com", "must not include credentials"),
        ("https://example.com:bad", "must have a valid port"),
        ("https://example.com:99999", "must have a valid port"),
    ],
)
def test_settings_validate_rejects_unsafe_download_base_url_authority(
    download_base_url: str,
    message: str,
) -> None:
    settings = Settings(download_base_url=download_base_url)

    with _mock_dns_resolution(), pytest.raises(ValueError, match=message):
        settings.validate()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("settings", "field_name"),
    [
        (Settings(virustotal_api_key=""), "virustotal_api_key"),
        (Settings(virustotal_api_key="   "), "virustotal_api_key"),
        (Settings(user_agent=""), "user_agent"),
        (Settings(user_agent="   "), "user_agent"),
    ],
)
def test_settings_validate_rejects_blank_optional_strings(
    settings: Settings,
    field_name: str,
) -> None:
    with pytest.raises(ValueError, match=f"{field_name} must be a non-empty string"):
        settings.validate()


@pytest.mark.unit
@pytest.mark.parametrize(
    "field_name",
    [
        "download_directory",
        "download_base_url",
        "virustotal_api_key",
        "user_agent",
    ],
)
def test_settings_from_json_rejects_blank_string_values(
    tmp_path: Path,
    field_name: str,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({field_name: ""}))

    with pytest.raises(ValueError, match=f"{field_name} must be a non-empty string"):
        SettingsLoader.from_json(str(config_path))


@pytest.mark.unit
def test_settings_validate_rejects_unknown_log_level() -> None:
    settings = Settings(log_level="DEBIG")

    with pytest.raises(ValueError, match="log_level must be one of"):
        settings.validate()


@pytest.mark.unit
def test_settings_loader_rejects_unknown_json_log_level() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "config.json"
        config_path.write_text(json.dumps({"log_level": "DEBIG"}))

        with pytest.raises(ValueError, match="log_level must be one of"):
            SettingsLoader.from_json(str(config_path))


@pytest.mark.unit
def test_settings_validate_rejects_string_boolean_fields() -> None:
    verify_ssl_settings = Settings(verify_ssl=cast(bool, "false"))
    scan_settings = Settings(scan_before_save=cast(bool, "false"))

    with pytest.raises(ValueError, match="verify_ssl must be a boolean"):
        verify_ssl_settings.validate()
    with pytest.raises(ValueError, match="scan_before_save must be a boolean"):
        scan_settings.validate()


@pytest.mark.unit
def test_settings_validate_rejects_non_empty_user_agent_pool_with_empty_item() -> None:
    settings = Settings(user_agent_pool=("",))

    with pytest.raises(
        ValueError,
        match="user_agent_pool must contain non-empty string values",
    ):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_rejects_boolean_numeric_fields() -> None:
    settings = Settings(http_timeout=cast(int, True))

    with pytest.raises(ValueError, match="http_timeout must be a number"):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_rejects_fractional_integer_fields() -> None:
    retry_settings = Settings(http_max_retries=cast(int, 1.5))
    threshold_settings = Settings(malicious_threshold=cast(int, 5.5))

    with pytest.raises(ValueError, match="http_max_retries must be an integer"):
        retry_settings.validate()
    with pytest.raises(ValueError, match="malicious_threshold must be an integer"):
        threshold_settings.validate()


@pytest.mark.unit
def test_settings_validate_negative_malicious_threshold_raises_error() -> None:
    """
    Test validation rejects invalid malicious threshold.

    Purpose:
        Verify malicious threshold validation.

    Expected Behavior:
        ValueError is raised for non-positive threshold.
    """
    settings = Settings(malicious_threshold=0)

    with pytest.raises(ValueError, match="malicious_threshold must be positive"):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_negative_suspicious_threshold_raises_error() -> None:
    """
    Test validation rejects invalid suspicious threshold.

    Purpose:
        Verify suspicious threshold validation.

    Expected Behavior:
        ValueError is raised for non-positive threshold.
    """
    settings = Settings(suspicious_threshold=-1)

    with pytest.raises(ValueError, match="suspicious_threshold must be positive"):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_threshold_relationship() -> None:
    """
    Test validation of threshold ordering.

    Purpose:
        Verify that suspicious_threshold < malicious_threshold.

    Expected Behavior:
        ValueError when suspicious >= malicious.
    """
    settings = Settings(suspicious_threshold=10, malicious_threshold=5)

    with pytest.raises(
        ValueError, match="suspicious_threshold must be less than malicious_threshold"
    ):
        settings.validate()


# ============================================================================
# Settings Properties Tests
# ============================================================================


@pytest.mark.unit
def test_settings_downloads_path_property() -> None:
    """
    Test downloads_path property converts string to Path.

    Purpose:
        Verify Path object creation from directory string.

    Expected Behavior:
        - Returns Path object
        - Path ends with expected components
    """
    settings = Settings(download_directory="/tmp/downloads")

    path = settings.downloads_path

    assert isinstance(path, Path)
    # Use endswith to handle macOS /private/tmp symlink
    assert path.as_posix().endswith("tmp/downloads")


@pytest.mark.unit
def test_settings_downloads_path_expands_user() -> None:
    """
    Test that downloads_path expands ~ to home directory.

    Purpose:
        Verify tilde expansion in paths.

    Expected Behavior:
        ~ is expanded to actual home directory.
    """
    settings = Settings(download_directory="~/my_downloads")

    path = settings.downloads_path

    assert "~" not in str(path)
    assert str(path).startswith(str(Path.home()))


# ============================================================================
# Settings.validate() type and SSRF branch coverage
# ============================================================================


@contextmanager
def _dns_returns(addresses: list[str]) -> Iterator[None]:
    """Patch getaddrinfo so any hostname resolves to the given IP strings."""
    original_getaddrinfo = socket.getaddrinfo

    def _patched_getaddrinfo(
        host: str | bytes | None,
        port: bytes | str | int | None,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[Any, ...]]:
        if isinstance(host, str) and not _is_ip_address(host):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    (addr, port),
                )
                for addr in addresses
            ]
        return original_getaddrinfo(host, port, family, type, proto, flags)

    socket.getaddrinfo = cast(Any, _patched_getaddrinfo)
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo


@pytest.mark.unit
def test_settings_validate_rejects_non_string_download_directory() -> None:
    settings = Settings(download_directory=cast(str, 123))

    with pytest.raises(ValueError, match="download_directory must be a string"):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_rejects_non_https_download_base_url() -> None:
    settings = Settings(download_base_url="http://example.com")

    with pytest.raises(ValueError, match="download_base_url must use HTTPS"):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_rejects_download_base_url_without_hostname() -> None:
    settings = Settings(download_base_url="https:///path")

    with pytest.raises(
        ValueError, match="download_base_url must have a valid hostname"
    ):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_rejects_private_ip_literal_download_base_url() -> None:
    settings = Settings(download_base_url="https://127.0.0.1")

    with pytest.raises(ValueError, match="must not point to a private"):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_rejects_download_base_url_resolving_to_private() -> None:
    settings = Settings(download_base_url="https://example.com")

    with _dns_returns(["10.0.0.1"]), pytest.raises(
        ValueError, match="must not resolve to a private"
    ):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_skips_unparseable_resolved_addresses() -> None:
    settings = Settings(download_base_url="https://example.com")

    with _dns_returns(["not-an-ip-address"]):
        assert settings.validate() is True


@pytest.mark.unit
def test_settings_validate_rejects_unresolvable_download_base_url() -> None:
    settings = Settings(download_base_url="https://does-not-exist.invalid")

    with pytest.raises(ValueError, match="hostname does not resolve"):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_rejects_non_string_log_level() -> None:
    settings = Settings(log_level=cast(str, 123))

    with _mock_dns_resolution(), pytest.raises(
        ValueError, match="log_level must be a string"
    ):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_rejects_non_string_user_agent() -> None:
    settings = Settings(user_agent=cast("str | None", 123))

    with _mock_dns_resolution(), pytest.raises(
        ValueError, match="user_agent must be a string or null"
    ):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_rejects_non_tuple_user_agent_pool() -> None:
    settings = Settings(user_agent_pool=cast("tuple[str, ...] | None", ["a"]))

    with _mock_dns_resolution(), pytest.raises(
        ValueError, match="user_agent_pool must be a tuple of strings"
    ):
        settings.validate()


@pytest.mark.unit
def test_settings_validate_accepts_public_ip_literal_download_base_url() -> None:
    settings = Settings(download_base_url=f"https://{_PUBLIC_IP}")

    assert settings.validate() is True


# ============================================================================
# SettingsLoader source branch coverage
# ============================================================================


@contextmanager
def _set_blocking_raises() -> Iterator[None]:
    """Force os.set_blocking to fail, exercising fd-cleanup finally blocks."""
    original_set_blocking = os.set_blocking

    def _boom(fd: int, blocking: bool) -> None:
        raise OSError("simulated set_blocking failure")

    os.set_blocking = cast(Any, _boom)
    try:
        yield
    finally:
        os.set_blocking = original_set_blocking


@pytest.mark.unit
def test_settings_loader_from_json_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real-config.json"
    target.write_text(json.dumps({"log_level": "DEBUG"}))
    link = tmp_path / "config.json"
    link.symlink_to(target)

    with pytest.raises(
        OSError, match="Refusing to read configuration from symlink"
    ):
        SettingsLoader.from_json(str(link))


@pytest.mark.unit
def test_settings_from_env_rejects_invalid_integer() -> None:
    with (
        _temporary_env({"DLL_HTTP_TIMEOUT": "not-an-int"}),
        pytest.raises(ValueError, match="must be an integer"),
    ):
        SettingsLoader.from_env()


@pytest.mark.unit
def test_settings_from_env_rejects_invalid_float() -> None:
    with (
        _temporary_env({"DLL_VIRUSTOTAL_TIMEOUT": "not-a-float"}),
        pytest.raises(ValueError, match="must be a float"),
    ):
        SettingsLoader.from_env()


@pytest.mark.unit
def test_settings_from_json_accepts_integral_float_for_int_field(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"http_timeout": 90.0}))

    settings = SettingsLoader.from_json(str(config_path))

    assert settings.http_timeout == 90
    assert isinstance(settings.http_timeout, int)


@pytest.mark.unit
def test_settings_loader_skips_symlink_config_path(tmp_path: Path) -> None:
    target = tmp_path / "real-config.json"
    target.write_text(json.dumps({"log_level": "DEBUG"}))
    (tmp_path / "config.json").symlink_to(target)

    with (
        _temporary_env({"HOME": str(tmp_path), "DLL_VIRUSTOTAL_API_KEY": None}),
        _temporary_cwd(tmp_path),
        _mock_dns_resolution(),
    ):
        settings = SettingsLoader.load(config_path=None)

    assert settings.log_level == "INFO"


@pytest.mark.unit
def test_settings_loader_from_json_closes_fd_when_set_blocking_fails(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"log_level": "DEBUG"}))

    with _set_blocking_raises(), pytest.raises(OSError):
        SettingsLoader.from_json(str(config_path))


@pytest.mark.unit
def test_settings_loader_vt_toml_closes_fd_when_set_blocking_fails(
    tmp_path: Path,
) -> None:
    vt_file = tmp_path / ".vt.toml"
    vt_file.write_text("apikey = 'vt-test-key'")

    with _set_blocking_raises():
        assert _VTTomlSettingsSource.load(str(tmp_path)) is None
