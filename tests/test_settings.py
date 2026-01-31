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
import tempfile
from pathlib import Path

import pytest

from dll_downloader.infrastructure.config.settings import Settings

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
        verify_ssl=False,
        user_agent="CustomAgent/1.0",
        scan_before_save=False,
        malicious_threshold=10,
        suspicious_threshold=3,
        log_level="DEBUG"
    )

    assert settings.virustotal_api_key == "my_api_key"
    assert settings.download_directory == "/custom/path"
    assert settings.download_base_url == "https://custom.url"
    assert settings.http_timeout == 30
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
def test_settings_from_env_all_variables(monkeypatch) -> None:
    """
    Test loading Settings from environment variables.

    Purpose:
        Verify that all environment variables are correctly mapped.

    Expected Behavior:
        Environment variables override defaults with correct types.
    """
    monkeypatch.setenv("DLL_VIRUSTOTAL_API_KEY", "env_api_key")
    monkeypatch.setenv("DLL_DOWNLOAD_DIRECTORY", "/env/downloads")
    monkeypatch.setenv("DLL_DOWNLOAD_BASE_URL", "https://env.url")
    monkeypatch.setenv("DLL_HTTP_TIMEOUT", "45")
    monkeypatch.setenv("DLL_VERIFY_SSL", "false")
    monkeypatch.setenv("DLL_SCAN_BEFORE_SAVE", "no")
    monkeypatch.setenv("DLL_MALICIOUS_THRESHOLD", "8")
    monkeypatch.setenv("DLL_SUSPICIOUS_THRESHOLD", "2")
    monkeypatch.setenv("DLL_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("DLL_USER_AGENT", "EnvAgent/1.0")

    settings = Settings.from_env()

    assert settings.virustotal_api_key == "env_api_key"
    assert settings.download_directory == "/env/downloads"
    assert settings.download_base_url == "https://env.url"
    assert settings.http_timeout == 45
    assert settings.verify_ssl is False
    assert settings.scan_before_save is False
    assert settings.malicious_threshold == 8
    assert settings.suspicious_threshold == 2
    assert settings.log_level == "WARNING"
    assert settings.user_agent == "EnvAgent/1.0"


@pytest.mark.unit
def test_settings_from_env_partial_variables(monkeypatch) -> None:
    """
    Test loading with only some environment variables set.

    Purpose:
        Verify that unset variables use defaults.

    Expected Behavior:
        - Set variables override defaults
        - Unset variables use default values
    """
    monkeypatch.setenv("DLL_VIRUSTOTAL_API_KEY", "partial_key")
    monkeypatch.setenv("DLL_HTTP_TIMEOUT", "90")

    settings = Settings.from_env()

    assert settings.virustotal_api_key == "partial_key"
    assert settings.http_timeout == 90
    # Unset values should use defaults
    assert settings.download_directory == str(Path.cwd() / "downloads")
    assert settings.verify_ssl is True


@pytest.mark.unit
def test_settings_from_env_boolean_parsing(monkeypatch) -> None:
    """
    Test boolean value parsing from environment.

    Purpose:
        Verify that various boolean representations are handled correctly.

    Expected Behavior:
        'true', '1', 'yes' -> True; other values -> False
    """
    # Test True values
    for true_value in ["true", "True", "TRUE", "1", "yes", "Yes"]:
        monkeypatch.setenv("DLL_VERIFY_SSL", true_value)
        settings = Settings.from_env()
        assert settings.verify_ssl is True, f"Failed for value: {true_value}"

    # Test False values
    for false_value in ["false", "False", "0", "no", "anything"]:
        monkeypatch.setenv("DLL_VERIFY_SSL", false_value)
        settings = Settings.from_env()
        assert settings.verify_ssl is False, f"Failed for value: {false_value}"


@pytest.mark.unit
def test_settings_from_env_integer_parsing(monkeypatch) -> None:
    """
    Test integer value parsing from environment.

    Purpose:
        Verify that string numbers are converted to integers.

    Expected Behavior:
        Numeric strings are converted to int type.
    """
    monkeypatch.setenv("DLL_HTTP_TIMEOUT", "120")
    monkeypatch.setenv("DLL_MALICIOUS_THRESHOLD", "15")
    monkeypatch.setenv("DLL_SUSPICIOUS_THRESHOLD", "5")

    settings = Settings.from_env()

    assert settings.http_timeout == 120
    assert isinstance(settings.http_timeout, int)
    assert settings.malicious_threshold == 15
    assert isinstance(settings.malicious_threshold, int)
    assert settings.suspicious_threshold == 5
    assert isinstance(settings.suspicious_threshold, int)


@pytest.mark.unit
def test_settings_from_env_no_variables_set() -> None:
    """
    Test from_env when no environment variables are set.

    Purpose:
        Verify behavior when environment is empty.

    Expected Behavior:
        Returns Settings with all default values.
    """
    # Ensure no DLL_ variables are set
    for key in list(os.environ.keys()):
        if key.startswith("DLL_"):
            del os.environ[key]

    settings = Settings.from_env()

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
        "verify_ssl": False,
        "user_agent": "JsonAgent/1.0",
        "scan_before_save": False,
        "malicious_threshold": 12,
        "suspicious_threshold": 4,
        "log_level": "ERROR"
    }

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(config_data, f)
        temp_path = f.name

    try:
        settings = Settings.from_json(temp_path)

        assert settings.virustotal_api_key == "json_api_key"
        assert settings.download_directory == "/json/downloads"
        assert settings.download_base_url == "https://json.url"
        assert settings.http_timeout == 75
        assert settings.verify_ssl is False
        assert settings.user_agent == "JsonAgent/1.0"
        assert settings.scan_before_save is False
        assert settings.malicious_threshold == 12
        assert settings.suspicious_threshold == 4
        assert settings.log_level == "ERROR"
    finally:
        os.unlink(temp_path)


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
    config_data = {
        "virustotal_api_key": "partial_json_key",
        "http_timeout": 100
    }

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(config_data, f)
        temp_path = f.name

    try:
        settings = Settings.from_json(temp_path)

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
        FileNotFoundError is raised.
    """
    with pytest.raises(FileNotFoundError):
        Settings.from_json("/nonexistent/config.json")


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
            Settings.from_json(temp_path)
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
        Non-default values from override replace base values.
    """
    base = Settings(
        virustotal_api_key="base_key",
        http_timeout=60
    )
    override = Settings(
        virustotal_api_key="override_key",
        malicious_threshold=10
    )

    merged = Settings._merge(base, override)

    assert merged.virustotal_api_key == "override_key"
    assert merged.malicious_threshold == 10
    assert merged.http_timeout == 60  # From base


@pytest.mark.unit
def test_settings_merge_preserves_base_when_override_is_default() -> None:
    """
    Test that merge preserves base values when override has defaults.

    Purpose:
        Verify that default values don't override explicit base values.

    Expected Behavior:
        Base values retained when override values are defaults.
    """
    base = Settings(
        http_timeout=120,
        malicious_threshold=15
    )
    override = Settings()  # All defaults

    merged = Settings._merge(base, override)

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
    override = Settings(virustotal_api_key=None)

    merged = Settings._merge(base, override)

    assert merged.virustotal_api_key == "base_key"


# ============================================================================
# Settings Load with Priority Tests
# ============================================================================

@pytest.mark.unit
def test_settings_load_priority_env_over_file(monkeypatch) -> None:
    """
    Test that environment variables override JSON config.

    Purpose:
        Verify configuration priority: env > file > defaults.

    Expected Behavior:
        Environment variables take precedence over file values.
    """
    # Create JSON config
    config_data = {
        "virustotal_api_key": "file_key",
        "http_timeout": 50
    }

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(config_data, f)
        temp_path = f.name

    try:
        # Set environment variable
        monkeypatch.setenv("DLL_VIRUSTOTAL_API_KEY", "env_key")

        settings = Settings.load(config_path=temp_path)

        # Env should override file
        assert settings.virustotal_api_key == "env_key"
        # File value used when no env override
        assert settings.http_timeout == 50
    finally:
        os.unlink(temp_path)


@pytest.mark.unit
def test_settings_load_with_no_config_file() -> None:
    """
    Test loading with no config file specified.

    Purpose:
        Verify fallback to defaults when no file exists.

    Expected Behavior:
        Returns Settings with default values.
    """
    settings = Settings.load(config_path="/nonexistent/config.json")

    # Should have default values (no file, no env)
    assert settings.http_timeout == 60
    assert settings.verify_ssl is True


@pytest.mark.unit
def test_settings_load_vt_toml_key(monkeypatch) -> None:
    """
    Test loading VirusTotal API key from ~/.vt.toml.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        monkeypatch.setenv("HOME", temp_dir)
        monkeypatch.setenv("USERPROFILE", temp_dir)
        monkeypatch.delenv("DLL_VIRUSTOTAL_API_KEY", raising=False)

        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.write_text('apikey="vt_file_key"')

        settings = Settings.load(config_path="/nonexistent/config.json")

        assert settings.virustotal_api_key == "vt_file_key"


@pytest.mark.unit
def test_settings_load_env_over_vt_toml(monkeypatch) -> None:
    """
    Test that environment variable overrides ~/.vt.toml.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        monkeypatch.setenv("HOME", temp_dir)
        monkeypatch.setenv("USERPROFILE", temp_dir)
        monkeypatch.setenv("DLL_VIRUSTOTAL_API_KEY", "env_key")

        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.write_text('apikey="vt_file_key"')

        settings = Settings.load(config_path="/nonexistent/config.json")

        assert settings.virustotal_api_key == "env_key"


@pytest.mark.unit
def test_settings_load_without_vt_toml(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        monkeypatch.setenv("HOME", temp_dir)
        monkeypatch.setenv("USERPROFILE", temp_dir)
        monkeypatch.delenv("DLL_VIRUSTOTAL_API_KEY", raising=False)

        settings = Settings.load(config_path="/nonexistent/config.json")

        assert settings.virustotal_api_key is None


@pytest.mark.unit
def test_load_vt_toml_key_missing_file(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        monkeypatch.setenv("HOME", temp_dir)
        monkeypatch.setenv("USERPROFILE", temp_dir)
        assert Settings._load_vt_toml_key() is None


@pytest.mark.unit
def test_load_vt_toml_key_invalid_contents(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        monkeypatch.setenv("HOME", temp_dir)
        monkeypatch.setenv("USERPROFILE", temp_dir)
        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.write_text("not_a_key=true")
        assert Settings._load_vt_toml_key() is None


@pytest.mark.unit
def test_load_vt_toml_key_read_error(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        monkeypatch.setenv("HOME", temp_dir)
        monkeypatch.setenv("USERPROFILE", temp_dir)
        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.write_text('apikey="vt_file_key"')

        original_read = Path.read_text

        def _raise(*_args, **_kwargs):
            raise OSError("read error")

        monkeypatch.setattr(Path, "read_text", _raise)
        try:
            assert Settings._load_vt_toml_key() is None
        finally:
            monkeypatch.setattr(Path, "read_text", original_read)


@pytest.mark.unit
def test_settings_load_config_over_vt_toml(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        monkeypatch.setenv("HOME", temp_dir)
        monkeypatch.setenv("USERPROFILE", temp_dir)
        monkeypatch.delenv("DLL_VIRUSTOTAL_API_KEY", raising=False)

        vt_path = Path(temp_dir) / ".vt.toml"
        vt_path.write_text('apikey="vt_file_key"')

        config_data = {"virustotal_api_key": "file_key"}
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            settings = Settings.load(config_path=temp_path)
            assert settings.virustotal_api_key == "file_key"
        finally:
            os.unlink(temp_path)


@pytest.mark.unit
def test_settings_load_searches_default_locations(monkeypatch) -> None:
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

        original_cwd = Path.cwd()
        try:
            monkeypatch.chdir(temp_dir)
            settings = Settings.load(config_path=None)
            # Should find .config.json in current directory
            assert settings.http_timeout == 999
        finally:
            monkeypatch.chdir(original_cwd)


@pytest.mark.unit
def test_settings_load_invalid_json_logs_warning(tmp_download_dir, caplog) -> None:
    """
    Verify Settings.load logs warning on invalid JSON and returns defaults.
    """
    bad_config = tmp_download_dir / "bad_config.json"
    bad_config.write_text("{invalid json")

    with caplog.at_level("WARNING"):
        settings = Settings.load(config_path=str(bad_config))

    assert "Failed to load config" in caplog.text
    assert settings.download_directory == Settings().download_directory


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
    settings = Settings(
        http_timeout=60,
        malicious_threshold=5,
        suspicious_threshold=1
    )

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
    settings = Settings(
        suspicious_threshold=10,
        malicious_threshold=5
    )

    with pytest.raises(ValueError, match="suspicious_threshold must be less than malicious_threshold"):
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
