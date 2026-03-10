import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from dll_downloader.api import API_VERSION, Settings
from dll_downloader.runtime import load_settings


@contextmanager
def _temporary_cwd(path: Path) -> Iterator[None]:
    original = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(original)


@pytest.mark.unit
def test_load_settings_uses_current_public_loader_contract(tmp_path: Path) -> None:
    config_path = tmp_path / ".config.json"
    expected_dir = tmp_path / "api-downloads"
    config_path.write_text(json.dumps({"download_directory": str(expected_dir)}))

    with _temporary_cwd(tmp_path):
        loaded = load_settings()

    assert isinstance(loaded, Settings)
    assert loaded.download_directory == str(expected_dir)


@pytest.mark.unit
def test_public_api_version_is_frozen_for_current_major_line() -> None:
    assert API_VERSION == "1"
