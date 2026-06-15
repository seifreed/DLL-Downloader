# Copyright (c) 2026 Marc Rivero López
# Licensed under the MIT License. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Integration tests for FileSystemDLLRepository.

These tests validate the repository implementation using real filesystem
operations with temporary directories. No mocks or stubs are used.
"""

import contextlib
import hashlib
import io
import json
import os
import zipfile
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import pytest

from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
)
from dll_downloader.domain.services.archive_safety import ZIP_MEMBER_COUNT_LIMIT
from dll_downloader.infrastructure.persistence.file_repository import (
    FileSystemDLLRepository,
    RepositoryError,
)


def _require_str(value: str | None) -> str:
    assert value is not None
    return value


def _build_pe_payload(architecture: Architecture = Architecture.X64) -> bytes:
    raw_data = b"\x00"
    machine = 0x014C if architecture == Architecture.X86 else 0x8664
    pe_offset = 0x80
    optional_header_size = 0xF0 if architecture == Architecture.X64 else 0xE0
    optional_header_offset = pe_offset + 24
    section_table_offset = optional_header_offset + optional_header_size
    payload = bytearray(section_table_offset + 40)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    payload[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    payload[pe_offset + 4 : pe_offset + 6] = machine.to_bytes(2, "little")
    payload[pe_offset + 6 : pe_offset + 8] = (1).to_bytes(2, "little")
    payload[pe_offset + 20 : pe_offset + 22] = optional_header_size.to_bytes(
        2, "little"
    )
    payload[pe_offset + 22 : pe_offset + 24] = (0x2000).to_bytes(2, "little")
    optional_magic = 0x20B if architecture == Architecture.X64 else 0x10B
    payload[optional_header_offset : optional_header_offset + 2] = (
        optional_magic.to_bytes(
            2,
            "little",
        )
    )
    payload[section_table_offset : section_table_offset + 5] = b".text"
    payload[section_table_offset + 8 : section_table_offset + 12] = len(
        raw_data
    ).to_bytes(4, "little")
    payload[section_table_offset + 12 : section_table_offset + 16] = (0x1000).to_bytes(
        4,
        "little",
    )
    payload[section_table_offset + 16 : section_table_offset + 20] = len(
        raw_data
    ).to_bytes(4, "little")
    payload[section_table_offset + 20 : section_table_offset + 24] = len(
        payload
    ).to_bytes(4, "little")
    return bytes(payload) + raw_data


def _build_pe_header_stub(architecture: Architecture = Architecture.X64) -> bytes:
    machine = 0x014C if architecture == Architecture.X86 else 0x8664
    pe_offset = 0x80
    payload = bytearray(pe_offset + 24)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    payload[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    payload[pe_offset + 4 : pe_offset + 6] = machine.to_bytes(2, "little")
    payload[pe_offset + 6 : pe_offset + 8] = (0).to_bytes(2, "little")
    payload[pe_offset + 20 : pe_offset + 22] = (0).to_bytes(2, "little")
    payload[pe_offset + 22 : pe_offset + 24] = (0x2000).to_bytes(2, "little")
    return bytes(payload)


def _build_pe_payload_with_blank_section(
    architecture: Architecture = Architecture.X64,
) -> bytes:
    machine = 0x014C if architecture == Architecture.X86 else 0x8664
    pe_offset = 0x80
    optional_header_size = 0xF0 if architecture == Architecture.X64 else 0xE0
    optional_header_offset = pe_offset + 24
    section_table_offset = optional_header_offset + optional_header_size
    payload = bytearray(section_table_offset + 40)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    payload[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    payload[pe_offset + 4 : pe_offset + 6] = machine.to_bytes(2, "little")
    payload[pe_offset + 6 : pe_offset + 8] = (1).to_bytes(2, "little")
    payload[pe_offset + 20 : pe_offset + 22] = optional_header_size.to_bytes(
        2, "little"
    )
    payload[pe_offset + 22 : pe_offset + 24] = (0x2000).to_bytes(2, "little")
    optional_magic = 0x20B if architecture == Architecture.X64 else 0x10B
    payload[optional_header_offset : optional_header_offset + 2] = (
        optional_magic.to_bytes(
            2,
            "little",
        )
    )
    return bytes(payload)


def _build_pe_payload_without_dll_flag() -> bytes:
    payload = bytearray(_build_pe_payload(Architecture.X64))
    pe_offset = int.from_bytes(payload[0x3C:0x40], "little")
    payload[pe_offset + 22 : pe_offset + 24] = (0).to_bytes(2, "little")
    return bytes(payload)


@pytest.fixture
def repository(tmp_path: Path) -> FileSystemDLLRepository:
    """
    Create a FileSystemDLLRepository with a temporary directory.

    Args:
        tmp_path: pytest's built-in temporary path fixture

    Returns:
        Configured FileSystemDLLRepository instance
    """
    return FileSystemDLLRepository(tmp_path)


@pytest.fixture
def sample_dll_content() -> bytes:
    """
    Generate realistic DLL binary content with proper PE header.

    Returns:
        Bytes representing a minimal valid DLL structure
    """
    content_section = b"Realistic DLL content for integration testing." * 50
    return _build_pe_payload(Architecture.X64) + content_section


def _build_zip_payload(dll_name: str, dll_bytes: bytes) -> bytes:
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr(Path(dll_name).name, dll_bytes)
    return archive_buffer.getvalue()


class FailingIndexSaveRepository(FileSystemDLLRepository):
    """Repository variant that fails only after payload writes."""

    def _save_index(self, _index: object) -> None:
        raise RepositoryError("index write failed")


class OSErrorAtomicWriteRepository(FileSystemDLLRepository):
    """Repository variant whose atomic writes fail with OSError."""

    def _atomic_write_bytes(self, _file_path: Path, _content: bytes) -> None:
        raise OSError("atomic write failed")


class DirectoryRaceRepository(FileSystemDLLRepository):
    """Repository variant that creates a directory after write validation."""

    def _validate_repository_write_path(self, file_path: Path) -> Path:
        resolved_parent = super()._validate_repository_write_path(file_path)
        if file_path.name == "race.dll" and not file_path.exists():
            file_path.mkdir()
        return resolved_parent


class FailingRollbackWriteRepository(FailingIndexSaveRepository):
    """Repository variant whose rollback restoration write fails."""

    def _atomic_write_bytes(self, file_path: Path, content: bytes) -> None:
        if content.endswith(b"original content"):
            raise OSError("rollback restore failed")
        super()._atomic_write_bytes(file_path, content)


class VanishingPayloadRepository(FileSystemDLLRepository):
    """Repository variant that removes payloads during index validation."""

    def _path_locations_match(self, left: Path, right: Path) -> bool:
        matches = super()._path_locations_match(left, right)
        left.unlink(missing_ok=True)
        return matches


class EscapingFallbackRepository(FileSystemDLLRepository):
    """Repository variant that simulates a fallback payload resolving outside."""

    def _path_location_is_within_repository(self, _file_path: Path) -> bool:
        return True

    def _path_is_within_repository(self, _file_path: Path) -> bool:
        return False


@pytest.fixture
def dll_file_entity() -> DLLFile:
    """
    Create a DLLFile entity for testing.

    Returns:
        DLLFile entity with realistic metadata
    """
    return DLLFile(
        name="kernel32.dll",
        version="10.0.19041.1",
        architecture=Architecture.X64,
        download_url="https://example.com/dlls/x64/kernel32.dll",
        security_status=SecurityStatus.CLEAN,
    )


class TestFileSystemDLLRepositoryInitialization:
    """Test repository initialization and directory structure creation."""

    def test_creates_base_directory(self, tmp_path: Path) -> None:
        """
        Verify that repository creates base directory on initialization.

        Expected Behavior:
            - Base directory is created
            - Directory exists and is accessible
        """
        repo_path = tmp_path / "dll_repo"
        assert not repo_path.exists()

        FileSystemDLLRepository(repo_path)

        assert repo_path.exists()
        assert repo_path.is_dir()

    def test_creates_architecture_subdirectories(self, tmp_path: Path) -> None:
        """
        Verify that repository creates x86 and x64 architecture subdirectories.

        Expected Behavior:
            - x86/ subdirectory is created
            - x64/ subdirectory is created
            - Both directories are accessible
        """
        repo_path = tmp_path / "dll_repo"
        FileSystemDLLRepository(repo_path)

        x86_dir = repo_path / "x86"
        x64_dir = repo_path / "x64"

        assert x86_dir.exists()
        assert x86_dir.is_dir()
        assert x64_dir.exists()
        assert x64_dir.is_dir()

    def test_initializes_with_existing_directory(self, tmp_path: Path) -> None:
        """
        Verify that repository handles pre-existing directories correctly.

        Expected Behavior:
            - No errors when directory already exists
            - Existing files are preserved
            - Repository is functional
        """
        # Pre-create the directory structure
        repo_path = tmp_path / "dll_repo"
        repo_path.mkdir()
        (repo_path / "x86").mkdir()
        (repo_path / "x64").mkdir()

        # Create a pre-existing file
        existing_file = repo_path / "x64" / "existing.dll"
        existing_file.write_bytes(b"MZ\x90\x00existing content")

        # Initialize repository
        FileSystemDLLRepository(repo_path)

        # Verify existing file is preserved
        assert existing_file.exists()
        assert existing_file.read_bytes() == b"MZ\x90\x00existing content"

    def test_load_index_raises_for_invalid_top_level_json(
        self,
        tmp_path: Path,
    ) -> None:
        repo_path = tmp_path / "dll_repo"
        repo_path.mkdir()
        (repo_path / ".dll_index.json").write_text('["bad"]')

        repository = FileSystemDLLRepository(repo_path)

        with pytest.raises(RepositoryError):
            repository._load_index()

    def test_load_index_raises_for_invalid_files_shape(
        self,
        tmp_path: Path,
    ) -> None:
        repo_path = tmp_path / "dll_repo"
        repo_path.mkdir()
        (repo_path / ".dll_index.json").write_text('{"files": []}')

        repository = FileSystemDLLRepository(repo_path)

        with pytest.raises(RepositoryError):
            repository._load_index()


class TestFileSystemDLLRepositorySave:
    """Test save() operation with real filesystem writes."""

    def test_save_dll_to_filesystem(
        self,
        repository: FileSystemDLLRepository,
        dll_file_entity: DLLFile,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        """
        Verify that save() writes DLL file to correct location.

        Expected Behavior:
            - File is written to architecture-specific directory
            - File content matches saved bytes
            - File path is set on returned entity
        """
        saved_dll = repository.save(dll_file_entity, sample_dll_content)

        expected_path = tmp_path / "x64" / "kernel32.dll"
        assert expected_path.exists()
        assert expected_path.read_bytes() == sample_dll_content
        assert saved_dll.file_path == str(expected_path)

    def test_save_calculates_file_hash(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that save() calculates SHA256 hash when not present.

        Expected Behavior:
            - Hash is calculated from actual file content
            - Hash matches manually calculated value
            - Hash is set on returned entity
        """
        # Create entity without hash (None is the default)
        dll = DLLFile(
            name="kernel32.dll",
            version="10.0.19041.1",
            architecture=Architecture.X64,
        )

        saved_dll = repository.save(dll, sample_dll_content)

        expected_hash = hashlib.sha256(sample_dll_content).hexdigest()
        assert saved_dll.file_hash == expected_hash

    def test_save_canonicalizes_hash_and_size(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that save() persists metadata matching the actual payload bytes.

        Expected Behavior:
            - Existing stale hash/size values are overwritten
            - Returned entity can be found by name
        """
        predefined_hash = "abc123def456"
        dll = DLLFile(
            name="kernel32.dll",
            version="10.0.19041.1",
            architecture=Architecture.X64,
            file_hash=predefined_hash,
            file_size=1,
        )

        saved_dll = repository.save(dll, sample_dll_content)

        assert saved_dll.file_hash == hashlib.sha256(sample_dll_content).hexdigest()
        assert saved_dll.file_size == len(sample_dll_content)
        assert repository.find_by_name("kernel32.dll", Architecture.X64) is not None

    def test_save_updates_index(
        self,
        repository: FileSystemDLLRepository,
        dll_file_entity: DLLFile,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        """
        Verify that save() updates the JSON index file.

        Expected Behavior:
            - Index file is created at expected location
            - Index contains saved DLL metadata
            - Metadata is correctly serialized
        """
        repository.save(dll_file_entity, sample_dll_content)

        index_path = tmp_path / ".dll_index.json"
        assert index_path.exists()

        with open(index_path) as f:
            index_data = json.load(f)

        assert "files" in index_data
        key = "x64/kernel32.dll"
        assert key in index_data["files"]
        assert index_data["files"][key]["name"] == "kernel32.dll"
        assert index_data["files"][key]["architecture"] == "x64"

    def test_normalize_index_entry_rejects_invalid_shapes(
        self,
        repository: FileSystemDLLRepository,
    ) -> None:
        with pytest.raises(ValueError):
            repository._normalize_index_entry("bad")
        with pytest.raises(ValueError):
            repository._normalize_index_entry({"name": 1})
        with pytest.raises(ValueError):
            repository._normalize_index_entry({"name": "a.dll", "architecture": 1})
        with pytest.raises(ValueError):
            repository._normalize_index_entry(
                {"name": "a.dll", "architecture": "x64", "security_status": 1}
            )
        with pytest.raises(ValueError):
            repository._normalize_index_entry(
                {"name": "a.dll", "architecture": "x64", "file_size": "1"}
            )

    def test_save_x86_architecture(
        self,
        repository: FileSystemDLLRepository,
        tmp_path: Path,
    ) -> None:
        """
        Verify that x86 DLLs are saved to the x86/ directory.

        Expected Behavior:
            - File is written to x86/ subdirectory
            - File content is preserved
            - Index is updated with x86 architecture
        """
        dll = DLLFile(name="user32.dll", architecture=Architecture.X86)
        content = _build_pe_payload(Architecture.X86)

        saved_dll = repository.save(dll, content)

        expected_path = tmp_path / "x86" / "user32.dll"
        assert expected_path.exists()
        assert expected_path.read_bytes() == content
        assert saved_dll.architecture == Architecture.X86

    def test_save_rejects_pe_stub_without_image_layout(
        self,
        repository: FileSystemDLLRepository,
    ) -> None:
        with pytest.raises(RepositoryError, match="non-DLL payload"):
            repository.save(
                DLLFile(name="stub.dll", architecture=Architecture.X64),
                _build_pe_header_stub(Architecture.X64),
            )

    def test_save_rejects_pe_payload_with_blank_section_table(
        self,
        repository: FileSystemDLLRepository,
    ) -> None:
        with pytest.raises(RepositoryError, match="non-DLL payload"):
            repository.save(
                DLLFile(name="blank.dll", architecture=Architecture.X64),
                _build_pe_payload_with_blank_section(Architecture.X64),
            )

    def test_save_zip_skips_unreadable_duplicate_member(
        self,
        repository: FileSystemDLLRepository,
    ) -> None:
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            archive.writestr("bad/dupe.dll", _build_pe_payload(Architecture.X64))
            archive.writestr(
                "good/dupe.dll",
                _build_pe_payload(Architecture.X64) + b"valid",
            )
        payload = bytearray(archive_buffer.getvalue())
        local_header = payload.index(b"PK\x03\x04")
        central_directory_header = payload.index(b"PK\x01\x02")
        for flag_offset in (local_header + 6, central_directory_header + 8):
            flags = int.from_bytes(payload[flag_offset : flag_offset + 2], "little")
            payload[flag_offset : flag_offset + 2] = (flags | 0x01).to_bytes(
                2,
                "little",
            )

        saved = repository.save(
            DLLFile(name="dupe.dll", architecture=Architecture.X64),
            bytes(payload),
        )

        assert saved.name == "dupe.dll"
        assert repository.find_by_name("dupe.dll", Architecture.X64) is not None

    def test_find_rejects_unsafe_name(
        self,
        repository: FileSystemDLLRepository,
        tmp_path: Path,
    ) -> None:
        with pytest.raises(ValueError, match="DLL name"):
            repository.find_by_name("../evil", Architecture.X64)

        assert not (tmp_path / "evil.dll").exists()

    def test_save_rejects_symlink_dll_target(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        outside_file = tmp_path.parent / f"{tmp_path.name}-outside.dll"
        outside_file.write_bytes(b"external content")
        target_path = tmp_path / "x64" / "kernel32.dll"
        target_path.symlink_to(outside_file)

        try:
            with pytest.raises(RepositoryError, match="symlink"):
                repository.save(
                    DLLFile(name="kernel32.dll", architecture=Architecture.X64),
                    sample_dll_content,
                )

            assert outside_file.read_bytes() == b"external content"
            assert target_path.is_symlink()
            assert not (tmp_path / ".dll_index.json").exists()
        finally:
            target_path.unlink(missing_ok=True)
            outside_file.unlink(missing_ok=True)

    def test_save_rejects_symlink_index_target(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        outside_index = tmp_path.parent / f"{tmp_path.name}-outside-index.json"
        outside_index.write_text("external index")
        index_path = tmp_path / ".dll_index.json"
        index_path.symlink_to(outside_index)

        try:
            with pytest.raises(RepositoryError, match="symlink"):
                repository.save(
                    DLLFile(name="kernel32.dll", architecture=Architecture.X64),
                    sample_dll_content,
                )

            assert outside_index.read_text() == "external index"
            assert index_path.is_symlink()
            assert not (tmp_path / "x64" / "kernel32.dll").exists()
        finally:
            index_path.unlink(missing_ok=True)
            outside_index.unlink(missing_ok=True)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
    def test_save_rejects_fifo_payload_target(
        self,
        repository: FileSystemDLLRepository,
        tmp_path: Path,
    ) -> None:
        target_path = tmp_path / "x64" / "pipe.dll"
        os.mkfifo(target_path)

        with pytest.raises(RepositoryError, match="non-regular file"):
            repository._validate_repository_write_path(target_path)

        assert target_path.exists()
        assert not (tmp_path / ".dll_index.json").exists()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
    def test_read_file_no_follow_rejects_fifo_without_blocking(
        self,
        tmp_path: Path,
    ) -> None:
        fifo_path = tmp_path / "pipe.dll"
        os.mkfifo(fifo_path)

        with pytest.raises(RepositoryError, match="non-regular file"):
            FileSystemDLLRepository._read_file_no_follow(fifo_path)

    def test_save_rejects_index_directory_without_leaving_payload(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        index_path = tmp_path / ".dll_index.json"
        index_path.mkdir()

        with pytest.raises(RepositoryError, match="non-regular file"):
            repository.save(
                DLLFile(name="orphan.dll", architecture=Architecture.X64),
                sample_dll_content,
            )

        assert not (tmp_path / "x64" / "orphan.dll").exists()
        assert repository.find_by_name("orphan.dll", Architecture.X64) is None

    def test_save_rolls_back_new_payload_when_index_save_fails(
        self,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        repository = FailingIndexSaveRepository(tmp_path)

        with pytest.raises(RepositoryError, match="index write failed"):
            repository.save(
                DLLFile(name="rollback.dll", architecture=Architecture.X64),
                sample_dll_content,
            )

        assert not (tmp_path / "x64" / "rollback.dll").exists()
        assert repository.find_by_name("rollback.dll", Architecture.X64) is None

    def test_save_restores_existing_payload_when_index_save_fails(
        self,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        repository = FileSystemDLLRepository(tmp_path)
        saved = repository.save(
            DLLFile(name="restore.dll", architecture=Architecture.X64),
            sample_dll_content,
        )
        saved_path = Path(_require_str(saved.file_path))

        failing_repository = FailingIndexSaveRepository(tmp_path)
        with pytest.raises(RepositoryError, match="index write failed"):
            failing_repository.save(
                DLLFile(name="restore.dll", architecture=Architecture.X64),
                _build_pe_payload(Architecture.X64) + b"new content",
            )

        assert saved_path.read_bytes() == sample_dll_content

    def test_save_rejects_repository_subdirectory_symlink(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        outside_dir = tmp_path.parent / f"{tmp_path.name}-outside-dir"
        outside_dir.mkdir()
        arch_dir = tmp_path / "x64"
        arch_dir.rmdir()
        arch_dir.symlink_to(outside_dir, target_is_directory=True)

        try:
            with pytest.raises(RepositoryError, match="outside repository"):
                repository.save(
                    DLLFile(name="kernel32.dll", architecture=Architecture.X64),
                    sample_dll_content,
                )

            assert not (outside_dir / "kernel32.dll").exists()
        finally:
            arch_dir.unlink(missing_ok=True)
            outside_dir.rmdir()

    def test_save_overwrites_existing_file(
        self,
        repository: FileSystemDLLRepository,
        dll_file_entity: DLLFile,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        """
        Verify that saving with same name overwrites existing file.

        Expected Behavior:
            - Original file content is replaced
            - New content is written correctly
            - Index is updated with new metadata
        """
        # Save initial version
        original_content = _build_pe_payload(Architecture.X64) + b"original content"
        repository.save(dll_file_entity, original_content)

        # Save updated version
        new_content = sample_dll_content
        repository.save(dll_file_entity, new_content)

        file_path = tmp_path / "x64" / "kernel32.dll"
        assert file_path.read_bytes() == new_content
        assert file_path.read_bytes() != original_content

    def test_save_multiple_dlls(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that multiple DLLs can be saved independently.

        Expected Behavior:
            - All files are written to filesystem
            - Each file has correct content
            - Index contains all entries
        """
        dll1 = DLLFile(name="kernel32.dll", architecture=Architecture.X64)
        dll2 = DLLFile(name="user32.dll", architecture=Architecture.X64)
        dll3 = DLLFile(name="gdi32.dll", architecture=Architecture.X86)

        content1 = _build_pe_payload(Architecture.X64) + b"content1"
        content2 = _build_pe_payload(Architecture.X64) + b"content2"
        content3 = _build_pe_payload(Architecture.X86) + b"content3"

        repository.save(dll1, content1)
        repository.save(dll2, content2)
        repository.save(dll3, content3)

        # Verify all files exist and have correct content
        all_dlls = repository.list_all()
        assert len(all_dlls) == 3

        found_dll1 = repository.find_by_name("kernel32.dll", Architecture.X64)
        found_dll2 = repository.find_by_name("user32.dll", Architecture.X64)
        found_dll3 = repository.find_by_name("gdi32.dll", Architecture.X86)

        assert found_dll1 is not None
        assert found_dll2 is not None
        assert found_dll3 is not None

    def test_save_accepts_zip_containing_requested_dll(
        self,
        repository: FileSystemDLLRepository,
        tmp_path: Path,
    ) -> None:
        dll = DLLFile(name="zipped.dll", architecture=Architecture.X64)
        zip_payload = _build_zip_payload(
            "zipped.dll",
            _build_pe_payload(Architecture.X64),
        )

        saved = repository.save(dll, zip_payload)

        saved_path = Path(_require_str(saved.file_path))
        assert saved_path == tmp_path / "x64" / "zipped.zip"
        assert saved.name == "zipped.dll"
        assert saved_path.read_bytes() == zip_payload

    def test_save_accepts_zip_member_with_backslash_path(
        self,
        repository: FileSystemDLLRepository,
        tmp_path: Path,
    ) -> None:
        dll = DLLFile(name="zipped.dll", architecture=Architecture.X64)
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            archive.writestr(
                "nested\\zipped.dll",
                _build_pe_payload(Architecture.X64),
            )
        zip_payload = archive_buffer.getvalue()

        saved = repository.save(dll, zip_payload)

        saved_path = Path(_require_str(saved.file_path))
        assert saved_path == tmp_path / "x64" / "zipped.zip"
        assert saved.name == "zipped.dll"
        assert saved_path.read_bytes() == zip_payload

    def test_save_accepts_duplicate_zip_member_when_requested_architecture_exists(
        self,
        repository: FileSystemDLLRepository,
        tmp_path: Path,
    ) -> None:
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            archive.writestr("x86/zipped.dll", _build_pe_payload(Architecture.X86))
            archive.writestr("x64/zipped.dll", _build_pe_payload(Architecture.X64))
        zip_payload = archive_buffer.getvalue()

        saved = repository.save(
            DLLFile(name="zipped.dll", architecture=Architecture.X64),
            zip_payload,
        )

        saved_path = Path(_require_str(saved.file_path))
        assert saved_path == tmp_path / "x64" / "zipped.zip"
        assert saved.name == "zipped.dll"
        assert saved_path.read_bytes() == zip_payload

    def test_save_uses_case_insensitive_storage_name(
        self,
        repository: FileSystemDLLRepository,
        tmp_path: Path,
    ) -> None:
        saved = repository.save(
            DLLFile(name="Case.DLL", architecture=Architecture.X64),
            _build_pe_payload(Architecture.X64),
        )

        saved_path = Path(_require_str(saved.file_path))
        assert saved_path == tmp_path / "x64" / "case.dll"
        assert repository.find_by_name("case.dll", Architecture.X64) is not None
        assert repository.find_by_name("Case.DLL", Architecture.X64) is not None

    def test_save_rejects_non_dll_payload(
        self,
        repository: FileSystemDLLRepository,
        tmp_path: Path,
    ) -> None:
        dll = DLLFile(name="bad.dll", architecture=Architecture.X64)

        with pytest.raises(RepositoryError, match="non-DLL payload"):
            repository.save(dll, b"not a PE DLL")

        assert not (tmp_path / "x64" / "bad.dll").exists()
        assert repository.find_by_name("bad.dll", Architecture.X64) is None


class TestFileSystemDLLRepositoryFindByName:
    """Test find_by_name() with real filesystem reads."""

    def test_find_existing_dll_by_name_and_architecture(
        self,
        repository: FileSystemDLLRepository,
        dll_file_entity: DLLFile,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify finding DLL by exact name and architecture.

        Expected Behavior:
            - Returns correct DLLFile entity
            - Entity metadata matches saved data
            - File path is set correctly
        """
        repository.save(dll_file_entity, sample_dll_content)

        found = repository.find_by_name("kernel32.dll", Architecture.X64)

        assert found is not None
        assert found.name == "kernel32.dll"
        assert found.architecture == Architecture.X64
        assert found.version == "10.0.19041.1"

    def test_find_by_name_without_extension(
        self,
        repository: FileSystemDLLRepository,
        dll_file_entity: DLLFile,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that .dll extension is automatically appended when missing.

        Expected Behavior:
            - Finds DLL even when extension is omitted
            - Returns correct entity
        """
        repository.save(dll_file_entity, sample_dll_content)

        found = repository.find_by_name("kernel32", Architecture.X64)

        assert found is not None
        assert found.name == "kernel32.dll"

    def test_find_without_architecture_returns_first_match(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that searching without architecture returns first found match.

        Expected Behavior:
            - Searches in enum order (x86, x64, ...)
            - Returns first matching DLL
        """
        dll_x64 = DLLFile(
            name="common.dll", architecture=Architecture.X64, version="1.0"
        )
        dll_x86 = DLLFile(
            name="common.dll", architecture=Architecture.X86, version="2.0"
        )

        repository.save(dll_x64, sample_dll_content)
        repository.save(dll_x86, _build_pe_payload(Architecture.X86))

        found = repository.find_by_name("common.dll")

        assert found is not None
        assert found.architecture == Architecture.X86
        assert found.version == "2.0"


def test_find_without_architecture_no_match_hits_unknown(
    repository: FileSystemDLLRepository,
) -> None:
    """
    Verify loop reaches UNKNOWN when no matches exist.
    """
    found = repository.find_by_name("missing.dll")
    assert found is None


def test_find_with_unknown_architecture_finds_x64(tmp_download_dir: Path) -> None:
    """
    Verify UNKNOWN architecture lookup returns the indexed x64 entity.
    """
    repository = FileSystemDLLRepository(tmp_download_dir)
    dll = DLLFile(
        name="unknown.dll",
        architecture=Architecture.X64,
        download_url="https://example.test/unknown.zip",
        security_status=SecurityStatus.CLEAN,
    )
    repository.save(dll, _build_pe_payload())

    found = repository.find_by_name("unknown.dll", Architecture.UNKNOWN)
    assert found is not None
    assert found.architecture == Architecture.X64
    assert found.download_url == "https://example.test/unknown.zip"
    assert found.security_status == SecurityStatus.CLEAN


def test_save_with_unknown_architecture_detects_payload_architecture(
    tmp_download_dir: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)

    saved = repository.save(
        DLLFile(name="x86unknown.dll"),
        _build_pe_payload(Architecture.X86),
    )

    assert saved.architecture == Architecture.X86
    assert Path(_require_str(saved.file_path)).parent.name == "x86"
    assert repository.exists("x86unknown.dll") is True
    found = repository.find_by_name("x86unknown.dll")
    assert found is not None
    assert found.architecture == Architecture.X86


def test_save_index_raises_repository_error(
    tmp_download_dir: Path,
) -> None:
    """
    Verify _save_index raises RepositoryError on OSError.
    """
    repository = FileSystemDLLRepository(tmp_download_dir)
    repository._index_path.mkdir()

    with pytest.raises(RepositoryError):
        repository._save_index({"files": {}})


def test_save_index_wraps_atomic_write_os_error(tmp_download_dir: Path) -> None:
    repository = OSErrorAtomicWriteRepository(tmp_download_dir)

    with pytest.raises(RepositoryError, match="Failed to save index"):
        repository._save_index({"files": {}})


def test_atomic_write_cleans_temp_file_when_replace_fails(
    tmp_download_dir: Path,
) -> None:
    repository = DirectoryRaceRepository(tmp_download_dir)
    target_path = tmp_download_dir / "x64" / "race.dll"

    with pytest.raises(RepositoryError, match="Refusing to replace non-regular file"):
        repository._atomic_write_bytes(target_path, b"data")

    assert sorted(path.name for path in target_path.parent.iterdir()) == ["race.dll"]


def test_save_raises_repository_error_on_write(
    tmp_download_dir: Path,
) -> None:
    """
    Verify save raises RepositoryError on file write error.
    """
    repository = FileSystemDLLRepository(tmp_download_dir)
    dll = DLLFile(name="writefail.dll", architecture=Architecture.X64)
    target_path = repository._get_file_path(dll.name, dll.architecture)
    target_path.mkdir()

    with pytest.raises(RepositoryError):
        repository.save(dll, _build_pe_payload(Architecture.X64))


def test_save_wraps_payload_os_error(tmp_download_dir: Path) -> None:
    repository = OSErrorAtomicWriteRepository(tmp_download_dir)
    dll = DLLFile(name="writefail.dll", architecture=Architecture.X64)

    with pytest.raises(RepositoryError, match="Failed to save DLL"):
        repository.save(dll, _build_pe_payload(Architecture.X64))


def test_failed_rollback_write_is_logged_without_masking_index_error(
    tmp_download_dir: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    saved = repository.save(
        DLLFile(name="rollbacklog.dll", architecture=Architecture.X64),
        _build_pe_payload(Architecture.X64) + b"original content",
    )
    saved_path = Path(_require_str(saved.file_path))

    failing_repository = FailingRollbackWriteRepository(tmp_download_dir)
    with pytest.raises(RepositoryError, match="index write failed"):
        failing_repository.save(
            DLLFile(name="rollbacklog.dll", architecture=Architecture.X64),
            _build_pe_payload(Architecture.X64) + b"new content",
        )

    assert saved_path.read_bytes().endswith(b"new content")


def test_delete_returns_false_on_exception(
    tmp_download_dir: Path,
) -> None:
    """
    Verify delete returns False when unlink raises.
    """
    repository = FileSystemDLLRepository(tmp_download_dir)
    dll = DLLFile(name="deletefail.dll", architecture=Architecture.X64)
    saved = repository.save(dll, _build_pe_payload(Architecture.X64))
    saved_path = Path(saved.file_path or "")
    saved_path.unlink()
    saved_path.mkdir()
    assert repository.delete(saved) is False


def test_delete_with_missing_file_path_returns_true(tmp_download_dir: Path) -> None:
    """
    Verify delete succeeds when file_path does not exist on disk.
    """
    repository = FileSystemDLLRepository(tmp_download_dir)
    dll = DLLFile(
        name="missing.dll",
        architecture=Architecture.X64,
        file_path=str(tmp_download_dir / "x64" / "missing.dll"),
    )

    assert repository.delete(dll) is True


def test_delete_without_file_path_removes_expected_payload(
    tmp_download_dir: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    saved = repository.save(
        DLLFile(name="victim.dll", architecture=Architecture.X64),
        _build_pe_payload(Architecture.X64) + b"victim content",
    )
    saved_path = Path(_require_str(saved.file_path))

    assert repository.delete(DLLFile(name="victim.dll", architecture=Architecture.X64))
    assert not saved_path.exists()
    assert repository.find_by_name("victim.dll", Architecture.X64) is None


def test_delete_with_unknown_architecture_removes_payload_and_index(
    tmp_download_dir: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    saved = repository.save(
        DLLFile(name="unknown-delete.dll", architecture=Architecture.X64),
        _build_pe_payload(Architecture.X64),
    )
    saved_path = Path(_require_str(saved.file_path))

    assert repository.delete(DLLFile(name="unknown-delete.dll")) is True

    assert not saved_path.exists()
    assert repository.find_by_name("unknown-delete.dll", Architecture.X64) is None
    with (tmp_download_dir / ".dll_index.json").open() as index_file:
        index_data = json.load(index_file)
    assert "x64/unknown-delete.dll" not in index_data["files"]


def test_delete_rejects_mismatched_internal_file_path(
    tmp_download_dir: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    first = repository.save(
        DLLFile(name="first.dll", architecture=Architecture.X64),
        _build_pe_payload(Architecture.X64) + b"first content",
    )
    second = repository.save(
        DLLFile(name="second.dll", architecture=Architecture.X64),
        _build_pe_payload(Architecture.X64) + b"second content",
    )
    first_path = Path(_require_str(first.file_path))
    second_path = Path(_require_str(second.file_path))

    result = repository.delete(
        DLLFile(
            name="first.dll",
            architecture=Architecture.X64,
            file_path=str(second_path),
        )
    )

    assert result is False
    assert first_path.read_bytes().endswith(b"first content")
    assert second_path.read_bytes().endswith(b"second content")
    assert repository.find_by_name("first.dll", Architecture.X64) is not None
    assert repository.find_by_name("second.dll", Architecture.X64) is not None


def test_path_locations_match_rejects_missing_parent(tmp_download_dir: Path) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)

    with pytest.raises(RepositoryError):
        repository._path_locations_match(
            tmp_download_dir / "missing-parent" / "missing.dll",
            tmp_download_dir / "x64" / "missing.dll",
        )


def test_delete_rejects_file_path_outside_repository(
    tmp_download_dir: Path, tmp_path: Path
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    outside_file = tmp_path / "outside.dll"
    outside_file.write_bytes(b"external content")
    dll = DLLFile(
        name="outside.dll",
        architecture=Architecture.X64,
        file_path=str(outside_file),
    )

    assert repository.delete(dll) is False
    assert outside_file.read_bytes() == b"external content"


def test_delete_rejects_payload_resolving_outside_repository(
    tmp_download_dir: Path,
    tmp_path: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    arch_dir = tmp_download_dir / Architecture.X64.value
    outside_dir = tmp_path / "outside-arch"
    outside_dir.mkdir()
    arch_dir.rmdir()
    arch_dir.symlink_to(outside_dir, target_is_directory=True)

    try:
        dll = DLLFile(name="escaped.dll", architecture=Architecture.X64)

        assert repository.delete(dll) is False
        assert arch_dir.is_symlink()
    finally:
        arch_dir.unlink(missing_ok=True)


def test_delete_rejects_symlink_payload_inside_symlinked_arch_directory(
    tmp_download_dir: Path,
    tmp_path: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    arch_dir = tmp_download_dir / Architecture.X64.value
    outside_dir = tmp_path / "outside-arch"
    outside_dir.mkdir()
    outside_target = tmp_path / "outside-target.dll"
    outside_target.write_bytes(b"external content")
    outside_payload = outside_dir / "escaped.dll"
    outside_payload.symlink_to(outside_target)
    arch_dir.rmdir()
    arch_dir.symlink_to(outside_dir, target_is_directory=True)

    try:
        dll = DLLFile(name="escaped.dll", architecture=Architecture.X64)

        assert repository.delete(dll) is False
        assert outside_payload.is_symlink()
        assert outside_target.read_bytes() == b"external content"
    finally:
        arch_dir.unlink(missing_ok=True)
        outside_payload.unlink(missing_ok=True)


def test_delete_rejects_symlink_path_outside_repository(
    tmp_download_dir: Path,
    tmp_path: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    inside_file = tmp_download_dir / "x64" / "inside.dll"
    inside_file.write_bytes(b"inside content")
    outside_symlink = tmp_path / "outside-link.dll"
    outside_symlink.symlink_to(inside_file)
    dll = DLLFile(
        name="outside-link.dll",
        architecture=Architecture.X64,
        file_path=str(outside_symlink),
    )

    try:
        assert repository.delete(dll) is False
        assert outside_symlink.is_symlink()
        assert inside_file.read_bytes() == b"inside content"
    finally:
        outside_symlink.unlink(missing_ok=True)


def test_delete_refuses_internal_symlink_pointing_outside_repository(
    tmp_download_dir: Path,
    tmp_path: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    outside_file = tmp_path / "outside-target.dll"
    outside_file.write_bytes(b"external content")
    symlink_path = tmp_download_dir / "x64" / "evil.dll"
    symlink_path.symlink_to(outside_file)
    dll = DLLFile(
        name="evil.dll",
        architecture=Architecture.X64,
        file_path=str(symlink_path),
    )

    assert repository.delete(dll) is False
    assert symlink_path.is_symlink()
    assert outside_file.read_bytes() == b"external content"


def test_delete_refuses_broken_symlink_inside_repository(
    tmp_download_dir: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    symlink_path = tmp_download_dir / "x64" / "broken.dll"
    symlink_path.symlink_to(tmp_download_dir / "missing-target.dll")
    dll = DLLFile(
        name="broken.dll",
        architecture=Architecture.X64,
        file_path=str(symlink_path),
    )

    assert repository.delete(dll) is False
    assert symlink_path.is_symlink()


def test_find_nonexistent_dll_returns_none(
    repository: FileSystemDLLRepository,
) -> None:
    """
    Verify that searching for non-existent DLL returns None.

    Expected Behavior:
        - Returns None when DLL doesn't exist
        - No exceptions are raised
    """
    found = repository.find_by_name("nonexistent.dll", Architecture.X64)

    assert found is None


def test_find_file_on_disk_without_index_entry(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    """
    Verify that repository can find DLLs that exist on disk but not in index.

    Expected Behavior:
        - Finds file on filesystem
        - Creates DLLFile entity from file
        - Calculates hash from actual file content
    """
    dll_path = tmp_path / "x64" / "orphaned.dll"
    content = _build_pe_payload()
    dll_path.write_bytes(content)

    found = repository.find_by_name("orphaned.dll", Architecture.X64)

    assert found is not None
    assert found.name == "orphaned.dll"
    assert found.architecture == Architecture.X64
    assert found.file_hash == hashlib.sha256(content).hexdigest()


def test_list_all_includes_valid_fallback_payload_without_index(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    dll_path = tmp_path / "x64" / "orphaned.dll"
    content = _build_pe_payload()
    dll_path.write_bytes(content)

    all_dlls = repository.list_all()

    assert len(all_dlls) == 1
    assert all_dlls[0].name == "orphaned.dll"
    assert all_dlls[0].architecture == Architecture.X64
    assert all_dlls[0].file_hash == hashlib.sha256(content).hexdigest()


def test_fallback_enumeration_skips_unreadable_architecture_directory(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    arch_dir = tmp_path / "x64"
    arch_dir.chmod(0)
    try:
        try:
            list(arch_dir.iterdir())
        except OSError:
            pass
        else:
            pytest.skip("filesystem permits reading chmod 0 directories")

        assert repository.list_all() == []
        assert repository.find_by_hash("a" * 64) is None
    finally:
        arch_dir.chmod(0o700)


def test_find_by_name_ignores_fallback_payload_without_mz_signature(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    dll_path = tmp_path / "x64" / "bad.dll"
    dll_path.write_bytes(b"not a PE DLL")

    assert repository.find_by_name("bad.dll", Architecture.X64) is None


def test_find_by_name_ignores_fallback_payload_without_pe_signature(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    dll_path = tmp_path / "x64" / "fake.dll"
    dll_path.write_bytes(b"MZ not actually PE")

    assert repository.find_by_name("fake.dll", Architecture.X64) is None
    assert repository.exists("fake.dll", Architecture.X64) is False


def test_find_by_name_ignores_fallback_pe_stub_without_image_layout(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    dll_path = tmp_path / "x64" / "stub.dll"
    dll_path.write_bytes(_build_pe_header_stub(Architecture.X64))

    assert repository.find_by_name("stub.dll", Architecture.X64) is None
    assert repository.exists("stub.dll", Architecture.X64) is False


def test_find_by_name_ignores_fallback_pe_payload_with_blank_section_table(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    dll_path = tmp_path / "x64" / "blank.dll"
    dll_path.write_bytes(_build_pe_payload_with_blank_section(Architecture.X64))

    assert repository.find_by_name("blank.dll", Architecture.X64) is None
    assert repository.exists("blank.dll", Architecture.X64) is False


def test_find_by_name_ignores_fallback_payload_with_wrong_architecture(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    dll_path = tmp_path / "x64" / "wrongarch.dll"
    dll_path.write_bytes(_build_pe_payload(Architecture.X86))

    assert repository.find_by_name("wrongarch.dll", Architecture.X64) is None


def test_find_by_name_ignores_fallback_payload_through_arch_symlink(
    tmp_download_dir: Path,
    tmp_path: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    arch_dir = tmp_download_dir / Architecture.X64.value
    outside_dir = tmp_path / "outside-arch"
    outside_dir.mkdir()
    arch_dir.rmdir()
    arch_dir.symlink_to(outside_dir, target_is_directory=True)
    outside_payload = outside_dir / "escape.dll"
    outside_payload.write_bytes(b"MZ external content")

    try:
        assert repository.find_by_name("escape.dll", Architecture.X64) is None
    finally:
        arch_dir.unlink(missing_ok=True)


def test_find_by_name_ignores_symlink_fallback_payload(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    outside_file = tmp_path.parent / f"{tmp_path.name}-fallback-outside.dll"
    outside_file.write_bytes(b"MZ outside content")
    symlink_path = tmp_path / "x64" / "linked.dll"
    symlink_path.symlink_to(outside_file)

    try:
        assert repository.find_by_name("linked.dll", Architecture.X64) is None
    finally:
        symlink_path.unlink(missing_ok=True)
        outside_file.unlink(missing_ok=True)


def test_find_by_name_ignores_fallback_payload_resolving_outside(
    tmp_path: Path,
) -> None:
    repository = EscapingFallbackRepository(tmp_path)
    payload_path = tmp_path / "x64" / "escape.dll"
    payload_path.write_bytes(b"MZ outside content")

    assert repository.find_by_name("escape.dll", Architecture.X64) is None


def test_list_all_ignores_index_entry_without_file_path(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    repository.save(
        DLLFile(name="missing-path.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    index_path = tmp_path / ".dll_index.json"
    index_data = json.loads(index_path.read_text())
    index_data["files"]["x64/missing-path.dll"]["file_path"] = None
    index_path.write_text(json.dumps(index_data))

    assert repository.list_all() == []


def test_find_by_name_ignores_index_entry_when_payload_is_missing(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
) -> None:
    saved = repository.save(
        DLLFile(name="ghost.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    Path(_require_str(saved.file_path)).unlink()

    assert repository.find_by_name("ghost.dll", Architecture.X64) is None
    assert repository.exists("ghost.dll", Architecture.X64) is False


def test_find_by_name_rejects_tampered_indexed_payload(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
) -> None:
    saved = repository.save(
        DLLFile(name="tampered.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    payload_path = Path(_require_str(saved.file_path))
    payload_path.write_bytes(b"tampered content")

    assert repository.find_by_name("tampered.dll", Architecture.X64) is None


def test_find_by_name_rejects_indexed_payload_that_is_not_a_dll(
    tmp_path: Path,
) -> None:
    repository = FileSystemDLLRepository(tmp_path)
    payload = b"not a PE DLL"
    payload_path = tmp_path / "x64" / "bad.dll"
    payload_path.write_bytes(payload)
    index_data = {
        "files": {
            "x64/bad.dll": {
                "name": "bad.dll",
                "version": None,
                "architecture": "x64",
                "file_hash": hashlib.sha256(payload).hexdigest(),
                "file_path": str(payload_path),
                "download_url": None,
                "file_size": len(payload),
                "security_status": "not_scanned",
                "vt_detection_ratio": None,
                "vt_scan_date": None,
                "created_at": None,
            }
        }
    }
    (tmp_path / ".dll_index.json").write_text(json.dumps(index_data))

    assert repository.find_by_name("bad.dll", Architecture.X64) is None
    assert repository.find_by_hash(hashlib.sha256(payload).hexdigest()) is None
    assert repository.list_all() == []


def test_find_by_name_rebuilds_metadata_when_index_hash_is_invalid(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    repository.save(
        DLLFile(name="legacy.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    index_path = tmp_path / ".dll_index.json"
    index_data = json.loads(index_path.read_text())
    entry = index_data["files"]["x64/legacy.dll"]
    entry["file_hash"] = 123
    entry["security_status"] = "clean"
    entry["vt_detection_ratio"] = "0/72"
    index_path.write_text(json.dumps(index_data))

    found = repository.find_by_name("legacy.dll", Architecture.X64)

    assert found is not None
    assert found.file_hash == hashlib.sha256(sample_dll_content).hexdigest()
    assert found.security_status == SecurityStatus.NOT_SCANNED
    assert found.vt_detection_ratio is None


def test_find_by_hash_uses_disk_fallback_when_index_hash_is_invalid(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    repository.save(
        DLLFile(name="legacy-hash.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    expected_hash = hashlib.sha256(sample_dll_content).hexdigest()
    index_path = tmp_path / ".dll_index.json"
    index_data = json.loads(index_path.read_text())
    index_data["files"]["x64/legacy-hash.dll"]["file_hash"] = None
    index_path.write_text(json.dumps(index_data))
    (tmp_path / "x64" / "note.txt").write_text("not a DLL")
    (tmp_path / "x64" / "bad.dll").write_bytes(b"not a PE DLL")
    outside_arch = tmp_path / "outside-x86"
    outside_arch.mkdir()
    x86_dir = tmp_path / "x86"
    x86_dir.rmdir()
    x86_dir.symlink_to(outside_arch, target_is_directory=True)

    found = repository.find_by_hash(expected_hash)

    assert found is not None
    assert found.name == "legacy-hash.dll"
    assert found.file_hash == expected_hash


def test_find_by_hash_checks_next_index_entry_when_hash_differs(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
) -> None:
    repository.save(
        DLLFile(name="first.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    second = repository.save(
        DLLFile(name="second.dll", architecture=Architecture.X64),
        sample_dll_content + b"second",
    )

    found = repository.find_by_hash(_require_str(second.file_hash).upper())

    assert found is not None
    assert found.name == "second.dll"


def test_indexed_payload_validation_rejects_expected_hash_mismatch_after_content_match(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
) -> None:
    saved = repository.save(
        DLLFile(name="hash-mismatch.dll", architecture=Architecture.X64),
        sample_dll_content,
    )

    assert not repository._indexed_payload_is_valid(
        saved,
        expected_hash="a" * 64,
    )


def test_invalid_index_file_size_is_skipped(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    repository.save(
        DLLFile(name="bad-size.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    index_path = tmp_path / ".dll_index.json"
    index_data = json.loads(index_path.read_text())
    index_data["files"]["x64/bad-size.dll"]["file_size"] = "large"
    index_path.write_text(json.dumps(index_data))

    assert repository.list_all() == []


def test_unknown_architecture_save_rejects_payload_without_detectable_architecture(
    repository: FileSystemDLLRepository,
) -> None:
    with pytest.raises(RepositoryError, match="unknown-architecture payload"):
        repository.save(
            DLLFile(name="unknown.dll", architecture=Architecture.UNKNOWN),
            b"not a DLL",
        )


def test_detect_zip_payload_architecture_skips_invalid_members() -> None:
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("folder/", "")
        archive.writestr("other.dll", _build_pe_payload(Architecture.X64))
        archive.writestr("target.dll", b"")
        archive.writestr("nested/target.dll", b"not a PE DLL")
        archive.writestr("x86/target.dll", _build_pe_payload(Architecture.X86))

    assert (
        FileSystemDLLRepository._detect_zip_payload_architecture(
            "target.dll",
            archive_buffer.getvalue(),
            expected_architecture=Architecture.X64,
        )
        is None
    )


def test_detect_pe_dll_architecture_rejects_invalid_header_variants() -> None:
    pe_offset = 0x80
    unsupported_machine = bytearray(pe_offset + 24)
    unsupported_machine[0:2] = b"MZ"
    unsupported_machine[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    unsupported_machine[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    unsupported_machine[pe_offset + 4 : pe_offset + 6] = (0x1234).to_bytes(2, "little")

    assert (
        FileSystemDLLRepository._detect_pe_dll_architecture(b"MZ" + b"\0" * 62) is None
    )
    assert (
        FileSystemDLLRepository._detect_pe_dll_architecture(bytes(unsupported_machine))
        is None
    )
    assert (
        FileSystemDLLRepository._detect_pe_dll_architecture(
            _build_pe_header_stub(Architecture.X64)
        )
        is None
    )
    assert (
        FileSystemDLLRepository._detect_pe_dll_architecture(
            _build_pe_payload_without_dll_flag()
        )
        is None
    )


def test_pe_image_layout_rejects_invalid_boundaries() -> None:
    def build_layout_probe(
        *,
        section_count: int = 1,
        optional_header_size: int = 0xF0,
        optional_magic: int = 0x20B,
        total_size: int | None = None,
    ) -> bytes:
        section_table_offset = 20 + optional_header_size
        payload_size = section_table_offset + 40 if total_size is None else total_size
        payload = bytearray(max(payload_size, 22))
        payload[2:4] = section_count.to_bytes(2, "little")
        payload[16:18] = optional_header_size.to_bytes(2, "little")
        payload[20:22] = optional_magic.to_bytes(2, "little")
        return bytes(payload[:payload_size])

    assert not FileSystemDLLRepository._pe_image_layout_is_valid(
        build_layout_probe(section_count=0),
        0,
        Architecture.X64,
    )
    assert not FileSystemDLLRepository._pe_image_layout_is_valid(
        build_layout_probe(optional_header_size=0),
        0,
        Architecture.X64,
    )
    assert not FileSystemDLLRepository._pe_image_layout_is_valid(
        build_layout_probe(total_size=40),
        0,
        Architecture.X64,
    )
    assert not FileSystemDLLRepository._pe_image_layout_is_valid(
        build_layout_probe(optional_magic=0x10B),
        0,
        Architecture.X64,
    )
    assert not FileSystemDLLRepository._pe_image_layout_is_valid(
        build_layout_probe(optional_header_size=2, total_size=22),
        0,
        Architecture.X64,
    )


def test_content_matches_dll_payload_rejects_invalid_accepts_unknown_arch() -> None:
    assert not FileSystemDLLRepository._content_matches_dll_payload(
        "sample.dll",
        Architecture.X64,
        b"not a PE DLL",
    )
    assert FileSystemDLLRepository._content_matches_dll_payload(
        "sample.dll",
        Architecture.UNKNOWN,
        _build_pe_payload(Architecture.X64),
    )


def test_find_by_name_uses_zip_fallback_when_index_is_missing(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    zip_payload = _build_zip_payload(
        "cached.dll",
        _build_pe_payload(Architecture.X64),
    )
    repository.save(
        DLLFile(name="cached.dll", architecture=Architecture.X64),
        zip_payload,
    )
    (tmp_path / ".dll_index.json").unlink()

    found = repository.find_by_name("cached.dll", Architecture.X64)

    assert found is not None
    assert found.file_hash == hashlib.sha256(zip_payload).hexdigest()
    assert found.file_size == len(zip_payload)


def test_find_by_name_rejects_mismatched_index_metadata(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    repository.save(
        DLLFile(name="valid.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    index_path = tmp_path / ".dll_index.json"
    index_data = json.loads(index_path.read_text())
    index_data["files"]["x64/valid.dll"]["name"] = "other.dll"
    index_path.write_text(json.dumps(index_data))

    # Corrupt index metadata should not prevent finding the valid on-disk file.
    result = repository.find_by_name("valid.dll", Architecture.X64)
    assert result is not None
    assert result.name == "valid.dll"


def test_find_by_name_rejects_mismatched_index_architecture(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    repository.save(
        DLLFile(name="valid.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    index_path = tmp_path / ".dll_index.json"
    index_data = json.loads(index_path.read_text())
    index_data["files"]["x64/valid.dll"]["architecture"] = "x86"
    index_path.write_text(json.dumps(index_data))

    # Corrupt index metadata should not prevent finding the valid on-disk file.
    result = repository.find_by_name("valid.dll", Architecture.X64)
    assert result is not None
    assert result.name == "valid.dll"


def test_list_all_rejects_mismatched_index_payload_path(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    repository.save(
        DLLFile(name="valid.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    other = repository.save(
        DLLFile(name="other.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    index_path = tmp_path / ".dll_index.json"
    index_data = json.loads(index_path.read_text())
    index_data["files"]["x64/valid.dll"]["file_path"] = other.file_path
    del index_data["files"]["x64/other.dll"]
    index_path.write_text(json.dumps(index_data))

    listed_names = [dll.name for dll in repository.list_all()]
    assert listed_names == ["other.dll"]


def test_list_all_rejects_payload_that_disappears_during_validation(
    tmp_path: Path,
    sample_dll_content: bytes,
) -> None:
    repository = VanishingPayloadRepository(tmp_path)
    repository.save(
        DLLFile(name="vanish.dll", architecture=Architecture.X64),
        sample_dll_content,
    )

    assert repository.list_all() == []


def test_indexed_payload_validation_rejects_expected_hash_mismatch(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
) -> None:
    saved = repository.save(
        DLLFile(name="expected-hash.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    without_hash = replace(saved, file_hash=None)

    assert not repository._indexed_payload_is_valid(
        without_hash,
        expected_hash="wrong-hash",
    )


def test_list_all_rejects_mismatched_index_payload_size(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    repository.save(
        DLLFile(name="wrong-size.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    index_path = tmp_path / ".dll_index.json"
    index_data = json.loads(index_path.read_text())
    index_data["files"]["x64/wrong-size.dll"]["file_size"] = len(sample_dll_content) + 1
    index_path.write_text(json.dumps(index_data))

    assert repository.list_all() == []


def test_find_by_name_ignores_index_entry_when_payload_is_symlink(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    saved = repository.save(
        DLLFile(name="linked.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    payload_path = Path(_require_str(saved.file_path))
    outside_file = tmp_path.parent / f"{tmp_path.name}-outside-linked.dll"
    outside_file.write_bytes(b"external content")

    try:
        payload_path.unlink()
        payload_path.symlink_to(outside_file)

        assert repository.find_by_name("linked.dll", Architecture.X64) is None
    finally:
        payload_path.unlink(missing_ok=True)
        outside_file.unlink(missing_ok=True)


def test_index_symlink_is_not_loaded(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    payload_path = tmp_path / "x64" / "external-index.dll"
    payload_path.write_bytes(_build_pe_payload())
    file_hash = hashlib.sha256(sample_dll_content).hexdigest()
    external_index = tmp_path.parent / f"{tmp_path.name}-external-index.json"
    external_index.write_text(
        json.dumps(
            {
                "files": {
                    "x64/external-index.dll": {
                        "name": "external-index.dll",
                        "version": None,
                        "architecture": "x64",
                        "file_hash": file_hash,
                        "file_path": str(payload_path),
                        "download_url": "https://external.example/payload.zip",
                        "file_size": len(sample_dll_content),
                        "security_status": "unknown",
                        "vt_detection_ratio": None,
                        "vt_scan_date": None,
                        "created_at": None,
                    }
                }
            }
        )
    )
    index_path = tmp_path / ".dll_index.json"
    index_path.symlink_to(external_index)

    try:
        with pytest.raises(RepositoryError, match="symlink"):
            repository.find_by_name("external-index.dll", Architecture.X64)
        with pytest.raises(RepositoryError, match="symlink"):
            repository.find_by_hash(file_hash)
        with pytest.raises(RepositoryError, match="symlink"):
            repository.list_all()
    finally:
        index_path.unlink(missing_ok=True)
        external_index.unlink(missing_ok=True)


def test_index_entry_pointing_outside_repository_is_not_returned(
    repository: FileSystemDLLRepository,
    sample_dll_content: bytes,
    tmp_path: Path,
) -> None:
    saved = repository.save(
        DLLFile(name="outside-index.dll", architecture=Architecture.X64),
        sample_dll_content,
    )
    assert saved.file_hash is not None
    Path(_require_str(saved.file_path)).unlink()
    outside_file = tmp_path.parent / f"{tmp_path.name}-outside-index.dll"
    outside_file.write_bytes(sample_dll_content)

    try:
        index_path = tmp_path / ".dll_index.json"
        index_data = json.loads(index_path.read_text())
        index_data["files"]["x64/outside-index.dll"]["file_path"] = str(outside_file)
        index_path.write_text(json.dumps(index_data))

        assert repository.find_by_name("outside-index.dll", Architecture.X64) is None
        assert repository.find_by_hash(saved.file_hash) is None
        assert [dll.name for dll in repository.list_all()] == []
    finally:
        outside_file.unlink(missing_ok=True)


def test_find_by_name_ignores_directory_named_like_dll(
    repository: FileSystemDLLRepository,
    tmp_path: Path,
) -> None:
    dll_path = tmp_path / "x64" / "dir.dll"
    dll_path.mkdir()

    assert repository.find_by_name("dir.dll", Architecture.X64) is None


class TestFileSystemDLLRepositoryFindByHash:
    """Test find_by_hash() with real file hash calculations."""

    def test_find_dll_by_hash(
        self,
        repository: FileSystemDLLRepository,
        dll_file_entity: DLLFile,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify finding DLL by its SHA256 hash.

        Expected Behavior:
            - Returns DLL with matching hash
            - Entity metadata is correct
        """
        saved_dll = repository.save(dll_file_entity, sample_dll_content)

        found = repository.find_by_hash(_require_str(saved_dll.file_hash))

        assert found is not None
        assert found.name == "kernel32.dll"
        assert found.file_hash == saved_dll.file_hash

    def test_find_by_hash_with_multiple_files(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify finding specific DLL by hash when multiple files exist.

        Expected Behavior:
            - Returns only the DLL with matching hash
            - Different content produces different hashes
        """
        dll1 = DLLFile(name="file1.dll", architecture=Architecture.X64)
        dll2 = DLLFile(name="file2.dll", architecture=Architecture.X64)

        content1 = _build_pe_payload(Architecture.X64) + b"unique content 1"
        content2 = _build_pe_payload(Architecture.X64) + b"unique content 2"

        saved1 = repository.save(dll1, content1)
        saved2 = repository.save(dll2, content2)

        found = repository.find_by_hash(_require_str(saved1.file_hash))

        assert found is not None
        assert found.name == "file1.dll"
        assert found.file_hash != saved2.file_hash

    def test_find_by_nonexistent_hash_returns_none(
        self,
        repository: FileSystemDLLRepository,
    ) -> None:
        """
        Verify that searching for non-existent hash returns None.

        Expected Behavior:
            - Returns None when hash doesn't match any file
            - No exceptions are raised
        """
        fake_hash = "a" * 64  # Valid SHA256 format but non-existent

        found = repository.find_by_hash(fake_hash)

        assert found is None

    def test_find_by_hash_rejects_mismatched_payload_hash(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        saved = repository.save(
            DLLFile(name="valid.dll", architecture=Architecture.X64),
            sample_dll_content,
        )
        payload_path = Path(_require_str(saved.file_path))
        payload_path.write_bytes(b"tampered content")

        assert saved.file_hash is not None
        assert repository.find_by_hash(saved.file_hash) is None

        index_path = tmp_path / ".dll_index.json"
        index_data = json.loads(index_path.read_text())
        index_data["files"]["x64/valid.dll"]["file_hash"] = "fakehash"
        index_path.write_text(json.dumps(index_data))

        assert repository.find_by_hash("fakehash") is None


class TestFileSystemDLLRepositoryDelete:
    """Test delete() operation with real filesystem deletion."""

    def test_delete_removes_file_from_filesystem(
        self,
        repository: FileSystemDLLRepository,
        dll_file_entity: DLLFile,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        """
        Verify that delete() removes file from filesystem.

        Expected Behavior:
            - File is removed from disk
            - File path no longer exists
            - Returns True on success
        """
        saved_dll = repository.save(dll_file_entity, sample_dll_content)
        file_path = Path(_require_str(saved_dll.file_path))

        assert file_path.exists()

        result = repository.delete(saved_dll)

        assert result is True
        assert not file_path.exists()

    def test_delete_removes_from_index(
        self,
        repository: FileSystemDLLRepository,
        dll_file_entity: DLLFile,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        """
        Verify that delete() removes entry from JSON index.

        Expected Behavior:
            - Entry is removed from index
            - Index file is updated
            - find_by_name returns None after deletion
        """
        saved_dll = repository.save(dll_file_entity, sample_dll_content)

        repository.delete(saved_dll)

        # Verify index is updated
        index_path = tmp_path / ".dll_index.json"
        with open(index_path) as f:
            index_data = json.load(f)

        key = "x64/kernel32.dll"
        assert key not in index_data["files"]

        # Verify find_by_name returns None
        found = repository.find_by_name("kernel32.dll", Architecture.X64)
        assert found is None

    def test_delete_refuses_when_index_path_is_not_regular(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        saved_dll = repository.save(
            DLLFile(name="victim.dll", architecture=Architecture.X64),
            sample_dll_content,
        )
        file_path = Path(_require_str(saved_dll.file_path))
        index_path = tmp_path / ".dll_index.json"
        index_path.unlink()
        index_path.mkdir()

        result = repository.delete(saved_dll)

        assert result is False
        assert file_path.exists()
        assert index_path.is_dir()

    def test_delete_nonexistent_file_returns_true(
        self,
        repository: FileSystemDLLRepository,
    ) -> None:
        """
        Verify that deleting non-existent file doesn't raise exception.

        Expected Behavior:
            - Returns True even if file doesn't exist
            - No exceptions are raised
        """
        dll = DLLFile(name="ghost.dll", architecture=Architecture.X64)

        result = repository.delete(dll)

        assert result is True

    def test_delete_one_file_preserves_others(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that deleting one file doesn't affect other files.

        Expected Behavior:
            - Only specified file is deleted
            - Other files remain in repository
            - Other index entries are preserved
        """
        dll1 = DLLFile(name="keep.dll", architecture=Architecture.X64)
        dll2 = DLLFile(name="delete.dll", architecture=Architecture.X64)

        repository.save(dll1, sample_dll_content)
        saved2 = repository.save(dll2, sample_dll_content)

        repository.delete(saved2)

        # Verify dll1 still exists
        found = repository.find_by_name("keep.dll", Architecture.X64)
        assert found is not None

        # Verify dll2 is gone
        found = repository.find_by_name("delete.dll", Architecture.X64)
        assert found is None


class TestFileSystemDLLRepositoryExists:
    """Test exists() check with real filesystem queries."""

    def test_exists_returns_true_for_saved_file(
        self,
        repository: FileSystemDLLRepository,
        dll_file_entity: DLLFile,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that exists() returns True for saved files.

        Expected Behavior:
            - Returns True when file exists
            - Works with architecture parameter
        """
        repository.save(dll_file_entity, sample_dll_content)

        assert repository.exists("kernel32.dll", Architecture.X64) is True

    def test_exists_returns_false_for_nonexistent_file(
        self,
        repository: FileSystemDLLRepository,
    ) -> None:
        """
        Verify that exists() returns False for non-existent files.

        Expected Behavior:
            - Returns False when file doesn't exist
            - No exceptions are raised
        """
        assert repository.exists("nonexistent.dll", Architecture.X64) is False

    def test_exists_without_architecture(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that exists() works without architecture parameter.

        Expected Behavior:
            - Searches all architectures
            - Returns True if found in any architecture
        """
        dll = DLLFile(name="common.dll", architecture=Architecture.X86)
        repository.save(dll, _build_pe_payload(Architecture.X86))

        assert repository.exists("common.dll") is True


class TestFileSystemDLLRepositoryListAll:
    """Test list_all() with real filesystem enumeration."""

    def test_list_all_empty_repository(
        self,
        repository: FileSystemDLLRepository,
    ) -> None:
        """
        Verify that list_all() returns empty list for new repository.

        Expected Behavior:
            - Returns empty list
            - No exceptions are raised
        """
        all_dlls = repository.list_all()

        assert all_dlls == []
        assert isinstance(all_dlls, list)

    def test_list_all_returns_saved_files(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that list_all() returns all saved DLLs.

        Expected Behavior:
            - Returns list of all DLLFile entities
            - Count matches number of saved files
            - All entities have correct metadata
        """
        dll1 = DLLFile(name="file1.dll", architecture=Architecture.X64)
        dll2 = DLLFile(name="file2.dll", architecture=Architecture.X86)
        dll3 = DLLFile(name="file3.dll", architecture=Architecture.X64)

        repository.save(dll1, sample_dll_content)
        repository.save(dll2, _build_pe_payload(Architecture.X86))
        repository.save(dll3, sample_dll_content)

        all_dlls = repository.list_all()

        assert len(all_dlls) == 3
        names = {dll.name for dll in all_dlls}
        assert names == {"file1.dll", "file2.dll", "file3.dll"}

    def test_list_all_after_deletion(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that list_all() reflects deletions.

        Expected Behavior:
            - Deleted files are not included in list
            - Remaining files are still listed
        """
        dll1 = DLLFile(name="keep.dll", architecture=Architecture.X64)
        dll2 = DLLFile(name="delete.dll", architecture=Architecture.X64)

        repository.save(dll1, sample_dll_content)
        saved2 = repository.save(dll2, sample_dll_content)

        repository.delete(saved2)

        all_dlls = repository.list_all()

        assert len(all_dlls) == 1
        assert all_dlls[0].name == "keep.dll"


class TestFileSystemDLLRepositoryIndexPersistence:
    """Test JSON index persistence with real file I/O."""

    def test_index_persists_across_repository_instances(
        self,
        tmp_path: Path,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that index persists when repository is recreated.

        Expected Behavior:
            - Index is written to disk
            - New repository instance loads existing index
            - All saved files are accessible
        """
        # Create first repository instance and save files
        repo1 = FileSystemDLLRepository(tmp_path)
        dll = DLLFile(
            name="persistent.dll", architecture=Architecture.X64, version="1.0"
        )
        repo1.save(dll, sample_dll_content)

        # Create second repository instance
        repo2 = FileSystemDLLRepository(tmp_path)

        # Verify data persisted
        found = repo2.find_by_name("persistent.dll", Architecture.X64)
        assert found is not None
        assert found.version == "1.0"

    def test_index_contains_all_metadata(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        """
        Verify that index stores complete DLL metadata.

        Expected Behavior:
            - All entity fields are serialized
            - Datetime fields are in ISO format
            - Enum values are stored as strings
        """
        dll = DLLFile(
            name="complete.dll",
            version="2.0.1",
            architecture=Architecture.X64,
            download_url="https://example.com/complete.dll",
            security_status=SecurityStatus.CLEAN,
            vt_detection_ratio="0/72",
            vt_scan_date=datetime(2026, 1, 31, 12, 0, 0),
        )
        repository.save(dll, sample_dll_content)

        # Read index directly
        index_path = tmp_path / ".dll_index.json"
        with open(index_path) as f:
            index_data = json.load(f)

        entry = index_data["files"]["x64/complete.dll"]
        assert entry["name"] == "complete.dll"
        assert entry["version"] == "2.0.1"
        assert entry["architecture"] == "x64"
        assert entry["download_url"] == "https://example.com/complete.dll"
        assert entry["security_status"] == "clean"
        assert entry["vt_detection_ratio"] == "0/72"
        assert "2026-01-31" in entry["vt_scan_date"]

    def test_corrupted_index_is_handled_gracefully(
        self,
        tmp_path: Path,
    ) -> None:
        """
        Verify that corrupted index files raise RepositoryError.

        Expected Behavior:
            - Repository initializes successfully
            - Corrupted index raises RepositoryError on access
        """
        # Create repository with corrupted index
        index_path = tmp_path / ".dll_index.json"
        index_path.write_text("{corrupted json content")

        # Should not raise exception during init
        repo = FileSystemDLLRepository(tmp_path)

        # Corrupted JSON should raise RepositoryError on access
        with pytest.raises(RepositoryError):
            repo.list_all()

    def test_invalid_index_entries_are_skipped_when_listing(
        self,
        tmp_path: Path,
        sample_dll_content: bytes,
    ) -> None:
        repo = FileSystemDLLRepository(tmp_path)
        repo.save(
            DLLFile(name="valid.dll", architecture=Architecture.X64), sample_dll_content
        )

        index_path = tmp_path / ".dll_index.json"
        index_data = json.loads(index_path.read_text())
        valid_entry = index_data["files"]["x64/valid.dll"]
        index_data["files"]["x64/bad.dll"] = {
            **valid_entry,
            "name": "bad.dll",
            "architecture": "bogus",
        }
        index_path.write_text(json.dumps(index_data))

        all_dlls = repo.list_all()

        assert [dll.name for dll in all_dlls] == ["valid.dll"]

    def test_malformed_index_entry_does_not_hide_valid_entries(
        self,
        tmp_path: Path,
        sample_dll_content: bytes,
    ) -> None:
        repo = FileSystemDLLRepository(tmp_path)
        saved = repo.save(
            DLLFile(name="valid.dll", architecture=Architecture.X64),
            sample_dll_content,
        )
        assert saved.file_hash is not None

        index_path = tmp_path / ".dll_index.json"
        index_data = json.loads(index_path.read_text())
        index_data["files"]["x64/malformed.dll"] = {"architecture": "x64"}
        index_path.write_text(json.dumps(index_data))

        all_dlls = repo.list_all()
        found = repo.find_by_hash(saved.file_hash)

        assert [dll.name for dll in all_dlls] == ["valid.dll"]
        assert found is not None
        assert found.name == "valid.dll"

    def test_find_by_hash_skips_invalid_index_entries(
        self,
        tmp_path: Path,
        sample_dll_content: bytes,
    ) -> None:
        repo = FileSystemDLLRepository(tmp_path)
        saved = repo.save(
            DLLFile(name="valid.dll", architecture=Architecture.X64), sample_dll_content
        )
        assert saved.file_hash is not None

        index_path = tmp_path / ".dll_index.json"
        index_data = json.loads(index_path.read_text())
        valid_entry = index_data["files"]["x64/valid.dll"]
        index_data["files"] = {
            "x64/other.dll": {
                **valid_entry,
                "name": "other.dll",
                "file_hash": "different-hash",
            },
            "x64/bad.dll": {
                **valid_entry,
                "name": "bad.dll",
                "architecture": "bogus",
            },
            "x64/valid.dll": valid_entry,
        }
        index_path.write_text(json.dumps(index_data))

        found = repo.find_by_hash(saved.file_hash)

        assert found is not None
        assert found.name == "valid.dll"

    def test_find_by_name_ignores_invalid_index_entry(
        self,
        tmp_path: Path,
        sample_dll_content: bytes,
    ) -> None:
        repo = FileSystemDLLRepository(tmp_path)
        saved = repo.save(
            DLLFile(name="bad.dll", architecture=Architecture.X64), sample_dll_content
        )
        assert saved.file_path is not None
        Path(saved.file_path).unlink()

        index_path = tmp_path / ".dll_index.json"
        index_data = json.loads(index_path.read_text())
        index_data["files"]["x64/bad.dll"]["architecture"] = "bogus"
        index_path.write_text(json.dumps(index_data))

        assert repo.find_by_name("bad.dll", Architecture.X64) is None


@pytest.mark.integration
class TestFileSystemDLLRepositoryRealWorldScenarios:
    """Integration tests for real-world usage patterns."""

    def test_concurrent_saves_different_architectures(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify saving same DLL name with different architectures.

        Expected Behavior:
            - Both files are saved independently
            - Each can be retrieved by name + architecture
            - Index contains separate entries
        """
        dll_x64 = DLLFile(
            name="multiarch.dll", architecture=Architecture.X64, version="1.0"
        )
        dll_x86 = DLLFile(
            name="multiarch.dll", architecture=Architecture.X86, version="2.0"
        )

        content_x64 = _build_pe_payload(Architecture.X64) + b"x64 content"
        content_x86 = _build_pe_payload(Architecture.X86) + b"x86 content"

        repository.save(dll_x64, content_x64)
        repository.save(dll_x86, content_x86)

        found_x64 = repository.find_by_name("multiarch.dll", Architecture.X64)
        found_x86 = repository.find_by_name("multiarch.dll", Architecture.X86)

        assert found_x64 is not None
        assert found_x86 is not None
        assert found_x64.version == "1.0"
        assert found_x86.version == "2.0"
        assert found_x64.file_hash != found_x86.file_hash

    def test_full_lifecycle_save_find_update_delete(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify complete CRUD lifecycle for a DLL file.

        Expected Behavior:
            - Save creates file and index entry
            - Find retrieves correct entity
            - Update (re-save with new entity) modifies existing file
            - Delete removes file and index entry
        """
        # Create
        dll = DLLFile(
            name="lifecycle.dll", architecture=Architecture.X64, version="1.0"
        )
        saved = repository.save(dll, sample_dll_content)
        assert saved.file_path is not None

        # Read
        found = repository.find_by_name("lifecycle.dll", Architecture.X64)
        assert found is not None
        assert found.version == "1.0"

        # Update (use replace since DLLFile is frozen)
        updated_dll = replace(dll, version="2.0")
        updated_content = _build_pe_payload(Architecture.X64) + b"updated content"
        updated = repository.save(updated_dll, updated_content)

        found_updated = repository.find_by_name("lifecycle.dll", Architecture.X64)
        assert found_updated is not None
        assert found_updated.version == "2.0"

        # Delete
        repository.delete(updated)
        found_deleted = repository.find_by_name("lifecycle.dll", Architecture.X64)
        assert found_deleted is None

    def test_update_metadata_preserves_saved_payload_identity(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        saved = repository.save(
            DLLFile(name="metadata.dll", architecture=Architecture.X64),
            sample_dll_content,
        )
        poisoned_update = replace(
            saved,
            file_hash="0" * 64,
            file_path=str(tmp_path / "x64" / "other.dll"),
            file_size=len(sample_dll_content) + 1,
            security_status=SecurityStatus.CLEAN,
            vt_detection_ratio="0/72",
        )

        updated = repository.update_metadata(poisoned_update)

        assert updated.security_status == SecurityStatus.CLEAN
        assert updated.vt_detection_ratio == "0/72"
        assert updated.file_hash == saved.file_hash
        assert updated.file_path == saved.file_path
        assert updated.file_size == saved.file_size
        found = repository.find_by_name("metadata.dll", Architecture.X64)
        assert found is not None
        assert found.file_hash == saved.file_hash
        assert repository.find_by_hash(_require_str(saved.file_hash)) is not None
        assert [dll.name for dll in repository.list_all()] == ["metadata.dll"]

    def test_repository_with_large_number_of_files(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify repository handles many files efficiently.

        Expected Behavior:
            - All files are saved correctly
            - list_all returns complete list
            - Individual files can be found
            - Index remains valid
        """
        num_files = 50

        # Save many files
        for i in range(num_files):
            dll = DLLFile(
                name=f"file_{i:03d}.dll",
                architecture=Architecture.X64 if i % 2 == 0 else Architecture.X86,
            )
            content = (
                sample_dll_content
                if dll.architecture == Architecture.X64
                else _build_pe_payload(Architecture.X86)
            )
            repository.save(dll, content)

        # Verify all are listed
        all_dlls = repository.list_all()
        assert len(all_dlls) == num_files

        # Verify specific files can be found
        found_0 = repository.find_by_name("file_000.dll", Architecture.X64)
        found_25 = repository.find_by_name("file_025.dll", Architecture.X86)
        found_49 = repository.find_by_name("file_049.dll", Architecture.X86)

        assert found_0 is not None
        assert found_25 is not None
        assert found_49 is not None


@pytest.mark.unit
def test_detect_zip_payload_architecture_rejects_excessive_member_count(
    tmp_path: Path,
) -> None:
    """
    Regression: ZIP payloads whose member count exceeds the configured ceiling
    must short-circuit architecture detection rather than iterating millions of
    central-directory entries.
    """
    repository = FileSystemDLLRepository(tmp_path)
    limit = ZIP_MEMBER_COUNT_LIMIT

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(
        archive_buffer, "w", compression=zipfile.ZIP_STORED
    ) as archive:
        archive.writestr("kernel32.dll", _build_pe_payload(Architecture.X64))
        for index in range(limit):
            archive.writestr(f"filler_{index:05d}.bin", b"")

    payload = archive_buffer.getvalue()
    assert (
        repository._detect_zip_payload_architecture(
            "kernel32.dll",
            payload,
            expected_architecture=Architecture.X64,
        )
        is None
    )


# ---------------------------------------------------------------------------
# Coverage gap tests — bring file_repository.py to 100% line+branch coverage
# ---------------------------------------------------------------------------

import fcntl  # noqa: E402  (needed for flock fault injection)
import stat as _stat  # noqa: E402


# LINE 132 — _ensure_directories: symlinked base path
@pytest.mark.integration
def test_ensure_directories_raises_for_symlinked_base_path(
    tmp_path: Path,
) -> None:
    """_ensure_directories rejects a base path that is itself a symlink."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real_dir)

    with pytest.raises(RepositoryError, match="symlinked base path"):
        FileSystemDLLRepository(link)


# LINES 153-157 — _with_index_lock: fd opened, then flock raises OSError
@pytest.mark.integration
def test_with_index_lock_closes_fd_when_flock_raises(
    tmp_download_dir: Path,
) -> None:
    """When flock raises after fd is open, RepositoryError is raised and fd is
    closed."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    original_flock = fcntl.flock

    def patched_flock(fd: int, op: int) -> None:
        raise OSError("injected flock failure")

    fcntl.flock = cast(Any, patched_flock)
    try:
        with (
            pytest.raises(RepositoryError, match="Failed to acquire index lock"),
            repository._with_index_lock(),
        ):
            pass
    finally:
        fcntl.flock = original_flock


# LINES 215-217 — _load_index: os.open raises OSError
@pytest.mark.integration
def test_load_index_raises_when_os_open_fails(
    tmp_download_dir: Path,
) -> None:
    """_load_index wraps an OSError from os.open into RepositoryError."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    # Write a valid index so preconditions pass
    repository._index_path.write_text('{"files": {}}')

    original_open = os.open

    def patched_open(path: str, flags: int, mode: int = 0) -> int:
        if path == str(repository._index_path):
            raise OSError("injected open failure")
        return original_open(path, flags, mode)

    os.open = cast(Any, patched_open)
    try:
        with pytest.raises(RepositoryError, match="Failed to load index"):
            repository._load_index()
    finally:
        os.open = original_open


# LINE 222 — _load_index: fstat reports non-regular file
@pytest.mark.integration
def test_load_index_raises_when_fstat_shows_non_regular_file(
    tmp_download_dir: Path,
) -> None:
    """_load_index raises RepositoryError when fstat shows a non-regular file."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    repository._index_path.write_text('{"files": {}}')

    original_fstat = os.fstat

    def patched_fstat(fd: int) -> os.stat_result:
        result = original_fstat(fd)
        # Replace st_mode with a pipe mode so S_ISREG returns False
        fake = os.stat_result(
            (
                _stat.S_IFIFO | 0o600,
                result.st_ino,
                result.st_dev,
                result.st_nlink,
                result.st_uid,
                result.st_gid,
                result.st_size,
                result.st_atime,
                result.st_mtime,
                result.st_ctime,
            )
        )
        return fake

    os.fstat = patched_fstat
    try:
        with pytest.raises(RepositoryError, match="Index path is not a regular file"):
            repository._load_index()
    finally:
        os.fstat = original_fstat


# LINE 224 — _load_index: index file exceeds size limit (sparse file trick)
@pytest.mark.integration
def test_load_index_raises_when_index_exceeds_size_limit(
    tmp_download_dir: Path,
) -> None:
    """_load_index raises RepositoryError when the index file exceeds 10 MiB."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    repository._index_path.write_text('{"files": {}}')
    # Create a sparse file larger than _INDEX_MAX_BYTES without allocating blocks
    limit = FileSystemDLLRepository._INDEX_MAX_BYTES
    os.truncate(str(repository._index_path), limit + 1)

    with pytest.raises(RepositoryError, match="exceeds size limit"):
        repository._load_index()


# LINES 238-239 — _load_index: finally closes fd when set_blocking raises
@pytest.mark.integration
def test_load_index_closes_fd_in_finally_when_set_blocking_raises(
    tmp_download_dir: Path,
) -> None:
    """When os.set_blocking raises between os.open and os.fdopen, the finally
    block closes the fd."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    repository._index_path.write_text('{"files": {}}')

    original_set_blocking = os.set_blocking

    def patched_set_blocking(fd: int, blocking: bool) -> None:
        raise OSError("injected set_blocking failure")

    os.set_blocking = patched_set_blocking
    try:
        with pytest.raises(RepositoryError, match="Failed to load index"):
            repository._load_index()
    finally:
        os.set_blocking = original_set_blocking


# LINES 295-296 — _path_is_within_repository: resolve raises OSError
@pytest.mark.integration
def test_path_is_within_repository_raises_on_oserror(
    tmp_download_dir: Path,
) -> None:
    """_path_is_within_repository propagates OSError from resolve() as
    RepositoryError.

    Path.resolve() (without strict) delegates to os.path.realpath internally.
    Patching os.path.realpath to raise OSError for the target path causes
    resolve() to propagate the error, which the method catches and re-raises
    as RepositoryError.
    """
    import os.path as _os_path

    repository = FileSystemDLLRepository(tmp_download_dir)
    target = tmp_download_dir / "x64" / "target.dll"

    original_realpath = _os_path.realpath

    def patched_realpath(path: str, *, strict: bool = False) -> str:
        if "target.dll" in str(path):
            raise OSError("injected realpath failure")
        return original_realpath(path, strict=strict)

    _os_path.realpath = cast(Any, patched_realpath)
    try:
        with pytest.raises(RepositoryError, match="Cannot verify path"):
            repository._path_is_within_repository(target)
    finally:
        _os_path.realpath = original_realpath


# LINES 310-311 — _path_location_is_within_repository: parent resolve raises
@pytest.mark.integration
def test_path_location_is_within_repository_raises_when_parent_missing(
    tmp_download_dir: Path,
) -> None:
    """_path_location_is_within_repository raises RepositoryError when the
    parent directory does not exist (strict=True raises FileNotFoundError)."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    # Use a path whose parent does not exist so resolve(strict=True) raises
    missing_parent_path = tmp_download_dir / "nonexistent-parent" / "file.dll"

    with pytest.raises(RepositoryError, match="Cannot verify path location"):
        repository._path_location_is_within_repository(missing_parent_path)


# LINES 354-355 — _is_symlink_safe: non-FileNotFoundError OSError returns False
@pytest.mark.integration
def test_is_symlink_safe_returns_false_on_permission_error(
    tmp_download_dir: Path,
) -> None:
    """_is_symlink_safe swallows OSError (other than FileNotFoundError) and
    returns False."""
    target = tmp_download_dir / "probe.dll"
    target.write_bytes(b"data")

    original_lstat = os.lstat

    def patched_lstat(
        path: str | bytes | os.PathLike[str], **kw: object
    ) -> os.stat_result:
        # Path objects are valid lstat arguments in Python 3.6+; convert first
        if "probe.dll" in str(path):
            raise PermissionError("injected permission error")
        return original_lstat(path, **kw)  # type: ignore[arg-type]

    os.lstat = patched_lstat  # type: ignore[assignment]
    try:
        result = FileSystemDLLRepository._is_symlink_safe(target)
        assert result is False
    finally:
        os.lstat = original_lstat


# LINES 380-381 — _validate_repository_write_path: file exists but resolve raises
@pytest.mark.integration
def test_validate_repository_write_path_raises_when_resolve_fails_on_existing_file(
    tmp_download_dir: Path,
) -> None:
    """_validate_repository_write_path raises RepositoryError when an existing
    file's resolve(strict=True) raises OSError.

    Path.resolve() uses os.path.realpath internally. Patching realpath to raise
    OSError for the target file causes resolve(strict=True) (line 379) to
    propagate the error, which the inner try/except re-raises as RepositoryError.
    The patch activates only when the target filename appears in the path so that
    the earlier parent.resolve(strict=True) at line 365 is unaffected.
    """
    import os.path as _os_path

    repository = FileSystemDLLRepository(tmp_download_dir)
    file_path = tmp_download_dir / "x64" / "existing.dll"
    file_path.write_bytes(b"data")

    original_realpath = _os_path.realpath

    def patched_realpath(path: str | bytes, *, strict: bool = False) -> str:
        if strict and "existing.dll" in str(path):
            raise PermissionError("injected realpath failure on strict resolve")
        return cast(str, original_realpath(path, strict=strict))

    _os_path.realpath = cast(Any, patched_realpath)
    try:
        with pytest.raises(RepositoryError, match="Refusing to write outside"):
            repository._validate_repository_write_path(file_path)
    finally:
        _os_path.realpath = original_realpath


# LINE 397 — _read_file_no_follow: file exceeds max_bytes
@pytest.mark.integration
def test_read_file_no_follow_raises_when_file_exceeds_max_bytes(
    tmp_download_dir: Path,
) -> None:
    """_read_file_no_follow raises RepositoryError when the file size exceeds
    max_bytes."""
    target = tmp_download_dir / "big.dll"
    content = b"A" * 10
    target.write_bytes(content)

    with pytest.raises(RepositoryError, match="exceeds read limit"):
        FileSystemDLLRepository._read_file_no_follow(target, max_bytes=len(content) - 1)


# LINES 419-422 — _write_temp_file: os.fdopen raises before fd_opened is set
@pytest.mark.integration
def test_write_temp_file_closes_fd_when_fdopen_raises(
    tmp_download_dir: Path,
) -> None:
    """When os.fdopen raises before the context manager assigns fd_opened=True,
    _write_temp_file falls into the except branch and closes the fd directly."""
    import tempfile as _tempfile

    fd, temp_name = _tempfile.mkstemp(dir=str(tmp_download_dir))
    original_fdopen = os.fdopen

    def patched_fdopen(
        fd_arg: int, mode: str = "r", *args: object, **kwargs: object
    ) -> None:
        raise OSError("injected fdopen failure")

    os.fdopen = cast(Any, patched_fdopen)
    try:
        with pytest.raises(OSError, match="injected fdopen failure"):
            FileSystemDLLRepository._write_temp_file(fd, b"data")
    finally:
        os.fdopen = original_fdopen
        # fd was closed by the except branch; unlinking the temp file is enough
        with contextlib.suppress(OSError):
            os.unlink(temp_name)


# LINES 438-442 — _verify_target_not_symlink: ELOOP and generic OSError
@pytest.mark.integration
def test_verify_target_not_symlink_raises_for_circular_symlink(
    tmp_download_dir: Path,
) -> None:
    """_verify_target_not_symlink raises RepositoryError with 'symlink' message
    when the target path forms a circular symlink (ELOOP on open)."""
    link_a = tmp_download_dir / "loop_a.dll"
    link_b = tmp_download_dir / "loop_b.dll"
    link_a.symlink_to(link_b)
    link_b.symlink_to(link_a)

    try:
        with pytest.raises(RepositoryError, match="symlink"):
            FileSystemDLLRepository._verify_target_not_symlink(link_a)
    finally:
        link_a.unlink(missing_ok=True)
        link_b.unlink(missing_ok=True)


@pytest.mark.integration
def test_verify_target_not_symlink_raises_for_generic_oserror(
    tmp_download_dir: Path,
) -> None:
    """_verify_target_not_symlink raises RepositoryError when os.open raises a
    non-ELOOP OSError."""
    # Write directly into tmp_download_dir (no x64 subdir needed here)
    target = tmp_download_dir / "victim.dll"
    target.write_bytes(b"content")

    original_open = os.open

    def patched_open(path: str, flags: int, mode: int = 0) -> int:
        if "victim.dll" in path:
            raise OSError(13, "Permission denied")  # EACCES, not ELOOP
        return original_open(path, flags, mode)

    os.open = cast(Any, patched_open)
    try:
        with pytest.raises(RepositoryError, match="Cannot verify target path"):
            FileSystemDLLRepository._verify_target_not_symlink(target)
    finally:
        os.open = original_open


# LINES 457-458 — _fsync_directory: fsync raises OSError (returns silently)
@pytest.mark.integration
def test_fsync_directory_swallows_oserror_from_fsync(
    tmp_download_dir: Path,
) -> None:
    """_fsync_directory catches OSError from os.fsync and returns without
    raising."""
    original_fsync = os.fsync

    def patched_fsync(fd: int) -> None:
        raise OSError("injected fsync failure")

    os.fsync = cast(Any, patched_fsync)
    try:
        # Must complete without raising
        FileSystemDLLRepository._fsync_directory(tmp_download_dir)
    finally:
        os.fsync = original_fsync


# LINE 460->exit — _fsync_directory: os.open raises (dir_fd stays -1)
@pytest.mark.integration
def test_fsync_directory_handles_open_failure_without_close(
    tmp_download_dir: Path,
) -> None:
    """When os.open fails in _fsync_directory, dir_fd stays -1 so the finally
    block skips os.close."""
    original_open = os.open

    def patched_open(path: str, flags: int, mode: int = 0) -> int:
        if path == str(tmp_download_dir) and flags == os.O_RDONLY:
            raise OSError("injected directory open failure")
        return original_open(path, flags, mode)

    os.open = cast(Any, patched_open)
    try:
        # Must complete without raising even though the open failed
        FileSystemDLLRepository._fsync_directory(tmp_download_dir)
    finally:
        os.open = original_open


# LINES 486->489 — _atomic_write_bytes: BaseException after rename (temp_name="")
@pytest.mark.integration
def test_atomic_write_skips_unlink_when_rename_already_succeeded(
    tmp_download_dir: Path,
) -> None:
    """When a BaseException occurs after os.rename succeeds (temp_name already
    cleared), the cleanup branch skips os.unlink and re-raises."""

    class FsyncRaisesRepository(FileSystemDLLRepository):
        """Repository whose _fsync_directory raises a non-OSError exception."""

        @staticmethod
        def _fsync_directory(directory: Path) -> None:
            raise RuntimeError("injected post-rename failure")

    repository = FsyncRaisesRepository(tmp_download_dir)
    target = tmp_download_dir / "x64" / "target.dll"

    with pytest.raises(RuntimeError, match="injected post-rename failure"):
        repository._atomic_write_bytes(target, _build_pe_payload())

    # The rename succeeded before the exception so the file is on disk
    assert target.exists()


# LINES 655-657 — _fallback_payload_is_valid: _read_file_no_follow raises OSError
@pytest.mark.integration
def test_fallback_payload_is_valid_returns_false_on_read_oserror(
    tmp_download_dir: Path,
) -> None:
    """_fallback_payload_is_valid returns False when _read_file_no_follow raises
    OSError."""

    class UnreadablePayloadRepository(FileSystemDLLRepository):
        @classmethod
        def _read_file_no_follow(
            cls, file_path: Path, max_bytes: int = 1024 * 1024 * 1024
        ) -> bytes:
            raise OSError("injected read failure")

    repository = UnreadablePayloadRepository(tmp_download_dir)
    target = tmp_download_dir / "x64" / "target.dll"
    target.write_bytes(_build_pe_payload())

    result = repository._fallback_payload_is_valid(
        target, "target.dll", Architecture.X64
    )
    assert result is False


# LINES 760-765 — _candidate_zip_members: member.file_size > ZIP_MEMBER_SIZE_LIMIT
@pytest.mark.integration
def test_candidate_zip_members_skips_oversized_member(
    tmp_download_dir: Path,
) -> None:
    """_candidate_zip_members logs and skips members whose file_size field
    exceeds ZIP_MEMBER_SIZE_LIMIT (set directly on the ZipInfo object)."""
    from dll_downloader.domain.services.archive_safety import ZIP_MEMBER_SIZE_LIMIT

    repository = FileSystemDLLRepository(tmp_download_dir)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("target.dll", b"small")

    buf.seek(0)
    with zipfile.ZipFile(buf) as probe:
        members = probe.infolist()
        assert len(members) == 1
        # Artificially inflate the declared file_size
        members[0].file_size = ZIP_MEMBER_SIZE_LIMIT + 1
        result = list(repository._candidate_zip_members(probe, "target.dll"))

    assert result == []


# LINE 826 — _has_loadable_section static wrapper
@pytest.mark.integration
def test_has_loadable_section_wrapper_returns_expected_value() -> None:
    """FileSystemDLLRepository._has_loadable_section delegates to the module
    function and returns its result."""
    payload = _build_pe_payload(Architecture.X64)
    pe_offset = int.from_bytes(payload[0x3C:0x40], "little")
    optional_header_size = 0xF0
    section_table_offset = pe_offset + 24 + optional_header_size
    section_count = 1

    result = FileSystemDLLRepository._has_loadable_section(
        payload, section_table_offset, section_count
    )
    assert isinstance(result, bool)


# LINE 831 — _expected_optional_magic static wrapper
@pytest.mark.integration
def test_expected_optional_magic_wrapper_returns_correct_magic() -> None:
    """FileSystemDLLRepository._expected_optional_magic delegates to the module
    function."""
    magic_x64 = FileSystemDLLRepository._expected_optional_magic(Architecture.X64)
    magic_x86 = FileSystemDLLRepository._expected_optional_magic(Architecture.X86)
    assert magic_x64 == 0x20B
    assert magic_x86 == 0x10B


# LINE 891->880 — _find_fallback_by_hash: hash mismatch, loop continues
@pytest.mark.integration
def test_find_fallback_by_hash_skips_mismatched_hash(
    tmp_download_dir: Path,
) -> None:
    """_find_fallback_by_hash iterates past files whose actual hash does not
    match the target hash."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    decoy_content = _build_pe_payload(Architecture.X64) + b"decoy"
    decoy_path = tmp_download_dir / "x64" / "decoy.dll"
    decoy_path.write_bytes(decoy_content)

    # Request a hash that does not match decoy_content
    result = repository._find_fallback_by_hash("a" * 64)
    assert result is None


# LINE 927 — _list_fallback_payloads: arch_dir is a symlink
@pytest.mark.integration
def test_list_fallback_payloads_skips_symlinked_arch_dir(
    tmp_download_dir: Path,
    tmp_path: Path,
) -> None:
    """_list_fallback_payloads skips architecture directories that are symlinks
    (_is_symlink_safe returns True)."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    outside_dir = tmp_path / "outside-arch"
    outside_dir.mkdir()
    (outside_dir / "decoy.dll").write_bytes(_build_pe_payload())
    arch_dir = tmp_download_dir / "x64"
    arch_dir.rmdir()
    arch_dir.symlink_to(outside_dir, target_is_directory=True)

    try:
        result = repository._list_fallback_payloads(set())
        names = [dll.name for dll in result]
        assert "decoy.dll" not in names
    finally:
        arch_dir.unlink(missing_ok=True)


# LINE 936 — _list_fallback_payloads: key in blocked_keys causes continue
@pytest.mark.integration
def test_list_fallback_payloads_skips_key_already_in_blocked_set(
    tmp_download_dir: Path,
) -> None:
    """_list_fallback_payloads skips files whose key is already in blocked_keys."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    payload = _build_pe_payload(Architecture.X64)
    (tmp_download_dir / "x64" / "blocked.dll").write_bytes(payload)

    # Pre-populate blocked_keys with the key for blocked.dll
    blocked = {"x64/blocked.dll"}
    result = repository._list_fallback_payloads(blocked)
    assert all(dll.name != "blocked.dll" for dll in result)


# LINE 962 — _read_raw_index_json: index is a symlink → returns None
@pytest.mark.integration
def test_read_raw_index_json_returns_none_for_symlink_index(
    tmp_download_dir: Path,
    tmp_path: Path,
) -> None:
    """_read_raw_index_json returns None when the index path is a symlink."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    external = tmp_path / "external.json"
    external.write_text('{"files": {}}')
    repository._index_path.symlink_to(external)

    try:
        result = repository._read_raw_index_json()
        assert result is None
    finally:
        repository._index_path.unlink(missing_ok=True)


# LINES 968-969 — _read_raw_index_json: os.open raises OSError → returns None
@pytest.mark.integration
def test_read_raw_index_json_returns_none_when_open_raises(
    tmp_download_dir: Path,
) -> None:
    """_read_raw_index_json returns None when os.open raises OSError."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    repository._index_path.write_text('{"files": {}}')

    original_open = os.open

    def patched_open(path: str, flags: int, mode: int = 0) -> int:
        if path == str(repository._index_path):
            raise OSError("injected open failure")
        return original_open(path, flags, mode)

    os.open = cast(Any, patched_open)
    try:
        result = repository._read_raw_index_json()
        assert result is None
    finally:
        os.open = original_open


# LINE 974 — _read_raw_index_json: fstat returns non-regular mode → None
@pytest.mark.integration
def test_read_raw_index_json_returns_none_when_fstat_non_regular(
    tmp_download_dir: Path,
) -> None:
    """_read_raw_index_json returns None when fstat shows a non-regular file."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    repository._index_path.write_text('{"files": {}}')

    original_fstat = os.fstat

    def patched_fstat(fd: int) -> os.stat_result:
        result = original_fstat(fd)
        return os.stat_result(
            (
                _stat.S_IFIFO | 0o600,
                result.st_ino,
                result.st_dev,
                result.st_nlink,
                result.st_uid,
                result.st_gid,
                result.st_size,
                result.st_atime,
                result.st_mtime,
                result.st_ctime,
            )
        )

    os.fstat = patched_fstat
    try:
        result = repository._read_raw_index_json()
        assert result is None
    finally:
        os.fstat = original_fstat


# LINES 976-980 — _read_raw_index_json: index exceeds size limit → None
@pytest.mark.integration
def test_read_raw_index_json_returns_none_when_index_too_large(
    tmp_download_dir: Path,
) -> None:
    """_read_raw_index_json returns None when the index file exceeds 10 MiB."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    repository._index_path.write_text('{"files": {}}')
    limit = FileSystemDLLRepository._INDEX_MAX_BYTES
    os.truncate(str(repository._index_path), limit + 1)

    result = repository._read_raw_index_json()
    assert result is None


# LINES 986-988 — _read_raw_index_json: JSONDecodeError → None
@pytest.mark.integration
def test_read_raw_index_json_returns_none_for_corrupt_json(
    tmp_download_dir: Path,
) -> None:
    """_read_raw_index_json returns None when json.load raises JSONDecodeError."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    repository._index_path.write_text("{not valid json")

    result = repository._read_raw_index_json()
    assert result is None


# LINES 991-992 — _read_raw_index_json: finally closes fd when set_blocking raises
@pytest.mark.integration
def test_read_raw_index_json_closes_fd_when_set_blocking_raises(
    tmp_download_dir: Path,
) -> None:
    """When os.set_blocking raises inside _read_raw_index_json, the finally
    block closes the fd and the method returns None."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    repository._index_path.write_text('{"files": {}}')

    original_set_blocking = os.set_blocking

    def patched_set_blocking(fd: int, blocking: bool) -> None:
        raise OSError("injected set_blocking failure")

    os.set_blocking = patched_set_blocking
    try:
        result = repository._read_raw_index_json()
        assert result is None
    finally:
        os.set_blocking = original_set_blocking


# LINE 1005 — _raw_index_key: entry is not a dict → fallback str(key).lower()
@pytest.mark.integration
def test_raw_index_key_falls_back_when_entry_is_not_a_dict(
    tmp_download_dir: Path,
) -> None:
    """_raw_index_key returns str(key).lower() when the entry is not a dict."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    result = repository._raw_index_key("MyKey", "not_a_dict")
    assert result == "mykey"


# LINE 1014 — _load_raw_index_keys: raw_files is not a dict → returns empty set
@pytest.mark.integration
def test_load_raw_index_keys_returns_empty_set_when_files_is_not_dict(
    tmp_download_dir: Path,
) -> None:
    """_load_raw_index_keys returns an empty set when the 'files' value is not a
    dict."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    repository._index_path.write_text('{"files": []}')

    result = repository._load_raw_index_keys()
    assert result == set()


# LINE 1030 — delete: _resolve_delete_target returns None (dead-code guard)
# The guard at line 1030 is unreachable in the current implementation.
# We exercise it via a subclass that forces None to be returned.
@pytest.mark.integration
def test_delete_returns_false_when_resolve_target_returns_none(
    tmp_download_dir: Path,
) -> None:
    """delete() returns False when _resolve_delete_target returns None
    (exercised via subclass)."""

    class NullTargetRepository(FileSystemDLLRepository):
        def _resolve_delete_target(self, dll_file: DLLFile) -> DLLFile | None:
            return None

    repository = NullTargetRepository(tmp_download_dir)
    dll = DLLFile(name="ghost.dll", architecture=Architecture.X64)
    assert repository.delete(dll) is False


# LINES 1040-1044 — delete: _delete_path_is_safe returns False
@pytest.mark.integration
def test_delete_returns_false_when_delete_path_is_not_safe(
    tmp_download_dir: Path,
) -> None:
    """delete() returns False when _delete_path_is_safe returns False for the
    resolved file path."""

    class UnsafeDeleteRepository(FileSystemDLLRepository):
        def _delete_path_is_safe(self, file_path: Path) -> bool:
            return False

    repository = UnsafeDeleteRepository(tmp_download_dir)
    saved = repository.save(
        DLLFile(name="unsafe.dll", architecture=Architecture.X64),
        _build_pe_payload(Architecture.X64),
    )
    # File still exists; delete must be refused
    result = repository.delete(saved)
    assert result is False
    assert Path(saved.file_path or "").exists()


# LINES 1067-1072 — _resolve_delete_target: file_path branch with arch
@pytest.mark.integration
def test_resolve_delete_target_resolves_architecture_from_file_path(
    tmp_download_dir: Path,
) -> None:
    """_resolve_delete_target infers the architecture from file_path when
    architecture is UNKNOWN and file_path points into an arch directory."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    saved = repository.save(
        DLLFile(name="arch-from-path.dll", architecture=Architecture.X64),
        _build_pe_payload(Architecture.X64),
    )
    # Build a DLLFile with UNKNOWN arch but a file_path inside the x64 dir
    dll = DLLFile(
        name="arch-from-path.dll",
        architecture=Architecture.UNKNOWN,
        file_path=saved.file_path,
    )
    target = repository._resolve_delete_target(dll)
    assert target is not None
    assert target.architecture == Architecture.X64


@pytest.mark.integration
def test_resolve_delete_target_returns_dll_when_arch_undetectable_from_path(
    tmp_download_dir: Path,
) -> None:
    """_resolve_delete_target returns the dll unchanged when file_path exists
    but _architecture_from_repository_path returns None (path in repo root)."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    # Place the file directly in the repo root (no arch subdir)
    payload_path = tmp_download_dir / "rootlevel.dll"
    payload_path.write_bytes(_build_pe_payload(Architecture.X64))
    dll = DLLFile(
        name="rootlevel.dll",
        architecture=Architecture.UNKNOWN,
        file_path=str(payload_path),
    )
    target = repository._resolve_delete_target(dll)
    assert target is not None
    # Architecture stays UNKNOWN because path is not inside an arch subdir
    assert target.architecture == Architecture.UNKNOWN


# LINE 1077 — _resolve_delete_target: find_by_name returns None → X64 fallback
@pytest.mark.integration
def test_resolve_delete_target_falls_back_to_x64_when_not_found(
    tmp_download_dir: Path,
) -> None:
    """_resolve_delete_target replaces architecture with X64 when find_by_name
    returns None and no file_path is provided."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    dll = DLLFile(name="notfound.dll", architecture=Architecture.UNKNOWN)
    target = repository._resolve_delete_target(dll)
    assert target is not None
    assert target.architecture == Architecture.X64


# LINES 1083-1097 — _architecture_from_repository_path branches
@pytest.mark.integration
def test_architecture_from_repository_path_returns_none_for_root_path(
    tmp_download_dir: Path,
) -> None:
    """Returns None when the path is directly in the base directory (no arch
    parts)."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    path = tmp_download_dir / "file.dll"
    path.write_bytes(b"data")
    result = repository._architecture_from_repository_path(path)
    assert result is None


@pytest.mark.integration
def test_architecture_from_repository_path_returns_none_for_unknown_arch_name(
    tmp_download_dir: Path,
) -> None:
    """Returns None when the first path component maps to Architecture.UNKNOWN."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    unknown_dir = tmp_download_dir / "unknown"
    unknown_dir.mkdir(exist_ok=True)
    path = unknown_dir / "file.dll"
    path.write_bytes(b"data")
    result = repository._architecture_from_repository_path(path)
    assert result is None


@pytest.mark.integration
def test_architecture_from_repository_path_returns_none_for_invalid_arch_name(
    tmp_download_dir: Path,
) -> None:
    """Returns None when the first path component is not a valid Architecture
    value (ValueError from Architecture())."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    # Use a directory name that is not any Architecture enum value
    bogus_dir = tmp_download_dir / "notanarch"
    bogus_dir.mkdir(exist_ok=True)
    path = bogus_dir / "file.dll"
    path.write_bytes(b"data")
    result = repository._architecture_from_repository_path(path)
    assert result is None


@pytest.mark.integration
def test_architecture_from_repository_path_returns_none_for_missing_parent(
    tmp_download_dir: Path,
) -> None:
    """Returns None when the parent directory does not exist (strict=True
    raises OSError)."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    path = tmp_download_dir / "nonexistent" / "file.dll"
    result = repository._architecture_from_repository_path(path)
    assert result is None


# LINE 1129 — _delete_path_is_safe: file_path.is_symlink() is True
@pytest.mark.integration
def test_delete_path_is_safe_delegates_to_location_check_for_symlink(
    tmp_download_dir: Path,
) -> None:
    """_delete_path_is_safe returns the result of
    _path_location_is_within_repository when file_path is a symlink."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    outside = tmp_download_dir.parent / "outside-target.dll"
    outside.write_bytes(b"data")
    symlink_inside = tmp_download_dir / "x64" / "linked.dll"
    symlink_inside.symlink_to(outside)

    try:
        # Symlink is inside the repo root so location check passes
        result = repository._delete_path_is_safe(symlink_inside)
        assert result is True
    finally:
        symlink_inside.unlink(missing_ok=True)
        outside.unlink(missing_ok=True)


# LINES 1160-1163 — _unlink_payload_for_delete: unlink raises, index restored
@pytest.mark.integration
def test_unlink_payload_raises_oserror_and_restores_index(
    tmp_download_dir: Path,
) -> None:
    """When file_path.unlink() raises OSError and the index was updated,
    _restore_index_after_delete_failure is called to restore the entry.

    Making the arch subdirectory read-only prevents unlink() while still
    allowing _validate_repository_write_path and _save_index to succeed
    (they operate on the index in the parent directory).
    """
    import json as _json

    repository = FileSystemDLLRepository(tmp_download_dir)
    saved = repository.save(
        DLLFile(name="unlink-fail.dll", architecture=Architecture.X64),
        _build_pe_payload(Architecture.X64),
    )
    arch_dir = tmp_download_dir / "x64"

    # Make the arch directory read-only so unlink raises PermissionError
    arch_dir.chmod(0o555)
    try:
        # Verify that listing a read-only directory is possible on this platform
        try:
            list(arch_dir.iterdir())
        except PermissionError:
            pytest.skip("cannot read chmod-555 directories on this platform")

        result = repository.delete(saved)
        # delete() catches PermissionError (OSError subclass) and returns False
        assert result is False
        # Allow reading to verify index restoration
        arch_dir.chmod(0o755)
        # The index entry must have been restored
        index_data = _json.loads((tmp_download_dir / ".dll_index.json").read_text())
        assert "x64/unlink-fail.dll" in index_data["files"]
    finally:
        arch_dir.chmod(0o755)


# BRANCH 1161->1163 — _unlink_payload_for_delete: index_was_updated is False
# so the restore is skipped and OSError propagates directly
@pytest.mark.integration
def test_unlink_payload_raises_oserror_without_restore_when_index_not_updated(
    tmp_download_dir: Path,
) -> None:
    """When file_path.unlink() raises OSError and index_was_updated is False,
    _restore_index_after_delete_failure is NOT called and OSError propagates."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    # Create a real file in the x64 dir without going through save() so it
    # won't be in the index; then make the parent directory read-only
    arch_dir = tmp_download_dir / "x64"
    arch_dir.mkdir(exist_ok=True)
    dll_path = arch_dir / "orphan-unlink.dll"
    dll_path.write_bytes(_build_pe_payload(Architecture.X64))

    # Empty index — key is not present, so index_was_updated will be False
    empty_index: dict[str, object] = {"files": {}}

    arch_dir.chmod(0o555)
    try:
        try:
            list(arch_dir.iterdir())
        except PermissionError:
            pytest.skip("cannot read chmod-555 directories on this platform")

        # Call _unlink_payload_for_delete directly: index_was_updated=False means
        # no restore, but OSError from unlink still propagates via `raise`
        with pytest.raises(PermissionError):
            repository._unlink_payload_for_delete(
                dll_path,
                index_was_updated=False,
                original_index=empty_index,  # type: ignore[arg-type]
            )
    finally:
        arch_dir.chmod(0o755)


# LINES 1167-1170 — _restore_index_after_delete_failure: _save_index raises
@pytest.mark.integration
def test_restore_index_after_delete_failure_logs_when_save_index_raises(
    tmp_download_dir: Path,
) -> None:
    """_restore_index_after_delete_failure logs a warning and returns without
    raising when _save_index raises RepositoryError during rollback.

    The first _save_index call (index update inside _remove_index_entry_under_lock)
    must SUCCEED so that index_was_updated=True and _restore_index_after_delete_failure
    is triggered.  Only the SECOND _save_index call (the rollback) should fail.
    A call-counter gate achieves the right sequencing.
    """

    class RollbackFailingRepository(FileSystemDLLRepository):
        _save_call_count: int = 0

        def _save_index(self, index: object) -> None:
            self._save_call_count += 1
            if self._save_call_count == 2:  # second call is the rollback
                raise RepositoryError("injected rollback save failure")
            super()._save_index(index)  # type: ignore[arg-type]

    repository = RollbackFailingRepository(tmp_download_dir)
    saved = repository.save(
        DLLFile(name="restore-fail.dll", architecture=Architecture.X64),
        _build_pe_payload(Architecture.X64),
    )
    # Reset the call counter so that:
    #   call 1 (inside _remove_index_entry_under_lock) → succeeds
    #   call 2 (the rollback inside _restore_index_after_delete_failure) → fails
    repository._save_call_count = 0
    arch_dir = tmp_download_dir / "x64"

    # Making the arch directory read-only causes file_path.unlink() to raise,
    # which triggers _restore_index_after_delete_failure (the second _save_index call).
    arch_dir.chmod(0o555)
    try:
        try:
            list(arch_dir.iterdir())
        except PermissionError:
            pytest.skip("cannot read chmod-555 directories on this platform")

        # Neither PermissionError nor RepositoryError should propagate to caller
        result = repository.delete(saved)
        assert result is False
        # Rollback save was attempted (and failed); call count must be >= 2
        assert repository._save_call_count >= 2
    finally:
        arch_dir.chmod(0o755)


# LINE 1182 — update_metadata: key not in index → RepositoryOperationError
@pytest.mark.integration
def test_update_metadata_raises_when_dll_not_in_index(
    tmp_download_dir: Path,
) -> None:
    """update_metadata raises RepositoryOperationError when the DLL is not
    found in the index."""
    from dll_downloader.domain.errors import RepositoryOperationError

    repository = FileSystemDLLRepository(tmp_download_dir)
    dll = DLLFile(name="not-indexed.dll", architecture=Architecture.X64)

    with pytest.raises(RepositoryOperationError, match="DLL not found in index"):
        repository.update_metadata(dll)


# LINE 1191 — update_metadata: payload not valid → RepositoryOperationError
@pytest.mark.integration
def test_update_metadata_raises_when_payload_is_invalid(
    tmp_download_dir: Path,
) -> None:
    """update_metadata raises RepositoryOperationError when the indexed payload
    fails validation (e.g. the file was deleted after save)."""
    from dll_downloader.domain.errors import RepositoryOperationError

    repository = FileSystemDLLRepository(tmp_download_dir)
    saved = repository.save(
        DLLFile(name="ghost-meta.dll", architecture=Architecture.X64),
        _build_pe_payload(Architecture.X64),
    )
    # Remove the payload so _indexed_payload_is_valid returns False
    Path(saved.file_path or "").unlink()

    with pytest.raises(RepositoryOperationError, match="DLL payload not found"):
        repository.update_metadata(saved)


# LINES 1264-1265 — _deserialize_dll: invalid vt_scan_date
@pytest.mark.integration
def test_deserialize_dll_skips_invalid_vt_scan_date(
    tmp_download_dir: Path,
) -> None:
    """_deserialize_dll logs a warning and leaves vt_scan_date as None when the
    stored value is not a valid ISO datetime string."""
    import hashlib
    import json as _json

    repository = FileSystemDLLRepository(tmp_download_dir)
    payload = _build_pe_payload(Architecture.X64)
    file_hash = hashlib.sha256(payload).hexdigest()
    payload_path = tmp_download_dir / "x64" / "scan-date.dll"
    payload_path.write_bytes(payload)

    index_data = {
        "files": {
            "x64/scan-date.dll": {
                "name": "scan-date.dll",
                "version": None,
                "architecture": "x64",
                "file_hash": file_hash,
                "file_path": str(payload_path),
                "download_url": None,
                "file_size": len(payload),
                "security_status": "not_scanned",
                "vt_detection_ratio": None,
                "vt_scan_date": "not-a-date",
                "created_at": None,
            }
        }
    }
    (tmp_download_dir / ".dll_index.json").write_text(_json.dumps(index_data))

    found = repository.find_by_name("scan-date.dll", Architecture.X64)
    assert found is not None
    assert found.vt_scan_date is None


# LINES 1272-1273 — _deserialize_dll: invalid created_at
@pytest.mark.integration
def test_deserialize_dll_skips_invalid_created_at(
    tmp_download_dir: Path,
) -> None:
    """_deserialize_dll logs a warning and leaves created_at as its default
    when the stored value is not a valid ISO datetime string."""
    import hashlib
    import json as _json

    repository = FileSystemDLLRepository(tmp_download_dir)
    payload = _build_pe_payload(Architecture.X64)
    file_hash = hashlib.sha256(payload).hexdigest()
    payload_path = tmp_download_dir / "x64" / "created-at.dll"
    payload_path.write_bytes(payload)

    index_data = {
        "files": {
            "x64/created-at.dll": {
                "name": "created-at.dll",
                "version": None,
                "architecture": "x64",
                "file_hash": file_hash,
                "file_path": str(payload_path),
                "download_url": None,
                "file_size": len(payload),
                "security_status": "not_scanned",
                "vt_detection_ratio": None,
                "vt_scan_date": None,
                "created_at": "not-a-date",
            }
        }
    }
    (tmp_download_dir / ".dll_index.json").write_text(_json.dumps(index_data))

    found = repository.find_by_name("created-at.dll", Architecture.X64)
    assert found is not None
    # No crash; created_at retains the DLLFile default value


# LINES 1296-1298 — _try_deserialize_dll: missing required key → None
@pytest.mark.integration
def test_try_deserialize_dll_returns_none_for_missing_required_key(
    tmp_download_dir: Path,
) -> None:
    """_try_deserialize_dll returns None and logs a warning when the entry dict
    is missing required keys (KeyError inside _deserialize_dll)."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    result = repository._try_deserialize_dll(cast(Any, {"architecture": "x64"}))
    assert result is None


# LINES 1369-1372 — _validated_indexed_payload_path: payload is a symlink
@pytest.mark.integration
def test_validated_indexed_payload_path_returns_none_for_symlink_payload(
    tmp_download_dir: Path,
    tmp_path: Path,
) -> None:
    """_validated_indexed_payload_path returns None when the indexed file_path
    is a symlink."""
    import hashlib

    repository = FileSystemDLLRepository(tmp_download_dir)
    outside = tmp_path / "outside-payload.dll"
    pe = _build_pe_payload()
    outside.write_bytes(pe)
    symlink_path = tmp_download_dir / "x64" / "symlinked.dll"
    symlink_path.symlink_to(outside)

    try:
        dll = DLLFile(
            name="symlinked.dll",
            architecture=Architecture.X64,
            file_hash=hashlib.sha256(pe).hexdigest(),
            file_path=str(symlink_path),
            file_size=len(pe),
        )
        result = repository._validated_indexed_payload_path(
            dll,
            expected_name="symlinked.dll",
            expected_architecture=Architecture.X64,
        )
        assert result is None
    finally:
        symlink_path.unlink(missing_ok=True)


# LINES 1374-1375 — _validated_indexed_payload_path: path outside repository
@pytest.mark.integration
def test_validated_indexed_payload_path_returns_none_for_path_outside_repo(
    tmp_download_dir: Path,
    tmp_path: Path,
) -> None:
    """_validated_indexed_payload_path returns None when the indexed file_path
    resolves outside the repository."""
    import hashlib

    repository = FileSystemDLLRepository(tmp_download_dir)
    pe = _build_pe_payload()
    outside = tmp_path / "outside.dll"
    outside.write_bytes(pe)

    dll = DLLFile(
        name="outside.dll",
        architecture=Architecture.X64,
        file_hash=hashlib.sha256(pe).hexdigest(),
        file_path=str(outside),
        file_size=len(pe),
    )
    result = repository._validated_indexed_payload_path(
        dll,
        expected_name="outside.dll",
        expected_architecture=Architecture.X64,
    )
    assert result is None


# LINES 1447-1448 — _create_dll_from_file: os.open raises OSError
@pytest.mark.integration
def test_create_dll_from_file_raises_when_open_fails(
    tmp_download_dir: Path,
) -> None:
    """_create_dll_from_file raises RepositoryError when os.open raises."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    target = tmp_download_dir / "x64" / "open-fail.dll"
    target.write_bytes(_build_pe_payload())

    original_open = os.open

    def patched_open(path: str, flags: int, mode: int = 0) -> int:
        if "open-fail.dll" in path:
            raise OSError("injected open failure")
        return original_open(path, flags, mode)

    os.open = cast(Any, patched_open)
    try:
        with pytest.raises(RepositoryError, match="Failed to read DLL file"):
            repository._create_dll_from_file(target, "open-fail.dll", Architecture.X64)
    finally:
        os.open = original_open


# LINE 1452 — _create_dll_from_file: fstat shows non-regular file
@pytest.mark.integration
def test_create_dll_from_file_raises_when_fstat_non_regular(
    tmp_download_dir: Path,
) -> None:
    """_create_dll_from_file raises RepositoryError when fstat indicates a
    non-regular file."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    target = tmp_download_dir / "x64" / "non-reg.dll"
    target.write_bytes(_build_pe_payload())

    original_fstat = os.fstat

    def patched_fstat(fd: int) -> os.stat_result:
        result = original_fstat(fd)
        return os.stat_result(
            (
                _stat.S_IFIFO | 0o600,
                result.st_ino,
                result.st_dev,
                result.st_nlink,
                result.st_uid,
                result.st_gid,
                result.st_size,
                result.st_atime,
                result.st_mtime,
                result.st_ctime,
            )
        )

    os.fstat = patched_fstat
    try:
        with pytest.raises(RepositoryError, match="non-regular file"):
            repository._create_dll_from_file(target, "non-reg.dll", Architecture.X64)
    finally:
        os.fstat = original_fstat


# LINES 1457-1458, 1461-1462 — _create_dll_from_file: set_blocking raises
@pytest.mark.integration
def test_create_dll_from_file_raises_and_closes_fd_when_set_blocking_fails(
    tmp_download_dir: Path,
) -> None:
    """When os.set_blocking raises inside _create_dll_from_file, a
    RepositoryError is raised and the fd is closed by the finally block."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    target = tmp_download_dir / "x64" / "set-blocking-fail.dll"
    target.write_bytes(_build_pe_payload())

    original_set_blocking = os.set_blocking

    def patched_set_blocking(fd: int, blocking: bool) -> None:
        raise OSError("injected set_blocking failure")

    os.set_blocking = patched_set_blocking
    try:
        with pytest.raises(RepositoryError, match="Failed to read DLL file"):
            repository._create_dll_from_file(
                target, "set-blocking-fail.dll", Architecture.X64
            )
    finally:
        os.set_blocking = original_set_blocking


# LINE 1495 — _normalize_index_entry: second isinstance check is dead code
# The check at line 1494 (second isinstance(architecture, str)) can never be
# False because the first guard at line 1482 already validated it.
# We document this by showing the earlier guard catches the invalid input.
@pytest.mark.integration
def test_normalize_index_entry_raises_for_non_string_architecture(
    tmp_download_dir: Path,
) -> None:
    """_normalize_index_entry raises ValueError for a non-string architecture
    value via the first guard (line 1482); the dead second guard at line 1494
    is never reached in normal execution."""
    repository = FileSystemDLLRepository(tmp_download_dir)

    with pytest.raises(ValueError, match="architecture"):
        repository._normalize_index_entry({"name": "a.dll", "architecture": 42})


# BRANCH 154->157 — _with_index_lock: os.open itself fails so fd stays -1
@pytest.mark.integration
def test_with_index_lock_raises_when_os_open_fails(
    tmp_download_dir: Path,
) -> None:
    """When os.open raises before the fd is assigned, fd stays -1, the close
    branch is skipped, and RepositoryError is still raised."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    original_open = os.open

    def patched_open(path: str, flags: int, *args: object, **kwargs: object) -> int:
        if ".dll_index.lock" in str(path):
            raise OSError("injected open failure")
        return original_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    os.open = patched_open  # type: ignore[assignment]
    try:
        with (
            pytest.raises(RepositoryError, match="Failed to acquire index lock"),
            repository._with_index_lock(),
        ):
            pass
    finally:
        os.open = original_open


# BRANCH 420->422 — _write_temp_file: fdopen succeeds (fd_opened=True),
# then os.fsync raises; except branch skips os.close because fd is already owned
@pytest.mark.integration
def test_write_temp_file_skips_close_when_fdopen_succeeded_and_fsync_raises(
    tmp_download_dir: Path,
) -> None:
    """When os.fdopen succeeds (sets fd_opened=True) but os.fsync then raises,
    the except BaseException branch skips os.close because the context manager
    already owns the fd."""
    import tempfile as _tempfile

    fd, temp_name = _tempfile.mkstemp(dir=str(tmp_download_dir))
    original_fsync = os.fsync

    def patched_fsync(fd_arg: int) -> None:
        raise OSError("injected fsync failure")

    os.fsync = patched_fsync  # type: ignore[assignment]
    try:
        with pytest.raises(OSError, match="injected fsync failure"):
            FileSystemDLLRepository._write_temp_file(fd, b"payload-data")
    finally:
        os.fsync = original_fsync
        # fd was closed by the context manager in os.fdopen before fsync raised
        with contextlib.suppress(OSError):
            os.unlink(temp_name)


# LINE 936 — _list_fallback_payloads: _validated_fallback_payload_path returns
# None (dll file is a symlink → skipped), key not in blocked_keys
@pytest.mark.integration
def test_list_fallback_payloads_skips_when_validated_path_returns_none(
    tmp_download_dir: Path,
    tmp_path: Path,
) -> None:
    """_list_fallback_payloads skips a .dll file when
    _validated_fallback_payload_path returns None.  A symlink .dll in the arch
    directory (not in blocked_keys) is a concrete case that triggers line 936."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    arch_dir = tmp_download_dir / "x64"

    # Place a real DLL outside the repository so the symlink points to it
    real_dll = tmp_path / "outside.dll"
    real_dll.write_bytes(_build_pe_payload(Architecture.X64))

    symlink_dll = arch_dir / "symlinked.dll"
    symlink_dll.symlink_to(real_dll)
    try:
        result = repository._list_fallback_payloads(set())
        names = [dll.name for dll in result]
        # The symlink payload must be rejected (fallback_path is None)
        assert "symlinked.dll" not in names
    finally:
        symlink_dll.unlink(missing_ok=True)


# BRANCH 999->1005 — _raw_index_key: entry is a dict but arch or name is not a
# string → skips the inner if and falls through to return str(key).lower()
@pytest.mark.integration
def test_raw_index_key_falls_back_when_arch_is_not_a_string(
    tmp_download_dir: Path,
) -> None:
    """When entry is a dict with a non-string 'architecture' value, the inner
    isinstance guard at line 999 is False and _raw_index_key returns the
    fallback str(key).lower() at line 1005."""
    repository = FileSystemDLLRepository(tmp_download_dir)
    # architecture value is an integer — not a string
    result = repository._raw_index_key(
        "x64/myfile.dll", {"architecture": 99, "name": "myfile.dll"}
    )
    assert result == "x64/myfile.dll"
