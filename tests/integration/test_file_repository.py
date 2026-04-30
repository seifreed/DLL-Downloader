# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Integration tests for FileSystemDLLRepository.

These tests validate the repository implementation using real filesystem
operations with temporary directories. No mocks or stubs are used.
"""

import hashlib
import io
import json
import os
import zipfile
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
)
from dll_downloader.infrastructure.persistence.file_repository import (
    FileSystemDLLRepository,
    RepositoryError,
)


def _require_str(value: str | None) -> str:
    assert value is not None
    return value


def _build_pe_payload(architecture: Architecture = Architecture.X64) -> bytes:
    machine = 0x014C if architecture == Architecture.X86 else 0x8664
    pe_offset = 0x80
    optional_header_size = 0xF0 if architecture == Architecture.X64 else 0xE0
    optional_header_offset = pe_offset + 24
    section_table_offset = optional_header_offset + optional_header_size
    payload = bytearray(section_table_offset + 40)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    payload[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    payload[pe_offset + 4:pe_offset + 6] = machine.to_bytes(2, "little")
    payload[pe_offset + 6:pe_offset + 8] = (1).to_bytes(2, "little")
    payload[pe_offset + 20:pe_offset + 22] = optional_header_size.to_bytes(2, "little")
    payload[pe_offset + 22:pe_offset + 24] = (0x2000).to_bytes(2, "little")
    optional_magic = 0x20B if architecture == Architecture.X64 else 0x10B
    payload[optional_header_offset:optional_header_offset + 2] = optional_magic.to_bytes(
        2,
        "little",
    )
    payload[section_table_offset:section_table_offset + 5] = b".text"
    return bytes(payload)


def _build_pe_header_stub(architecture: Architecture = Architecture.X64) -> bytes:
    machine = 0x014C if architecture == Architecture.X86 else 0x8664
    pe_offset = 0x80
    payload = bytearray(pe_offset + 24)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    payload[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    payload[pe_offset + 4:pe_offset + 6] = machine.to_bytes(2, "little")
    payload[pe_offset + 6:pe_offset + 8] = (0).to_bytes(2, "little")
    payload[pe_offset + 20:pe_offset + 22] = (0).to_bytes(2, "little")
    payload[pe_offset + 22:pe_offset + 24] = (0x2000).to_bytes(2, "little")
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
    content_section = b'Realistic DLL content for integration testing.' * 50
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

    def _validate_repository_write_path(self, file_path: Path) -> None:
        super()._validate_repository_write_path(file_path)
        if file_path.name == "race.dll" and not file_path.exists():
            file_path.mkdir()


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

    def test_load_index_returns_empty_for_invalid_top_level_json(
        self,
        tmp_path: Path,
    ) -> None:
        repo_path = tmp_path / "dll_repo"
        repo_path.mkdir()
        (repo_path / ".dll_index.json").write_text('["bad"]')

        repository = FileSystemDLLRepository(repo_path)

        assert repository._load_index() == {"files": {}}

    def test_load_index_returns_empty_for_invalid_files_shape(
        self,
        tmp_path: Path,
    ) -> None:
        repo_path = tmp_path / "dll_repo"
        repo_path.mkdir()
        (repo_path / ".dll_index.json").write_text('{"files": []}')

        repository = FileSystemDLLRepository(repo_path)

        assert repository._load_index() == {"files": {}}


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
            repository._normalize_index_entry({"name": "a.dll", "architecture": "x64", "security_status": 1})
        with pytest.raises(ValueError):
            repository._normalize_index_entry({"name": "a.dll", "architecture": "x64", "file_size": "1"})

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
            flags = int.from_bytes(payload[flag_offset:flag_offset + 2], "little")
            payload[flag_offset:flag_offset + 2] = (flags | 0x01).to_bytes(
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

    def test_save_rejects_index_directory_without_leaving_payload(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        index_path = tmp_path / ".dll_index.json"
        index_path.mkdir()

        with pytest.raises(RepositoryError, match="directory"):
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
        assert saved_path == tmp_path / "x64" / "zipped.dll"
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
        assert saved_path == tmp_path / "x64" / "zipped.dll"
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
        dll_x64 = DLLFile(name="common.dll", architecture=Architecture.X64, version="1.0")
        dll_x86 = DLLFile(name="common.dll", architecture=Architecture.X86, version="2.0")

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


def test_atomic_write_cleans_temp_file_when_replace_fails(tmp_download_dir: Path) -> None:
    repository = DirectoryRaceRepository(tmp_download_dir)
    target_path = tmp_download_dir / "x64" / "race.dll"

    with pytest.raises(OSError):
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
    dll = DLLFile(name="missing.dll", architecture=Architecture.X64, file_path=str(tmp_download_dir / "x64" / "missing.dll"))

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

    assert not repository._path_locations_match(
        tmp_download_dir / "missing-parent" / "missing.dll",
        tmp_download_dir / "x64" / "missing.dll",
    )


def test_delete_rejects_file_path_outside_repository(tmp_download_dir: Path, tmp_path: Path) -> None:
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


def test_delete_removes_internal_symlink_pointing_outside_repository(
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

    assert repository.delete(dll) is True
    assert not symlink_path.is_symlink()
    assert outside_file.read_bytes() == b"external content"


def test_delete_removes_broken_symlink_inside_repository(tmp_download_dir: Path) -> None:
    repository = FileSystemDLLRepository(tmp_download_dir)
    symlink_path = tmp_download_dir / "x64" / "broken.dll"
    symlink_path.symlink_to(tmp_download_dir / "missing-target.dll")
    dll = DLLFile(
        name="broken.dll",
        architecture=Architecture.X64,
        file_path=str(symlink_path),
    )

    assert repository.delete(dll) is True
    assert not symlink_path.is_symlink()


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

    assert repository.find_by_name("valid.dll", Architecture.X64) is None


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

    assert repository.find_by_name("valid.dll", Architecture.X64) is None


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

    assert repository.list_all() == []


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
        found = repository.find_by_name("external-index.dll", Architecture.X64)

        assert found is not None
        assert found.download_url is None
        assert repository.find_by_hash(file_hash) is None
        assert repository.list_all() == []
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
        dll = DLLFile(name="persistent.dll", architecture=Architecture.X64, version="1.0")
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
        Verify that corrupted index files are handled without crashing.

        Expected Behavior:
            - Repository initializes successfully
            - Corrupted index is treated as empty
            - New index is created on save
        """
        # Create repository with corrupted index
        index_path = tmp_path / ".dll_index.json"
        index_path.write_text("{corrupted json content")

        # Should not raise exception
        repo = FileSystemDLLRepository(tmp_path)

        # Should return empty list
        all_dlls = repo.list_all()
        assert all_dlls == []

    def test_invalid_index_entries_are_skipped_when_listing(
        self,
        tmp_path: Path,
        sample_dll_content: bytes,
    ) -> None:
        repo = FileSystemDLLRepository(tmp_path)
        repo.save(DLLFile(name="valid.dll", architecture=Architecture.X64), sample_dll_content)

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
        saved = repo.save(DLLFile(name="valid.dll", architecture=Architecture.X64), sample_dll_content)
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
        saved = repo.save(DLLFile(name="bad.dll", architecture=Architecture.X64), sample_dll_content)
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
        dll_x64 = DLLFile(name="multiarch.dll", architecture=Architecture.X64, version="1.0")
        dll_x86 = DLLFile(name="multiarch.dll", architecture=Architecture.X86, version="2.0")

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
        dll = DLLFile(name="lifecycle.dll", architecture=Architecture.X64, version="1.0")
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
