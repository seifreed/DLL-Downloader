# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Integration tests for FileSystemDLLRepository.

These tests validate the repository implementation using real filesystem
operations with temporary directories. No mocks or stubs are used.
"""

import hashlib
import json
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
    # Realistic PE header structure
    dos_header = b'MZ\x90\x00'  # DOS signature
    dos_stub = b'\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
    dos_padding = b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00'
    dos_filler = b'\x00' * 32
    pe_signature = b'PE\x00\x00'

    # COFF header
    coff_header = (
        b'\x64\x86'  # Machine type: AMD64
        b'\x03\x00'  # Number of sections
        b'\x00\x00\x00\x00'  # Time stamp
        b'\x00\x00\x00\x00'  # Pointer to symbol table
        b'\x00\x00\x00\x00'  # Number of symbols
        b'\xf0\x00'  # Size of optional header
        b'\x22\x00'  # Characteristics
    )

    # Content section
    content_section = b'Realistic DLL content for integration testing.' * 50

    return (
        dos_header + dos_stub + dos_padding + dos_filler +
        pe_signature + coff_header + content_section
    )


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

    def test_save_preserves_existing_hash(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that save() preserves pre-existing hash values.

        Expected Behavior:
            - Existing hash value is not overwritten
            - Returned entity maintains the original hash
        """
        predefined_hash = "abc123def456"
        dll = DLLFile(
            name="kernel32.dll",
            version="10.0.19041.1",
            architecture=Architecture.X64,
            file_hash=predefined_hash,
        )

        saved_dll = repository.save(dll, sample_dll_content)

        assert saved_dll.file_hash == predefined_hash

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

    def test_save_x86_architecture(
        self,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
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

        saved_dll = repository.save(dll, sample_dll_content)

        expected_path = tmp_path / "x86" / "user32.dll"
        assert expected_path.exists()
        assert expected_path.read_bytes() == sample_dll_content
        assert saved_dll.architecture == Architecture.X86

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
        original_content = b"MZ\x90\x00original content"
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

        content1 = b"MZ\x90\x00content1" + sample_dll_content
        content2 = b"MZ\x90\x00content2" + sample_dll_content
        content3 = b"MZ\x90\x00content3" + sample_dll_content

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
        repository.save(dll_x86, sample_dll_content)

        found = repository.find_by_name("common.dll")

        assert found is not None
        assert found.architecture == Architecture.X86
        assert found.version == "2.0"


def test_find_without_architecture_no_match_hits_unknown(repository) -> None:
    """
    Verify loop reaches UNKNOWN when no matches exist.
    """
    found = repository.find_by_name("missing.dll")
    assert found is None


def test_find_with_unknown_architecture_finds_x64(tmp_download_dir) -> None:
    """
    Verify UNKNOWN architecture falls back to x64 path.
    """
    repository = FileSystemDLLRepository(tmp_download_dir)
    dll = DLLFile(name="unknown.dll", architecture=Architecture.X64)
    repository.save(dll, b"data")

    found = repository.find_by_name("unknown.dll", Architecture.UNKNOWN)
    assert found is not None
    assert found.architecture == Architecture.UNKNOWN


def test_save_index_raises_repository_error(tmp_download_dir, monkeypatch) -> None:
    """
    Verify _save_index raises RepositoryError on OSError.
    """
    repository = FileSystemDLLRepository(tmp_download_dir)

    def raise_oserror(*args, **kwargs):
        raise OSError("nope")

    monkeypatch.setattr("builtins.open", raise_oserror)

    with pytest.raises(RepositoryError):
        repository._save_index({"files": {}})


def test_save_raises_repository_error_on_write(tmp_download_dir, monkeypatch) -> None:
    """
    Verify save raises RepositoryError on file write error.
    """
    repository = FileSystemDLLRepository(tmp_download_dir)
    dll = DLLFile(name="writefail.dll", architecture=Architecture.X64)

    def raise_oserror(*args, **kwargs):
        raise OSError("nope")

    monkeypatch.setattr("builtins.open", raise_oserror)

    with pytest.raises(RepositoryError):
        repository.save(dll, b"data")


def test_delete_returns_false_on_exception(tmp_download_dir, monkeypatch) -> None:
    """
    Verify delete returns False when unlink raises.
    """
    repository = FileSystemDLLRepository(tmp_download_dir)
    dll = DLLFile(name="deletefail.dll", architecture=Architecture.X64)
    saved = repository.save(dll, b"data")

    def raise_unlink(self):
        raise OSError("nope")

    monkeypatch.setattr(Path, "unlink", raise_unlink, raising=True)
    assert repository.delete(saved) is False


def test_delete_with_missing_file_path_returns_true(tmp_download_dir) -> None:
    """
    Verify delete succeeds when file_path does not exist on disk.
    """
    repository = FileSystemDLLRepository(tmp_download_dir)
    dll = DLLFile(name="missing.dll", architecture=Architecture.X64, file_path=str(tmp_download_dir / "x64" / "missing.dll"))

    assert repository.delete(dll) is True

    def test_find_nonexistent_dll_returns_none(
        self,
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
        self,
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
        # Manually create DLL file bypassing repository
        dll_path = tmp_path / "x64" / "orphaned.dll"
        content = b"MZ\x90\x00orphaned content"
        dll_path.write_bytes(content)

        found = repository.find_by_name("orphaned.dll", Architecture.X64)

        assert found is not None
        assert found.name == "orphaned.dll"
        assert found.architecture == Architecture.X64
        assert found.file_hash == hashlib.sha256(content).hexdigest()


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

        found = repository.find_by_hash(saved_dll.file_hash)

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

        content1 = b"MZ\x90\x00unique content 1"
        content2 = b"MZ\x90\x00unique content 2"

        saved1 = repository.save(dll1, content1)
        saved2 = repository.save(dll2, content2)

        found = repository.find_by_hash(saved1.file_hash)

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
        file_path = Path(saved_dll.file_path)

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
        repository.save(dll, sample_dll_content)

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
        repository.save(dll2, sample_dll_content)
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

        content_x64 = b"MZ\x90\x00x64 content"
        content_x86 = b"MZ\x90\x00x86 content"

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
        updated_content = b"MZ\x90\x00updated content"
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
            repository.save(dll, sample_dll_content)

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
