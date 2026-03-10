"""
File System DLL Repository Implementation

Implements the IDLLRepository interface using the local filesystem for storage.
"""

import json
import logging
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import TypedDict

from ...domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
    normalize_dll_name,
)
from ...domain.errors import RepositoryOperationError
from ...domain.repositories.dll_repository import IDLLRepository
from ...domain.services import calculate_sha256

logger = logging.getLogger(__name__)


class IndexEntry(TypedDict):
    name: str
    version: str | None
    architecture: str
    file_hash: str | None
    file_path: str | None
    download_url: str | None
    file_size: int | None
    security_status: str
    vt_detection_ratio: str | None
    vt_scan_date: str | None
    created_at: str | None


class IndexData(TypedDict):
    files: dict[str, IndexEntry]


class RepositoryError(RepositoryOperationError):
    """Exception raised for repository operation errors."""
    pass


class FileSystemDLLRepository(IDLLRepository):
    """
    File system implementation of the DLL repository.

    Stores DLL files in a directory structure organized by architecture,
    with metadata stored in a JSON index file.

    Directory structure:
        downloads/
            x86/
                kernel32.dll
            x64/
                kernel32.dll
            .dll_index.json

    Example:
        >>> repo = FileSystemDLLRepository(Path("./downloads"))
        >>> dll = DLLFile(name="kernel32.dll", architecture=Architecture.X64)
        >>> repo.save(dll, content)
    """

    INDEX_FILENAME = ".dll_index.json"

    def __init__(self, base_path: Path) -> None:
        """
        Initialize the file system repository.

        Args:
            base_path: Base directory for storing DLL files
        """
        self._base_path = Path(base_path)
        self._index_path = self._base_path / self.INDEX_FILENAME
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Create base directory and architecture subdirectories if needed."""
        self._base_path.mkdir(parents=True, exist_ok=True)
        for arch in Architecture:
            if arch != Architecture.UNKNOWN:
                (self._base_path / arch.value).mkdir(exist_ok=True)

    def _load_index(self) -> IndexData:
        """Load the DLL index from disk."""
        if not self._index_path.exists():
            return {"files": {}}

        try:
            with open(self._index_path) as f:
                raw_data = json.load(f)
                if not isinstance(raw_data, dict):
                    raise ValueError("Index file must contain a JSON object")
                raw_files = raw_data.get("files", {})
                if not isinstance(raw_files, dict):
                    raise ValueError("Index 'files' entry must be an object")
                return {
                    "files": {
                        str(key): self._normalize_index_entry(value)
                        for key, value in raw_files.items()
                    }
                }
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to load index: {e}")
            return {"files": {}}
        except ValueError as e:
            logger.warning(f"Invalid index structure: {e}")
            return {"files": {}}

    def _save_index(self, index: IndexData) -> None:
        """Save the DLL index to disk."""
        try:
            with open(self._index_path, "w") as f:
                json.dump(index, f, indent=2, default=str)
        except OSError as e:
            logger.error(f"Failed to save index: {e}")
            raise RepositoryError(f"Failed to save index: {e}") from e

    def _get_file_key(self, name: str, architecture: Architecture) -> str:
        """Generate a unique key for a DLL file."""
        return f"{architecture.value}/{name.lower()}"

    def _get_file_path(self, name: str, architecture: Architecture) -> Path:
        """Get the filesystem path for a DLL file."""
        arch_value = architecture.value if architecture != Architecture.UNKNOWN else "x64"
        return self._base_path / arch_value / name

    def save(self, dll_file: DLLFile, content: bytes) -> DLLFile:
        """
        Save a DLL file to the filesystem.

        Args:
            dll_file: The DLL entity with metadata
            content: Raw binary content of the DLL file

        Returns:
            Updated DLLFile entity with file_path set

        Raises:
            RepositoryError: If the save operation fails
        """
        try:
            # Determine file path
            file_path = self._get_file_path(dll_file.name, dll_file.architecture)

            # Write content to disk
            with open(file_path, "wb") as f:
                f.write(content)

            # Update entity with file path (use replace since DLLFile is frozen)
            dll_file = replace(dll_file, file_path=str(file_path))

            # Calculate hash if not present
            if not dll_file.file_hash:
                dll_file = replace(dll_file, file_hash=calculate_sha256(content))

            # Update index
            index = self._load_index()
            key = self._get_file_key(dll_file.name, dll_file.architecture)
            index["files"][key] = self._serialize_dll(dll_file)
            self._save_index(index)

            logger.info(f"Saved DLL: {dll_file.name} to {file_path}")
            return dll_file

        except OSError as e:
            logger.error(f"Failed to save DLL {dll_file.name}: {e}")
            raise RepositoryError(f"Failed to save DLL: {e}") from e

    def find_by_name(
        self,
        name: str,
        architecture: Architecture | None = None
    ) -> DLLFile | None:
        """
        Find a DLL by its name and optionally architecture.

        Args:
            name: The DLL filename to search for
            architecture: Optional architecture filter

        Returns:
            DLLFile if found, None otherwise
        """
        name = normalize_dll_name(name)

        index = self._load_index()

        for arch in self._iter_architectures(architecture):
            key = self._get_file_key(name, arch)
            if key in index["files"]:
                return self._deserialize_dll(index["files"][key])

        # Check if file exists on disk without index entry
        for arch in self._iter_architectures(architecture):
            file_path = self._get_file_path(name, arch)
            if file_path.exists():
                return self._create_dll_from_file(file_path, name, arch)

        return None

    @staticmethod
    def _iter_architectures(
        architecture: Architecture | None
    ) -> list[Architecture]:
        if architecture:
            return [architecture]
        return [arch for arch in Architecture if arch != Architecture.UNKNOWN]

    def find_by_hash(self, file_hash: str) -> DLLFile | None:
        """
        Find a DLL by its SHA256 hash.

        Args:
            file_hash: SHA256 hash of the DLL file

        Returns:
            DLLFile if found, None otherwise
        """
        index = self._load_index()
        return next(
            (
                self._deserialize_dll(data)
                for data in index["files"].values()
                if data.get("file_hash") == file_hash
            ),
            None
        )

    def list_all(self) -> list[DLLFile]:
        """
        List all DLL files in the repository.

        Returns:
            List of all DLLFile entities in the repository
        """
        index = self._load_index()
        return [
            self._deserialize_dll(data)
            for data in index["files"].values()
        ]

    def delete(self, dll_file: DLLFile) -> bool:
        """
        Delete a DLL file from the repository.

        Args:
            dll_file: The DLL entity to delete

        Returns:
            True if deletion was successful, False otherwise
        """
        try:
            # Remove from filesystem
            if dll_file.file_path:
                file_path = Path(dll_file.file_path)
                if file_path.exists():
                    file_path.unlink()

            # Remove from index
            index = self._load_index()
            key = self._get_file_key(dll_file.name, dll_file.architecture)
            if key in index["files"]:
                del index["files"][key]
                self._save_index(index)

            logger.info(f"Deleted DLL: {dll_file.name}")
            return True

        except (OSError, RepositoryError) as e:
            logger.error(f"Failed to delete DLL {dll_file.name}: {e}")
            return False

    def exists(self, name: str, architecture: Architecture | None = None) -> bool:
        """
        Check if a DLL exists in the repository.

        Args:
            name: The DLL filename to check
            architecture: Optional architecture filter

        Returns:
            True if the DLL exists, False otherwise
        """
        return self.find_by_name(name, architecture) is not None

    def _serialize_dll(self, dll_file: DLLFile) -> IndexEntry:
        """Convert a DLLFile entity to a dictionary for JSON storage."""
        return {
            "name": dll_file.name,
            "version": dll_file.version,
            "architecture": dll_file.architecture.value,
            "file_hash": dll_file.file_hash,
            "file_path": dll_file.file_path,
            "download_url": dll_file.download_url,
            "file_size": dll_file.file_size,
            "security_status": dll_file.security_status.value,
            "vt_detection_ratio": dll_file.vt_detection_ratio,
            "vt_scan_date": dll_file.vt_scan_date.isoformat() if dll_file.vt_scan_date else None,
            "created_at": dll_file.created_at.isoformat() if dll_file.created_at else None,
        }

    def _deserialize_dll(self, data: IndexEntry) -> DLLFile:
        """Convert a dictionary to a DLLFile entity."""
        name = data["name"]
        version = data["version"]
        architecture = Architecture(data["architecture"])
        file_hash = data["file_hash"]
        file_path = data["file_path"]
        download_url = data["download_url"]
        file_size = data["file_size"]
        security_status = SecurityStatus(data["security_status"])
        vt_detection_ratio = data["vt_detection_ratio"]

        vt_scan_date_raw = data["vt_scan_date"]
        vt_scan_date = (
            datetime.fromisoformat(vt_scan_date_raw)
            if isinstance(vt_scan_date_raw, str)
            else None
        )
        created_at_raw = data["created_at"]
        created_at = (
            datetime.fromisoformat(created_at_raw)
            if isinstance(created_at_raw, str)
            else datetime.now()
        )

        return DLLFile(
            name=name,
            version=version,
            architecture=architecture,
            file_hash=file_hash,
            file_path=file_path,
            download_url=download_url,
            file_size=file_size,
            security_status=security_status,
            vt_detection_ratio=vt_detection_ratio,
            vt_scan_date=vt_scan_date,
            created_at=created_at,
        )

    def _create_dll_from_file(
        self,
        file_path: Path,
        name: str,
        architecture: Architecture
    ) -> DLLFile:
        """Create a DLLFile entity from an existing file on disk."""
        # Calculate hash
        with open(file_path, "rb") as f:
            content = f.read()
            file_hash = calculate_sha256(content)

        return DLLFile(
            name=name,
            architecture=architecture,
            file_hash=file_hash,
            file_path=str(file_path),
            file_size=len(content),
        )

    @staticmethod
    def _normalize_index_entry(raw_entry: object) -> IndexEntry:
        """Normalize loosely typed JSON metadata into a typed index entry."""
        if not isinstance(raw_entry, dict):
            raise ValueError("Index entry must be an object")

        name = raw_entry.get("name")
        architecture = raw_entry.get("architecture", "unknown")
        security_status = raw_entry.get("security_status", "not_scanned")
        file_size = raw_entry.get("file_size")

        if not isinstance(name, str):
            raise ValueError("Index entry 'name' must be a string")
        if not isinstance(architecture, str):
            raise ValueError("Index entry 'architecture' must be a string")
        if not isinstance(security_status, str):
            raise ValueError("Index entry 'security_status' must be a string")
        if file_size is not None and not isinstance(file_size, int):
            raise ValueError("Index entry 'file_size' must be an integer or null")

        return {
            "name": name,
            "version": raw_entry.get("version")
            if isinstance(raw_entry.get("version"), str)
            else None,
            "architecture": architecture,
            "file_hash": raw_entry.get("file_hash")
            if isinstance(raw_entry.get("file_hash"), str)
            else None,
            "file_path": raw_entry.get("file_path")
            if isinstance(raw_entry.get("file_path"), str)
            else None,
            "download_url": raw_entry.get("download_url")
            if isinstance(raw_entry.get("download_url"), str)
            else None,
            "file_size": file_size,
            "security_status": security_status,
            "vt_detection_ratio": raw_entry.get("vt_detection_ratio")
            if isinstance(raw_entry.get("vt_detection_ratio"), str)
            else None,
            "vt_scan_date": raw_entry.get("vt_scan_date")
            if isinstance(raw_entry.get("vt_scan_date"), str)
            else None,
            "created_at": raw_entry.get("created_at")
            if isinstance(raw_entry.get("created_at"), str)
            else None,
        }
