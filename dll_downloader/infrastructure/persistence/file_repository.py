"""
File System DLL Repository Implementation

Implements the IDLLRepository interface using the local filesystem for storage.
"""

import json
import logging
import os
import tempfile
import zipfile
from dataclasses import replace
from datetime import datetime
from io import BytesIO
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
_PE_POINTER_OFFSET = 0x3C
_PE_SIGNATURE = b"PE\x00\x00"
_PE_CHARACTERISTICS_OFFSET_FROM_MACHINE = 18
_PE_DLL_CHARACTERISTIC = 0x2000
_PE_MACHINE_ARCHITECTURES = {
    0x014C: Architecture.X86,
    0x8664: Architecture.X64,
}


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
        if self._index_path.is_symlink():
            logger.warning("Refusing to load DLL index through symlink: %s", self._index_path)
            return {"files": {}}
        if not self._index_path.exists():
            return {"files": {}}
        if not self._index_path.is_file():
            logger.warning("Refusing to load non-regular DLL index: %s", self._index_path)
            return {"files": {}}

        try:
            with open(self._index_path) as f:
                raw_data = json.load(f)
                if not isinstance(raw_data, dict):
                    raise ValueError("Index file must contain a JSON object")
                raw_files = raw_data.get("files", {})
                if not isinstance(raw_files, dict):
                    raise ValueError("Index 'files' entry must be an object")
                normalized_files: dict[str, IndexEntry] = {}
                for key, value in raw_files.items():
                    try:
                        normalized_files[str(key)] = self._normalize_index_entry(value)
                    except ValueError as entry_error:
                        logger.warning(
                            "Skipping invalid DLL index entry: %s",
                            entry_error,
                        )
                return {"files": normalized_files}
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to load index: {e}")
            return {"files": {}}
        except ValueError as e:
            logger.warning(f"Invalid index structure: {e}")
            return {"files": {}}

    def _save_index(self, index: IndexData) -> None:
        """Save the DLL index to disk."""
        try:
            self._atomic_write_bytes(
                self._index_path,
                json.dumps(index, indent=2, default=str).encode("utf-8"),
            )
        except OSError as e:
            logger.error(f"Failed to save index: {e}")
            raise RepositoryError(f"Failed to save index: {e}") from e

    def _get_file_key(self, name: str, architecture: Architecture) -> str:
        """Generate a unique key for a DLL file."""
        return f"{architecture.value}/{name.lower()}"

    def _get_file_path(self, name: str, architecture: Architecture) -> Path:
        """Get the filesystem path for a DLL file."""
        arch_value = architecture.value if architecture != Architecture.UNKNOWN else "x64"
        return self._base_path / arch_value / name.lower()

    def _path_is_within_repository(self, file_path: Path) -> bool:
        """Return True when a filesystem path is owned by this repository."""
        try:
            file_path.resolve().relative_to(self._base_path.resolve())
        except (OSError, ValueError):
            return False
        return True

    def _path_location_is_within_repository(self, file_path: Path) -> bool:
        """Return True when the path itself is located under the repository root."""
        try:
            file_path.parent.resolve(strict=True).relative_to(self._base_path.resolve())
        except (OSError, ValueError):
            return False
        return True

    def _path_locations_match(self, left: Path, right: Path) -> bool:
        """Return True when two paths identify the same repository entry location."""
        try:
            left_parent = left.parent.resolve(strict=True)
            right_parent = right.parent.resolve(strict=True)
        except OSError:
            return False
        return left_parent == right_parent and left.name.lower() == right.name.lower()

    def _validate_repository_write_path(self, file_path: Path) -> None:
        """Reject writes through symlinks or paths escaping the repository root."""
        if file_path.is_symlink():
            raise RepositoryError(f"Refusing to write through symlink: {file_path}")
        if file_path.exists():
            if file_path.is_dir():
                raise RepositoryError(f"Refusing to write over directory: {file_path}")
            if not file_path.is_file():
                raise RepositoryError(
                    f"Refusing to write over non-regular file: {file_path}"
                )

        repository_root = self._base_path.resolve()
        try:
            file_path.parent.resolve(strict=True).relative_to(repository_root)
            file_path.resolve(strict=False).relative_to(repository_root)
        except (OSError, ValueError) as exc:
            raise RepositoryError(
                f"Refusing to write outside repository: {file_path}"
            ) from exc

    def _atomic_write_bytes(self, file_path: Path, content: bytes) -> None:
        """Write bytes through a same-directory temp file and atomic replace."""
        self._validate_repository_write_path(file_path)
        fd, temp_name = tempfile.mkstemp(
            dir=file_path.parent,
            prefix=f".{file_path.name}.",
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as temp_file:
                temp_file.write(content)
            temp_path.replace(file_path)
        except OSError:
            temp_path.unlink(missing_ok=True)
            raise

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
            storage_architecture = self._storage_architecture_for_save(dll_file, content)
            dll_file = replace(dll_file, architecture=storage_architecture)
            # Determine file path
            file_path = self._get_file_path(dll_file.name, dll_file.architecture)
            self._validate_payload_content(dll_file, content)
            self._validate_repository_write_path(file_path)
            self._validate_repository_write_path(self._index_path)
            previous_content = file_path.read_bytes() if file_path.exists() else None

            # Write content to disk
            self._atomic_write_bytes(file_path, content)

            # Persist canonical metadata matching the bytes actually written.
            dll_file = replace(
                dll_file,
                file_path=str(file_path),
                file_hash=calculate_sha256(content),
                file_size=len(content),
            )

            # Update index
            index = self._load_index()
            key = self._get_file_key(dll_file.name, dll_file.architecture)
            index["files"][key] = self._serialize_dll(dll_file)
            try:
                self._save_index(index)
            except RepositoryError:
                self._rollback_payload_write(file_path, previous_content)
                raise

            logger.debug("Saved DLL %s to %s", dll_file.name, file_path)
            return dll_file

        except OSError as e:
            logger.error(f"Failed to save DLL {dll_file.name}: {e}")
            raise RepositoryError(f"Failed to save DLL: {e}") from e

    def _rollback_payload_write(
        self,
        file_path: Path,
        previous_content: bytes | None,
    ) -> None:
        """Restore payload state after an index write failure."""
        try:
            if previous_content is None:
                file_path.unlink(missing_ok=True)
                return
            self._atomic_write_bytes(file_path, previous_content)
        except OSError as exc:
            logger.error("Failed to roll back payload write for %s: %s", file_path, exc)

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
        invalid_index_architectures: set[Architecture] = set()

        for arch in self._iter_architectures(architecture):
            key = self._get_file_key(name, arch)
            if key in index["files"]:
                indexed_dll = self._try_deserialize_dll(index["files"][key])
                if indexed_dll and self._indexed_payload_is_valid(
                    indexed_dll,
                    expected_name=name,
                    expected_architecture=arch,
                ):
                    return indexed_dll
                invalid_index_architectures.add(arch)

        # Check if file exists on disk without index entry
        for arch in self._iter_architectures(architecture):
            if arch in invalid_index_architectures:
                continue
            file_path = self._get_file_path(name, arch)
            fallback_path = self._validated_fallback_payload_path(file_path, arch)
            if fallback_path is not None:
                return self._create_dll_from_file(fallback_path, name, arch)

        return None

    def _validated_fallback_payload_path(
        self,
        file_path: Path,
        architecture: Architecture,
    ) -> Path | None:
        """Return a disk fallback payload only when its path is repository-owned."""
        if file_path.is_symlink():
            logger.warning("Skipping fallback DLL payload with symlink: %s", file_path)
            return None
        if not self._path_location_is_within_repository(file_path):
            logger.warning(
                "Skipping fallback DLL payload outside repository location: %s",
                file_path,
            )
            return None
        if not self._path_is_within_repository(file_path):
            logger.warning("Skipping fallback DLL payload outside repository: %s", file_path)
            return None
        if not file_path.is_file():
            return None
        if not self._fallback_payload_is_valid(file_path, file_path.name, architecture):
            logger.warning(
                "Skipping fallback payload that is not a valid DLL payload: %s",
                file_path,
            )
            return None
        return file_path

    @classmethod
    def _fallback_payload_is_valid(
        cls,
        file_path: Path,
        dll_name: str,
        architecture: Architecture,
    ) -> bool:
        """Return True when an orphaned disk payload is a DLL or DLL ZIP."""
        try:
            content = file_path.read_bytes()
        except OSError as exc:
            logger.warning("Skipping unreadable fallback DLL payload: %s", exc)
            return False
        return cls._content_matches_dll_payload(dll_name, architecture, content)

    @classmethod
    def _validate_payload_content(cls, dll_file: DLLFile, content: bytes) -> None:
        """Reject repository payloads that are neither a DLL nor a valid DLL ZIP."""
        if cls._content_matches_dll_payload(
            dll_file.name,
            dll_file.architecture,
            content,
        ):
            return
        raise RepositoryError(
            "Refusing to save non-DLL payload: content must be a PE DLL or a ZIP "
            "containing the requested DLL"
        )

    @classmethod
    def _storage_architecture_for_save(
        cls,
        dll_file: DLLFile,
        content: bytes,
    ) -> Architecture:
        """Return the concrete architecture used for repository storage."""
        if dll_file.architecture != Architecture.UNKNOWN:
            return dll_file.architecture

        detected_architecture = cls._detect_payload_architecture(dll_file.name, content)
        if detected_architecture is None:
            raise RepositoryError(
                "Refusing to save unknown-architecture payload without a valid "
                "x86 or x64 DLL"
            )
        return detected_architecture

    @classmethod
    def _content_matches_dll_payload(
        cls,
        dll_name: str,
        expected_architecture: Architecture,
        content: bytes,
    ) -> bool:
        """Return True for direct DLL bytes or a ZIP carrying the requested DLL."""
        detected_architecture = cls._detect_pe_dll_architecture(content)
        if detected_architecture is not None:
            return (
                expected_architecture == Architecture.UNKNOWN
                or detected_architecture == expected_architecture
            )
        return cls._zip_payload_contains_valid_dll(
            dll_name,
            expected_architecture,
            content,
        )

    @classmethod
    def _detect_payload_architecture(
        cls,
        dll_name: str,
        content: bytes,
    ) -> Architecture | None:
        """Detect the concrete architecture for direct DLL bytes or a DLL ZIP."""
        direct_architecture = cls._detect_pe_dll_architecture(content)
        if direct_architecture is not None:
            return direct_architecture
        return cls._detect_zip_payload_architecture(dll_name, content)

    @classmethod
    def _zip_payload_contains_valid_dll(
        cls,
        dll_name: str,
        expected_architecture: Architecture,
        content: bytes,
    ) -> bool:
        """Return True when ZIP content contains the requested PE DLL member."""
        return (
            cls._detect_zip_payload_architecture(
                dll_name,
                content,
                expected_architecture=expected_architecture,
            )
            is not None
        )

    @classmethod
    def _detect_zip_payload_architecture(
        cls,
        dll_name: str,
        content: bytes,
        *,
        expected_architecture: Architecture = Architecture.UNKNOWN,
    ) -> Architecture | None:
        """Return the architecture of the requested DLL member in a ZIP payload."""
        archive_buffer = BytesIO(content)
        if not zipfile.is_zipfile(archive_buffer):
            return None

        expected_name = dll_name.lower()
        try:
            with zipfile.ZipFile(BytesIO(content)) as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    member_name = member.filename.rsplit("/", 1)[-1].lower()
                    if member_name != expected_name:
                        continue
                    member_content = archive.read(member)
                    if not member_content:
                        continue
                    architecture = cls._detect_pe_dll_architecture(member_content)
                    if architecture is None:
                        continue
                    if (
                        expected_architecture == Architecture.UNKNOWN
                        or architecture == expected_architecture
                    ):
                        return architecture
        except (
            OSError,
            RuntimeError,
            NotImplementedError,
            zipfile.BadZipFile,
        ):
            return None
        return None

    @staticmethod
    def _detect_pe_dll_architecture(content: bytes) -> Architecture | None:
        """Return the concrete architecture when content is a PE DLL."""
        if not content.startswith(b"MZ"):
            return None
        if len(content) < _PE_POINTER_OFFSET + 4:
            return None

        pe_offset = int.from_bytes(
            content[_PE_POINTER_OFFSET:_PE_POINTER_OFFSET + 4],
            "little",
        )
        machine_offset = pe_offset + len(_PE_SIGNATURE)
        if (
            len(content) < machine_offset + 2
            or content[pe_offset:machine_offset] != _PE_SIGNATURE
        ):
            return None

        machine = int.from_bytes(content[machine_offset:machine_offset + 2], "little")
        architecture = _PE_MACHINE_ARCHITECTURES.get(machine)
        if architecture is None:
            return None

        characteristics_offset = machine_offset + _PE_CHARACTERISTICS_OFFSET_FROM_MACHINE
        if len(content) < characteristics_offset + 2:
            return None
        characteristics = int.from_bytes(
            content[characteristics_offset:characteristics_offset + 2],
            "little",
        )
        if characteristics & _PE_DLL_CHARACTERISTIC == 0:
            return None
        return architecture

    @classmethod
    def _content_is_pe_dll(
        cls,
        content: bytes,
        expected_architecture: Architecture,
    ) -> bool:
        architecture = cls._detect_pe_dll_architecture(content)
        if architecture is None:
            return False
        return (
            expected_architecture == Architecture.UNKNOWN
            or architecture == expected_architecture
        )

    @staticmethod
    def _iter_architectures(
        architecture: Architecture | None
    ) -> list[Architecture]:
        concrete_architectures: list[Architecture] = [
            arch for arch in Architecture if arch != Architecture.UNKNOWN
        ]
        if architecture is None:
            return concrete_architectures
        if architecture == Architecture.UNKNOWN:
            return [
                Architecture.X64,
                *[
                    arch for arch in concrete_architectures
                    if arch != Architecture.X64
                ],
            ]
        return [architecture]

    def find_by_hash(self, file_hash: str) -> DLLFile | None:
        """
        Find a DLL by its SHA256 hash.

        Args:
            file_hash: SHA256 hash of the DLL file

        Returns:
            DLLFile if found, None otherwise
        """
        index = self._load_index()
        for data in index["files"].values():
            if data.get("file_hash") != file_hash:
                continue
            indexed_dll = self._try_deserialize_dll(data)
            if indexed_dll and self._indexed_payload_is_valid(
                indexed_dll,
                expected_hash=file_hash,
            ):
                return indexed_dll
        return None

    def list_all(self) -> list[DLLFile]:
        """
        List all DLL files in the repository.

        Returns:
            List of all DLLFile entities in the repository
        """
        index = self._load_index()
        dll_files: list[DLLFile] = []
        for data in index["files"].values():
            indexed_dll = self._try_deserialize_dll(data)
            if indexed_dll and self._indexed_payload_is_valid(indexed_dll):
                dll_files.append(indexed_dll)
        return dll_files

    def delete(self, dll_file: DLLFile) -> bool:
        """
        Delete a DLL file from the repository.

        Args:
            dll_file: The DLL entity to delete

        Returns:
            True if deletion was successful, False otherwise
        """
        try:
            delete_target = self._resolve_delete_target(dll_file)
            if delete_target is None:
                return False

            file_path = self._resolve_delete_file_path(delete_target)
            if file_path is None:
                return False

            self._validate_repository_write_path(self._index_path)
            if not self._delete_path_is_safe(file_path):
                logger.warning(
                    "Refusing to delete DLL outside repository: %s",
                    file_path,
                )
                return False

            original_index, index_was_updated = self._remove_index_entry_for_delete(
                delete_target
            )
            self._unlink_payload_for_delete(
                file_path,
                index_was_updated=index_was_updated,
                original_index=original_index,
            )

            logger.info(f"Deleted DLL: {delete_target.name}")
            return True

        except (OSError, RepositoryError) as e:
            logger.error(f"Failed to delete DLL {dll_file.name}: {e}")
            return False

    def _resolve_delete_target(self, dll_file: DLLFile) -> DLLFile | None:
        """Return a concrete-architecture entity for delete operations."""
        if dll_file.architecture != Architecture.UNKNOWN:
            return dll_file

        if dll_file.file_path:
            architecture = self._architecture_from_repository_path(
                Path(dll_file.file_path)
            )
            if architecture is not None:
                return replace(dll_file, architecture=architecture)
            return dll_file

        existing = self.find_by_name(dll_file.name, Architecture.UNKNOWN)
        if existing is not None:
            return existing
        return replace(dll_file, architecture=Architecture.X64)

    def _architecture_from_repository_path(self, file_path: Path) -> Architecture | None:
        """Infer architecture from a path located inside a repository arch dir."""
        try:
            relative_parent = file_path.parent.resolve(strict=True).relative_to(
                self._base_path.resolve()
            )
        except (OSError, ValueError):
            return None
        if not relative_parent.parts:
            return None
        try:
            architecture = Architecture(relative_parent.parts[0])
        except ValueError:
            return None
        if architecture == Architecture.UNKNOWN:
            return None
        return architecture

    def _resolve_delete_file_path(self, dll_file: DLLFile) -> Path | None:
        """Resolve and validate the repository location targeted by delete()."""
        file_path = self._get_file_path(dll_file.name, dll_file.architecture)
        if not dll_file.file_path:
            return file_path

        provided_path = Path(dll_file.file_path)
        if not self._path_location_is_within_repository(provided_path):
            logger.warning(
                "Refusing to delete DLL outside repository: %s",
                provided_path,
            )
            return None
        if not self._path_locations_match(provided_path, file_path):
            logger.warning(
                "Refusing to delete DLL with mismatched path: %s",
                provided_path,
            )
            return None
        return provided_path

    def _delete_path_is_safe(self, file_path: Path) -> bool:
        """Return True when deleting this payload path cannot escape the repo."""
        if file_path.is_symlink():
            return self._path_location_is_within_repository(file_path)
        return self._path_is_within_repository(file_path)

    def _remove_index_entry_for_delete(
        self,
        dll_file: DLLFile,
    ) -> tuple[IndexData, bool]:
        """Remove delete target metadata before unlinking the payload."""
        index = self._load_index()
        original_index: IndexData = {"files": dict(index["files"])}
        key = self._get_file_key(dll_file.name, dll_file.architecture)
        if key not in index["files"]:
            return original_index, False

        del index["files"][key]
        self._save_index(index)
        return original_index, True

    def _unlink_payload_for_delete(
        self,
        file_path: Path,
        *,
        index_was_updated: bool,
        original_index: IndexData,
    ) -> None:
        """Unlink the payload and restore metadata if the filesystem delete fails."""
        if not file_path.is_symlink() and not file_path.exists():
            return

        try:
            file_path.unlink()
        except OSError:
            if index_was_updated:
                self._restore_index_after_delete_failure(original_index)
            raise

    def _restore_index_after_delete_failure(self, original_index: IndexData) -> None:
        """Best-effort rollback for an index update when payload deletion fails."""
        try:
            self._save_index(original_index)
        except RepositoryError as exc:
            logger.error("Failed to roll back DLL index after delete failure: %s", exc)

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

    def _try_deserialize_dll(self, data: IndexEntry) -> DLLFile | None:
        """Return a DLL entity from index data, skipping corrupt entries."""
        try:
            return self._deserialize_dll(data)
        except (TypeError, ValueError) as e:
            logger.warning("Skipping invalid DLL index entry: %s", e)
            return None

    def _indexed_payload_is_valid(
        self,
        dll_file: DLLFile,
        *,
        expected_name: str | None = None,
        expected_architecture: Architecture | None = None,
        expected_hash: str | None = None,
    ) -> bool:
        """Return True when indexed metadata points at a real repository file."""
        if not self._indexed_metadata_matches(
            dll_file,
            expected_name=expected_name,
            expected_architecture=expected_architecture,
        ):
            return False
        file_path = self._validated_indexed_payload_path(
            dll_file,
            expected_name=expected_name,
            expected_architecture=expected_architecture,
        )
        if file_path is None:
            return False
        return self._indexed_payload_content_matches(
            file_path,
            dll_file,
            expected_hash=expected_hash,
        )

    def _indexed_metadata_matches(
        self,
        dll_file: DLLFile,
        *,
        expected_name: str | None,
        expected_architecture: Architecture | None,
    ) -> bool:
        """Return True when indexed identity fields match the lookup context."""
        if expected_name is not None and dll_file.name.lower() != expected_name.lower():
            logger.warning(
                "Skipping DLL index entry with mismatched name: %s",
                dll_file.name,
            )
            return False
        if (
            expected_architecture is not None
            and dll_file.architecture != expected_architecture
        ):
            logger.warning(
                "Skipping DLL index entry with mismatched architecture: %s",
                dll_file.architecture.value,
            )
            return False
        return True

    def _validated_indexed_payload_path(
        self,
        dll_file: DLLFile,
        *,
        expected_name: str | None,
        expected_architecture: Architecture | None,
    ) -> Path | None:
        """Return the indexed payload path when it is owned by this repository."""
        if not dll_file.file_path:
            logger.warning("Skipping DLL index entry without payload path: %s", dll_file.name)
            return None

        file_path = Path(dll_file.file_path)
        if file_path.is_symlink():
            logger.warning("Skipping DLL index entry with symlink payload: %s", file_path)
            return None
        if not self._path_is_within_repository(file_path):
            logger.warning("Skipping DLL index entry outside repository: %s", file_path)
            return None
        if not file_path.is_file():
            logger.warning("Skipping DLL index entry with missing payload: %s", file_path)
            return None
        canonical_name = expected_name or dll_file.name
        canonical_architecture = expected_architecture or dll_file.architecture
        if not self._path_locations_match(
            file_path,
            self._get_file_path(canonical_name, canonical_architecture),
        ):
            logger.warning("Skipping DLL index entry with mismatched path: %s", file_path)
            return None
        return file_path

    @classmethod
    def _indexed_payload_content_matches(
        cls,
        file_path: Path,
        dll_file: DLLFile,
        *,
        expected_hash: str | None,
    ) -> bool:
        """Return True when indexed hash and size match actual payload bytes."""
        try:
            content = file_path.read_bytes()
        except OSError as exc:
            logger.warning("Skipping DLL index entry with unreadable payload: %s", exc)
            return False
        actual_hash = calculate_sha256(content)
        if dll_file.file_hash is not None and dll_file.file_hash != actual_hash:
            logger.warning("Skipping DLL index entry with mismatched hash: %s", file_path)
            return False
        if expected_hash is not None and expected_hash != actual_hash:
            logger.warning("Skipping DLL index entry with mismatched hash: %s", file_path)
            return False
        if dll_file.file_size is not None and dll_file.file_size != len(content):
            logger.warning("Skipping DLL index entry with mismatched size: %s", file_path)
            return False
        if not cls._content_matches_dll_payload(
            dll_file.name,
            dll_file.architecture,
            content,
        ):
            logger.warning("Skipping DLL index entry with non-DLL payload: %s", file_path)
            return False
        return True

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
