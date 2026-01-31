"""
DLL Repository Interface

Defines the contract for DLL file storage and retrieval operations.
"""

from abc import ABC, abstractmethod

from ..entities.dll_file import Architecture, DLLFile


class IDLLRepository(ABC):
    """
    Abstract repository interface for DLL file operations.

    This interface defines the contract that any DLL storage implementation
    must fulfill. Implementations may use local filesystem, cloud storage,
    databases, or any other storage mechanism.
    """

    @abstractmethod
    def save(self, dll_file: DLLFile, content: bytes) -> DLLFile:
        """
        Save a DLL file to the repository.

        Args:
            dll_file: The DLL entity with metadata
            content: Raw binary content of the DLL file

        Returns:
            Updated DLLFile entity with file_path set

        Raises:
            RepositoryError: If the save operation fails
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def find_by_hash(self, file_hash: str) -> DLLFile | None:
        """
        Find a DLL by its SHA256 hash.

        Args:
            file_hash: SHA256 hash of the DLL file

        Returns:
            DLLFile if found, None otherwise
        """
        pass

    @abstractmethod
    def list_all(self) -> list[DLLFile]:
        """
        List all DLL files in the repository.

        Returns:
            List of all DLLFile entities in the repository
        """
        pass

    @abstractmethod
    def delete(self, dll_file: DLLFile) -> bool:
        """
        Delete a DLL file from the repository.

        Args:
            dll_file: The DLL entity to delete

        Returns:
            True if deletion was successful, False otherwise
        """
        pass

    @abstractmethod
    def exists(self, name: str, architecture: Architecture | None = None) -> bool:
        """
        Check if a DLL exists in the repository.

        Args:
            name: The DLL filename to check
            architecture: Optional architecture filter

        Returns:
            True if the DLL exists, False otherwise
        """
        pass
