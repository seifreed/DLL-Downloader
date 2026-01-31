"""
Infrastructure Layer

Contains implementations of domain interfaces and external service integrations.
This layer provides concrete implementations for repositories, HTTP clients,
external services like VirusTotal, and configuration management.
"""

from .config import Settings
from .persistence import FileSystemDLLRepository, RepositoryError

__all__ = [
    "FileSystemDLLRepository",
    "RepositoryError",
    "Settings",
]
