"""
Domain Repository Interfaces

Abstract interfaces defining how domain entities are persisted and retrieved.
Implementations are provided in the infrastructure layer.
"""

from ..errors import RepositoryOperationError
from .dll_repository import IDLLRepository

__all__ = ["IDLLRepository", "RepositoryOperationError"]
