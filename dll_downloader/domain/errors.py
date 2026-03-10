"""
Shared error taxonomy for domain-facing ports.
"""


class DomainPortError(Exception):
    """Base exception for failures crossing domain-facing ports."""


class RepositoryOperationError(DomainPortError):
    """Repository adapter failed to persist or retrieve data."""


class HTTPServiceError(DomainPortError):
    """HTTP adapter failed to communicate with a remote service."""


class DownloadResolutionError(DomainPortError):
    """Download URL resolution failed."""


class SecurityServiceError(DomainPortError):
    """Security scanning adapter failed."""
