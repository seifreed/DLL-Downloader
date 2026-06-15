"""
Application-layer exceptions.
"""


class ApplicationError(Exception):
    """Base exception for application-layer failures."""


class DownloadExecutionError(ApplicationError):
    """Raised when a DLL download flow cannot complete."""


class ArchiveExtractionError(DownloadExecutionError):
    """Raised when an archive cannot be converted into DLL bytes."""
