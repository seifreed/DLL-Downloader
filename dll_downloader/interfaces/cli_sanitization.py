"""Sanitize CLI boundary error messages."""

import re

_PATH_PATTERN = re.compile(r"(^|\s|['\"])(/[^\s'\"]+)")
_WINDOWS_DRIVE_PATH_PATTERN = re.compile(r"(^|\s|['\"])([A-Za-z]:[\\/][^\s'\"]+)")
_WINDOWS_UNC_PATH_PATTERN = re.compile(r"(^|\s|['\"])(\\\\[^\s'\"]+)")
_URL_CREDENTIALS_PATTERN = re.compile(r"://[^/\s:@]+:[^/\s@]+@|://[^/\s:@]+@")


def _path_replacer(match: re.Match[str]) -> str:
    prefix = match.group(1) or ""
    return f"{prefix}<path>"


def sanitize_boundary_message(exc: Exception) -> str:
    """Remove filesystem paths and URL credentials from exception messages."""
    message = str(exc)
    message = _PATH_PATTERN.sub(_path_replacer, message)
    message = _WINDOWS_DRIVE_PATH_PATTERN.sub(_path_replacer, message)
    message = _WINDOWS_UNC_PATH_PATTERN.sub(_path_replacer, message)
    return _URL_CREDENTIALS_PATTERN.sub("://<credentials>@", message)
