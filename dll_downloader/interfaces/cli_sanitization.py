"""Sanitize CLI boundary error messages."""

import re

_PATH_PATTERN = re.compile(r"(^|\s|['\"])(/[^\s'\"]+)")
_WINDOWS_DRIVE_PATH_PATTERN = re.compile(r"(^|\s|['\"])([A-Za-z]:[\\/][^\s'\"]+)")
_WINDOWS_UNC_PATH_PATTERN = re.compile(r"(^|\s|['\"])(\\\\[^\s'\"]+)")
_QUOTED_PATH_PATTERN = re.compile(
    r"(?P<quote>['\"])"
    r"(?P<path>(?!(?:[A-Za-z][A-Za-z0-9+.-]*:)?//)[^'\"\s]*[\\/][^'\"]+)"
    r"(?P=quote)"
)
_URL_CREDENTIALS_PATTERN = re.compile(r"://[^/\s:@]+:[^/\s@]+@|://[^/\s:@]+@")


def _path_replacer(match: re.Match[str]) -> str:
    prefix = match.group(1) or ""
    return f"{prefix}<path>"


def _quoted_path_replacer(match: re.Match[str]) -> str:
    quote = match.group("quote")
    return f"{quote}<path>{quote}"


def sanitize_boundary_message(exc: Exception) -> str:
    """Remove filesystem paths and URL credentials from exception messages."""
    message = str(exc)
    message = _QUOTED_PATH_PATTERN.sub(_quoted_path_replacer, message)
    message = _PATH_PATTERN.sub(_path_replacer, message)
    message = _WINDOWS_DRIVE_PATH_PATTERN.sub(_path_replacer, message)
    message = _WINDOWS_UNC_PATH_PATTERN.sub(_path_replacer, message)
    return _URL_CREDENTIALS_PATTERN.sub("://<credentials>@", message)
