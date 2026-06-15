"""
Bounded HTTP response stream reading helpers.
"""

import logging
import time
from collections.abc import Mapping

from ...domain.services.http_client import HTTPFileInfo
from ..http_session import HTTPResponseProtocol
from .transport import HTTP_STREAM_ERROR_TYPES, HTTPClientError, header_value

logger = logging.getLogger(__name__)


def validate_positive_size(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("max_download_bytes must be a positive integer")
    return value


def declared_content_length(
    response: HTTPResponseProtocol,
    *,
    max_bytes: int,
    operation: str,
    url: str,
) -> int | None:
    """Return a validated Content-Length header, if present."""
    content_length = header_value(dict(response.headers), "content-length")
    if content_length is None:
        return None
    try:
        declared_size = int(content_length)
    except ValueError as exc:
        raise HTTPClientError(
            f"Invalid Content-Length header: {content_length!r}",
            status_code=response.status_code,
            url=url,
        ) from exc
    if declared_size < 0:
        raise HTTPClientError(
            f"Invalid Content-Length header: {content_length!r}",
            status_code=response.status_code,
            url=url,
        )
    if declared_size > max_bytes:
        raise HTTPClientError(
            f"Content-Length {declared_size} exceeds {operation} limit {max_bytes}",
            status_code=response.status_code,
            url=url,
        )
    return declared_size


def read_bounded_response(
    response: HTTPResponseProtocol,
    *,
    max_bytes: int,
    wall_limit_seconds: float,
    operation: str,
    url: str,
    declared_size: int | None = None,
) -> bytes:
    """Read a streamed response while enforcing size and wall-clock limits."""
    chunks: list[bytes] = []
    total_bytes = 0
    stream_start = time.monotonic()
    for chunk in response.iter_content(chunk_size=8192):
        elapsed = time.monotonic() - stream_start
        if elapsed > wall_limit_seconds:
            raise HTTPClientError(
                f"{operation} exceeded wall-clock limit of {wall_limit_seconds}s",
                status_code=response.status_code,
                url=url,
            )
        if not chunk:
            continue
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise HTTPClientError(
                f"{operation} exceeds size limit {max_bytes}",
                status_code=response.status_code,
                url=url,
            )
        chunks.append(chunk)
    content = b"".join(chunks)
    if declared_size is not None and len(content) != declared_size:
        raise HTTPClientError(
            f"Incomplete download: received {len(content)} bytes, "
            f"expected {declared_size}",
            status_code=response.status_code,
            url=url,
        )
    return content


def close_response(response: HTTPResponseProtocol) -> None:
    close = getattr(response, "close", None)
    if not callable(close):
        return
    try:
        close()
    except HTTP_STREAM_ERROR_TYPES as exc:
        logger.warning("Failed to close response: %s", exc)


def file_info_from_headers(response_headers: Mapping[str, str]) -> HTTPFileInfo:
    content_length = header_value(response_headers, "content-length")
    length_value: int | None = None
    if content_length:
        try:
            parsed_length = int(content_length)
            if parsed_length >= 0:
                length_value = parsed_length
        except ValueError:
            length_value = None
    accept_ranges = header_value(response_headers, "accept-ranges")
    return {
        "content_type": header_value(response_headers, "content-type"),
        "content_length": length_value,
        "last_modified": header_value(response_headers, "last-modified"),
        "etag": header_value(response_headers, "etag"),
        "accept_ranges": bool(
            accept_ranges is not None and accept_ranges.lower() == "bytes"
        ),
    }


_TEXT_CHARSETS = frozenset(
    {
        "utf-8",
        "utf8",
        "utf-16",
        "utf-16-le",
        "utf-16-be",
        "utf-32",
        "utf-32-le",
        "utf-32-be",
        "ascii",
        "latin-1",
        "iso-8859-1",
        "iso-8859-15",
        "cp1252",
        "windows-1252",
        "cp1250",
        "windows-1250",
        "cp1251",
        "windows-1251",
        "shift_jis",
        "shift-jis",
        "euc-jp",
        "euc-kr",
        "gb2312",
        "gbk",
        "gb18030",
        "big5",
        "iso-2022-jp",
    }
)


def decode_text(content: bytes, headers: Mapping[str, str]) -> str:
    """Decode HTTP bytes using a conservative charset allowlist."""
    charset = _charset_from_headers(headers)
    try:
        return content.decode(charset)
    except LookupError:
        return content.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return content.decode(charset, errors="replace")


def _charset_from_headers(headers: Mapping[str, str]) -> str:
    content_type = header_value(headers, "content-type") or ""
    for part in content_type.split(";"):
        candidate = _charset_from_content_type_part(part)
        if candidate is not None:
            return candidate
    return "utf-8"


def _charset_from_content_type_part(part: str) -> str | None:
    stripped = part.strip()
    if not stripped.lower().startswith("charset="):
        return None
    candidate = stripped.split("=", 1)[1].strip().strip('"').strip("'").lower()
    if candidate in _TEXT_CHARSETS:
        return candidate
    return None
