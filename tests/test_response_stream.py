"""Tests for bounded HTTP response-stream reading and header helpers."""

from collections.abc import Iterator
from typing import cast

import pytest

from dll_downloader.infrastructure.http.response_stream import (
    _charset_from_content_type_part,
    declared_content_length,
    decode_text,
    file_info_from_headers,
    read_bounded_response,
)
from dll_downloader.infrastructure.http.transport import HTTPClientError
from dll_downloader.infrastructure.http_session import HTTPResponseProtocol


class _Response:
    def __init__(
        self,
        headers: dict[str, str],
        *,
        status_code: int = 200,
        chunks: tuple[bytes, ...] = (),
    ) -> None:
        self.headers = headers
        self.status_code = status_code
        self._chunks = chunks

    def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
        yield from self._chunks


def _make_response(
    headers: dict[str, str],
    *,
    status_code: int = 200,
    chunks: tuple[bytes, ...] = (),
) -> HTTPResponseProtocol:
    return cast(
        HTTPResponseProtocol,
        _Response(headers, status_code=status_code, chunks=chunks),
    )


@pytest.mark.unit
def test_declared_content_length_rejects_non_numeric_header() -> None:
    response = _make_response({"Content-Length": "not-a-number"})

    with pytest.raises(HTTPClientError, match="Invalid Content-Length"):
        declared_content_length(
            response, max_bytes=1000, operation="download", url="https://x"
        )


@pytest.mark.unit
def test_declared_content_length_rejects_value_over_limit() -> None:
    response = _make_response({"Content-Length": "2000"})

    with pytest.raises(HTTPClientError, match="exceeds download limit"):
        declared_content_length(
            response, max_bytes=1000, operation="download", url="https://x"
        )


@pytest.mark.unit
def test_declared_content_length_returns_none_without_header() -> None:
    assert (
        declared_content_length(
            _make_response({}), max_bytes=1000, operation="download", url="https://x"
        )
        is None
    )


@pytest.mark.unit
def test_read_bounded_response_enforces_wall_clock_limit() -> None:
    response = _make_response({}, chunks=(b"data",))

    with pytest.raises(HTTPClientError, match="wall-clock limit"):
        read_bounded_response(
            response,
            max_bytes=1000,
            wall_limit_seconds=-1.0,
            operation="download",
            url="https://x",
        )


@pytest.mark.unit
def test_read_bounded_response_rejects_oversized_stream() -> None:
    response = _make_response({}, chunks=(b"a" * 50, b"b" * 60))

    with pytest.raises(HTTPClientError, match="exceeds size limit"):
        read_bounded_response(
            response,
            max_bytes=80,
            wall_limit_seconds=10.0,
            operation="download",
            url="https://x",
        )


@pytest.mark.unit
def test_read_bounded_response_rejects_incomplete_download() -> None:
    response = _make_response({}, chunks=(b"abc",))

    with pytest.raises(HTTPClientError, match="Incomplete download"):
        read_bounded_response(
            response,
            max_bytes=1000,
            wall_limit_seconds=10.0,
            operation="download",
            url="https://x",
            declared_size=999,
        )


@pytest.mark.unit
def test_read_bounded_response_skips_empty_chunks_and_returns_content() -> None:
    response = _make_response({}, chunks=(b"", b"ab", b"", b"c"))

    content = read_bounded_response(
        response,
        max_bytes=1000,
        wall_limit_seconds=10.0,
        operation="download",
        url="https://x",
    )

    assert content == b"abc"


@pytest.mark.unit
def test_file_info_from_headers_without_content_length() -> None:
    info = file_info_from_headers({"Content-Type": "application/octet-stream"})

    assert info["content_length"] is None
    assert info["content_type"] == "application/octet-stream"
    assert info["accept_ranges"] is False


@pytest.mark.unit
def test_decode_text_replaces_undecodable_bytes() -> None:
    # 0xFF is not valid ASCII; decoding must fall back to errors="replace".
    decoded = decode_text(b"abc\xff", {"Content-Type": "text/plain; charset=ascii"})

    assert decoded.startswith("abc")
    assert "�" in decoded


@pytest.mark.unit
def test_charset_from_content_type_part_ignores_unknown_charset() -> None:
    assert _charset_from_content_type_part("charset=made-up-encoding") is None
    # A non-charset part also yields None.
    assert _charset_from_content_type_part("text/plain") is None
