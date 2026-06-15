"""Tests for the anchor-extraction HTML parser, including its safety limits."""

import pytest

from dll_downloader.infrastructure.http import html_link_extractor as hle
from dll_downloader.infrastructure.http.html_link_extractor import (
    HTMLLinkExtractor,
    extract_links,
    extract_links_with_positions,
)


@pytest.mark.unit
def test_extract_links_returns_href_and_text() -> None:
    links = extract_links('<a href="/a.dll.html">First</a><a href="/b">Second</a>')

    assert links == [("/a.dll.html", "First"), ("/b", "Second")]


@pytest.mark.unit
def test_extract_links_with_positions_reports_absolute_offsets() -> None:
    html = 'x\n<a href="/a">A</a>'
    positions = extract_links_with_positions(html)

    assert positions == [("/a", "A", 2)]


@pytest.mark.unit
def test_unclosed_anchor_with_href_is_flushed() -> None:
    # No closing tag: the anchor is recovered by the unclosed-anchor flush.
    assert extract_links('<a href="/late.dll">trailing text') == [
        ("/late.dll", "trailing text")
    ]


@pytest.mark.unit
def test_unclosed_anchor_without_href_is_skipped_during_flush() -> None:
    # Unclosed and href-less: the flush loop skips it (no link recorded).
    assert extract_links("<a>no href and never closed") == []


@pytest.mark.unit
def test_anchor_depth_limit_stops_pushing_nested_anchors() -> None:
    over_limit = hle._MAX_ANCHOR_DEPTH + 1
    # Nested, unclosed anchors; the parser refuses to track past the depth cap.
    html = "".join(f'<a href="/d{i}">' for i in range(over_limit))

    links = extract_links(html)

    # Only the anchors within the depth cap are recovered by the flush.
    assert len(links) == hle._MAX_ANCHOR_DEPTH


@pytest.mark.unit
def test_endtag_stops_recording_once_link_limit_reached() -> None:
    count = hle._MAX_EXTRACTED_LINKS + 1
    html = "".join(f'<a href="/x{i}">t</a>' for i in range(count))

    links = extract_links(html)

    assert len(links) == hle._MAX_EXTRACTED_LINKS


@pytest.mark.unit
def test_flush_clears_stack_when_link_limit_reached() -> None:
    closed = "".join(f'<a href="/x{i}">t</a>' for i in range(hle._MAX_EXTRACTED_LINKS))
    # One extra unclosed anchor: the flush sees the limit is already reached.
    html = closed + '<a href="/overflow">'

    links = extract_links(html)

    assert len(links) == hle._MAX_EXTRACTED_LINKS


@pytest.mark.unit
def test_absolute_position_returns_minus_one_when_line_out_of_range() -> None:
    # getpos() reports line 1 before any feed; with no line offsets recorded
    # the position is out of range and reported as -1.
    extractor = HTMLLinkExtractor(line_offsets=())

    assert extractor._absolute_position() == -1
