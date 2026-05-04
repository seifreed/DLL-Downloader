"""
HTML link extraction helpers for infrastructure adapters.
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser

_MAX_ANCHOR_DEPTH = 256
_MAX_EXTRACTED_LINKS = 10_000


@dataclass
class HTMLLinkExtractor(HTMLParser):
    """Extract ``(href, text)`` tuples from anchor tags."""

    line_offsets: tuple[int, ...] = (0,)
    links: list[tuple[str, str]] = field(default_factory=list)
    links_with_positions: list[tuple[str, str, int]] = field(default_factory=list)
    _anchor_stack: list[tuple[str, list[str], int]] = field(default_factory=list)

    def __post_init__(self) -> None:
        HTMLParser.__init__(self, convert_charrefs=True)

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag != "a":
            return
        if len(self._anchor_stack) >= _MAX_ANCHOR_DEPTH:
            return

        href: str = ""
        for key, value in attrs:
            if key == "href":
                href = value or ""

        self._anchor_stack.append((href or "", [], self._absolute_position()))

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or not self._anchor_stack:
            return
        if len(self.links) >= _MAX_EXTRACTED_LINKS:
            self._anchor_stack.clear()
            return

        href, text_parts, position = self._anchor_stack.pop()
        text = "".join(text_parts).strip()
        self.links.append((href, text))
        self.links_with_positions.append((href, text, position))

    def handle_data(self, data: str) -> None:
        for _href, text_parts, _pos in self._anchor_stack:
            text_parts.append(data)

    def _absolute_position(self) -> int:
        line_number, column_offset = self.getpos()
        if line_number < 1 or line_number > len(self.line_offsets):
            return -1
        return self.line_offsets[line_number - 1] + column_offset


def _line_start_offsets(html: str) -> tuple[int, ...]:
    offsets = [0]
    for index, character in enumerate(html):
        if character == "\n":
            offsets.append(index + 1)
    return tuple(offsets)


def _flush_unclosed_anchors(parser: HTMLLinkExtractor) -> None:
    while parser._anchor_stack and len(parser.links) < _MAX_EXTRACTED_LINKS:
        href, text_parts, position = parser._anchor_stack.pop()
        text = "".join(text_parts).strip()
        if href:
            parser.links.append((href, text))
            parser.links_with_positions.append((href, text, position))
    if len(parser.links) >= _MAX_EXTRACTED_LINKS:
        parser._anchor_stack.clear()


def extract_links(html: str) -> list[tuple[str, str]]:
    """Return all anchor links found in the given HTML fragment."""
    parser = HTMLLinkExtractor(_line_start_offsets(html))
    parser.feed(html)
    _flush_unclosed_anchors(parser)
    return parser.links


def extract_links_with_positions(html: str) -> list[tuple[str, str, int]]:
    """Return all anchor links with their absolute ``<a>`` start offsets."""
    parser = HTMLLinkExtractor(_line_start_offsets(html))
    parser.feed(html)
    _flush_unclosed_anchors(parser)
    return parser.links_with_positions
