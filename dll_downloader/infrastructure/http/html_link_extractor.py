"""
HTML link extraction helpers for infrastructure adapters.
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class HTMLLinkExtractor(HTMLParser):
    """Extract ``(href, text)`` tuples from anchor tags."""

    line_offsets: tuple[int, ...] = (0,)
    links: list[tuple[str, str]] = field(default_factory=list)
    links_with_positions: list[tuple[str, str, int]] = field(default_factory=list)
    _current_href: str | None = None
    _current_text: list[str] = field(default_factory=list)
    _current_position: int = -1
    _in_anchor: bool = False

    def __post_init__(self) -> None:
        HTMLParser.__init__(self)

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag != "a":
            return

        self._in_anchor = True
        self._current_href = ""
        self._current_text = []
        self._current_position = self._absolute_position()
        for key, value in attrs:
            if key == "href":
                self._current_href = value or ""

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or not self._in_anchor:
            return

        href = self._current_href or ""
        text = "".join(self._current_text).strip()
        self.links.append((href, text))
        self.links_with_positions.append((href, text, self._current_position))
        self._current_href = None
        self._current_text = []
        self._current_position = -1
        self._in_anchor = False

    def handle_data(self, data: str) -> None:
        if self._in_anchor:
            self._current_text.append(data)

    def _absolute_position(self) -> int:
        line_number, column_offset = self.getpos()
        return self.line_offsets[line_number - 1] + column_offset


def _line_start_offsets(html: str) -> tuple[int, ...]:
    offsets = [0]
    for index, character in enumerate(html):
        if character == "\n":
            offsets.append(index + 1)
    return tuple(offsets)


def extract_links(html: str) -> list[tuple[str, str]]:
    """Return all anchor links found in the given HTML fragment."""
    parser = HTMLLinkExtractor(_line_start_offsets(html))
    parser.feed(html)
    return parser.links


def extract_links_with_positions(html: str) -> list[tuple[str, str, int]]:
    """Return all anchor links with their absolute ``<a>`` start offsets."""
    parser = HTMLLinkExtractor(_line_start_offsets(html))
    parser.feed(html)
    return parser.links_with_positions
