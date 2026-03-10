"""
HTML link extraction helpers for infrastructure adapters.
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class HTMLLinkExtractor(HTMLParser):
    """Extract ``(href, text)`` tuples from anchor tags."""

    links: list[tuple[str, str]] = field(default_factory=list)
    _current_href: str | None = None
    _current_text: list[str] = field(default_factory=list)
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
        for key, value in attrs:
            if key == "href":
                self._current_href = value or ""

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or not self._in_anchor:
            return

        self.links.append((self._current_href or "", "".join(self._current_text).strip()))
        self._current_href = None
        self._current_text = []
        self._in_anchor = False

    def handle_data(self, data: str) -> None:
        if self._in_anchor:
            self._current_text.append(data)


def extract_links(html: str) -> list[tuple[str, str]]:
    """Return all anchor links found in the given HTML fragment."""
    parser = HTMLLinkExtractor()
    parser.feed(html)
    return parser.links
