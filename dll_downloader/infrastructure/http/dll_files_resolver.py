"""
DLL-files.com download URL resolver.

Resolves DLL names into direct download URLs by scraping search and download pages.
"""

import re
from dataclasses import dataclass, field
from html import unescape
from urllib.parse import quote, urljoin, urlparse

from ...domain.entities.dll_file import Architecture, normalize_dll_name
from ...domain.errors import DownloadResolutionError, HTTPServiceError
from ...domain.services.http_client import ITextHTTPClient
from .html_link_extractor import extract_links, extract_links_with_positions

_SECTION_START = "<section"
_SECTION_END = "</section>"
_SUPPORTED_DOWNLOAD_ARCHITECTURES = {Architecture.X86, Architecture.X64}
DownloadLinkCandidate = tuple[str, str, str]


def _default_port(scheme: str) -> int | None:
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


class DllFilesResolverError(DownloadResolutionError):
    """Raised when the resolver cannot derive a direct download URL."""


@dataclass
class DllFilesResolver:
    """
    Resolve direct download URLs from DLL-files.com.
    """

    http_client: ITextHTTPClient = field()
    base_url: str = "https://es.dll-files.com"

    def resolve_download_url(self, dll_name: str, architecture: Architecture) -> str:
        name = normalize_dll_name(dll_name)
        search_url = f"{self.base_url}/search/?q={quote(name, safe='')}"
        search_html = self._get(search_url)

        dll_page = self._extract_dll_page(search_html, name)
        if not dll_page:
            raise DllFilesResolverError(f"Could not find DLL page for {name}")

        dll_html = self._get(urljoin(self.base_url, dll_page))
        download_link = self._extract_download_link(dll_html, architecture)
        if not download_link:
            raise DllFilesResolverError(f"Could not find download link for {name}")

        download_html = self._get(urljoin(self.base_url, download_link))
        direct = self._extract_direct_link(download_html)
        if not direct:
            raise DllFilesResolverError(f"Could not resolve direct download for {name}")

        return direct

    def _get(self, url: str) -> str:
        try:
            return self.http_client.get_text(url)
        except (HTTPServiceError, ValueError) as exc:
            raise DllFilesResolverError(str(exc)) from exc

    def _extract_dll_page(self, html: str, dll_name: str) -> str | None:
        expected_page_name = f"{dll_name.lower()}.html"
        for href, _ in self._iter_links(html):
            if not self._is_base_url_link(href):
                continue
            href_page_name = urlparse(href).path.rstrip("/").rsplit("/", 1)[-1].lower()
            if href_page_name == expected_page_name:
                return href
        return None

    def _extract_download_link(
        self, html: str, architecture: Architecture
    ) -> str | None:
        candidates = self._download_link_candidates(html)
        if not candidates:
            return None

        if architecture == Architecture.UNKNOWN:
            return candidates[0][0]

        if architecture not in _SUPPORTED_DOWNLOAD_ARCHITECTURES:
            return None

        matched_link = self._candidate_link_text_match(candidates, architecture)
        if matched_link:
            return matched_link

        matched_context = self._candidate_context_match(candidates, architecture)
        if matched_context:
            return matched_context

        matched_href = self._candidate_href_match(candidates, architecture)
        if matched_href:
            return matched_href

        return None

    def _download_link_candidates(self, html: str) -> list[DownloadLinkCandidate]:
        return [
            (href, text, self._extract_link_context_at(html, position, text))
            for href, text, position in self._iter_links_with_positions(html)
            if self._is_valid_download_link(href)
        ]

    @staticmethod
    def _extract_link_context_at(
        html: str,
        position: int,
        link_text: str,
    ) -> str:
        if position == -1:
            return link_text

        lower_html = html.lower()
        start = lower_html.rfind(_SECTION_START, 0, position)
        if start == -1:
            return link_text

        previous_end = lower_html.rfind(_SECTION_END, 0, position)
        if previous_end > start:
            return link_text

        end = lower_html.find(_SECTION_END, position)
        if end == -1:
            return html[start:]
        return html[start : end + len(_SECTION_END)]

    def _candidate_link_text_match(
        self,
        candidates: list[DownloadLinkCandidate],
        architecture: Architecture,
    ) -> str | None:
        for href, link_text, _context in candidates:
            if self._context_matches_architecture(link_text, architecture):
                return href
        return None

    def _candidate_context_match(
        self,
        candidates: list[DownloadLinkCandidate],
        architecture: Architecture,
    ) -> str | None:
        for href, _link_text, context in candidates:
            if self._context_matches_architecture(context, architecture):
                return href
        return None

    def _candidate_href_match(
        self,
        candidates: list[DownloadLinkCandidate],
        architecture: Architecture,
    ) -> str | None:
        for href, link_text, context in candidates:
            if self._candidate_has_architecture(link_text, context):
                continue
            if self._href_matches_architecture(href, architecture):
                return href
        return None

    def _candidate_has_architecture(self, link_text: str, context: str) -> bool:
        return (
            self._context_architecture(link_text) is not None
            or self._context_architecture(context) is not None
        )

    def _context_matches_architecture(
        self,
        context: str,
        architecture: Architecture,
    ) -> bool:
        return self._context_architecture(context) == architecture

    def _context_architecture(self, context: str) -> Architecture | None:
        explicit_architectures = self._explicit_context_architectures(context)
        if len(explicit_architectures) == 1:
            return next(iter(explicit_architectures))
        if len(explicit_architectures) > 1:
            return None

        has_x64 = self._context_has_bits_hint(context, "64")
        has_x86 = self._context_has_bits_hint(context, "32")
        if has_x64 == has_x86:
            return None
        return Architecture.X64 if has_x64 else Architecture.X86

    def _explicit_context_architectures(self, context: str) -> set[Architecture]:
        text = self._html_text(context)
        architectures: set[Architecture] = set()
        for match in re.finditer(r"\barchitecture\s*:?\s*(32|64)\s*[- ]?bit\b", text):
            architectures.add(
                Architecture.X64 if match.group(1) == "64" else Architecture.X86
            )
        return architectures

    def _href_matches_architecture(
        self,
        href: str,
        architecture: Architecture,
    ) -> bool:
        path = urlparse(href).path.lower()
        if architecture == Architecture.X64:
            return bool(
                re.search(r"(^|[/_.-])x64([/_.-]|$)", path)
                or re.search(r"(^|[/_.-])64([/_.-]|$)", path)
            )
        if architecture == Architecture.X86:
            return bool(
                re.search(r"(^|[/_.-])x86([/_.-]|$)", path)
                or re.search(r"(^|[/_.-])32([/_.-]|$)", path)
            )
        return False

    def _context_has_bits_hint(self, context: str, bits: str) -> bool:
        text = self._html_text(context)
        return bool(
            re.search(rf">\s*{bits}\s*<", context)
            or re.search(rf"\b{bits}\s*[- ]?bit\b", text)
        )

    def _is_valid_download_link(self, href: str) -> bool:
        if not href:
            return False
        parsed_href = urlparse(href)
        if not parsed_href.path.startswith("/download/"):
            return False
        return self._is_base_url_link(href)

    def _extract_direct_link(self, html: str) -> str | None:  # noqa: C901
        for href, _ in self._iter_links(html):
            if self._is_official_zip_link(href):
                parsed = urlparse(href)
                if parsed.username is not None:
                    continue
                if parsed.scheme == "https":
                    try:
                        port = parsed.port
                    except ValueError:
                        continue
                    if port is not None and port != 443:
                        continue
                    return href
                if parsed.scheme == "" and parsed.netloc:
                    if "@" in parsed.netloc:
                        continue
                    try:
                        port = parsed.port
                    except ValueError:
                        continue
                    if port is not None and port != 443:
                        continue
                    parsed_base = urlparse(self.base_url)
                    allowed_hosts = {"download.zip.dll-files.com"}
                    if parsed_base.hostname:
                        allowed_hosts.add(parsed_base.hostname)
                    if parsed.hostname not in allowed_hosts:
                        continue
                    query = f"?{parsed.query}" if parsed.query else ""
                    return f"https://{parsed.netloc}{parsed.path}{query}"
        for href, _ in self._iter_links(html):
            if self._is_base_zip_link(href):
                return urljoin(self.base_url, href)
        return None

    def _is_base_url_link(self, href: str) -> bool:
        """Return True when a link stays on the configured base host."""
        parsed_href = urlparse(href)
        if parsed_href.scheme and parsed_href.scheme not in {"http", "https"}:
            return False
        if not parsed_href.netloc:
            return parsed_href.scheme == ""
        parsed_base = urlparse(self.base_url)
        href_scheme = parsed_href.scheme or parsed_base.scheme
        if href_scheme not in {"http", "https"}:
            return False
        if parsed_base.scheme == "https" and href_scheme == "http":
            return False
        try:
            href_port = parsed_href.port
            base_port = parsed_base.port
        except ValueError:
            return False
        if parsed_href.hostname != parsed_base.hostname:
            return False
        href_effective_port = href_port or _default_port(href_scheme)
        if base_port is not None:
            return href_effective_port == base_port
        return href_port is None or href_port == _default_port(href_scheme)

    @staticmethod
    def _is_official_zip_link(href: str) -> bool:
        parsed_href = urlparse(href)
        return (
            parsed_href.scheme in {"", "https"}
            and parsed_href.hostname == "download.zip.dll-files.com"
            and parsed_href.path.lower().endswith(".zip")
        )

    def _is_base_zip_link(self, href: str) -> bool:
        parsed_href = urlparse(href)
        return parsed_href.path.lower().endswith(".zip") and self._is_base_url_link(
            href
        )

    _TAG_PATTERN = re.compile(r"<[^>]*>")

    def _html_text(self, html: str) -> str:
        return unescape(self._TAG_PATTERN.sub(" ", html)).lower()

    def _iter_links(self, html: str) -> list[tuple[str, str]]:
        return extract_links(html)

    def _iter_links_with_positions(self, html: str) -> list[tuple[str, str, int]]:
        return extract_links_with_positions(html)
