"""
DLL-files.com download URL resolver.

Resolves DLL names into direct download URLs by scraping search and download pages.
"""

import re
from dataclasses import dataclass, field
from html import unescape
from urllib.parse import urljoin, urlparse

from ...domain.entities.dll_file import Architecture, normalize_dll_name
from ...domain.errors import DownloadResolutionError, HTTPServiceError
from ...domain.services.http_client import ITextHTTPClient
from .html_link_extractor import extract_links

_SECTION_END = "</section>"
_SUPPORTED_DOWNLOAD_ARCHITECTURES = {Architecture.X86, Architecture.X64}


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
        search_url = f"{self.base_url}/search/?q={name}"
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

    def _extract_download_link(self, html: str, architecture: Architecture) -> str | None:
        candidates = [
            (href, self._extract_link_context(html, href, text))
            for href, text in self._iter_links(html)
            if self._is_valid_download_link(href)
        ]
        if not candidates:
            return None

        if architecture == Architecture.UNKNOWN:
            return candidates[0][0]

        if architecture not in _SUPPORTED_DOWNLOAD_ARCHITECTURES:
            return None

        for href, context in candidates:
            if self._context_matches_architecture(context, architecture):
                return href

        has_architecture_hints = any(
            self._context_has_architecture_hint(context)
            for _, context in candidates
        )
        if architecture == Architecture.X64 and not has_architecture_hints:
            return candidates[0][0]

        return None

    def _extract_link_context(self, html: str, href: str, link_text: str) -> str:
        position = html.find(href)
        if position == -1:
            return link_text

        start = html.rfind("<section", 0, position)
        if start == -1:
            return link_text

        end = html.find(_SECTION_END, position)
        if end == -1:
            return html[start:]
        return html[start:end + len(_SECTION_END)]

    def _context_matches_architecture(
        self,
        context: str,
        architecture: Architecture,
    ) -> bool:
        bits = "64" if architecture == Architecture.X64 else "32"
        return self._context_has_bits_hint(context, bits)

    def _context_has_architecture_hint(self, context: str) -> bool:
        return self._context_has_bits_hint(context, "32") or self._context_has_bits_hint(
            context,
            "64",
        )

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

    def _extract_direct_link(self, html: str) -> str | None:
        for href, _ in self._iter_links(html):
            if self._is_official_zip_link(href):
                return urljoin("https:", href)
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
            return True
        parsed_base = urlparse(self.base_url)
        if parsed_href.netloc.lower() != parsed_base.netloc.lower():
            return False
        return not (parsed_base.scheme == "https" and parsed_href.scheme == "http")

    @staticmethod
    def _is_official_zip_link(href: str) -> bool:
        parsed_href = urlparse(href)
        return (
            parsed_href.scheme in {"", "https"}
            and parsed_href.hostname == "download.zip.dll-files.com"
            and parsed_href.path.endswith(".zip")
        )

    def _is_base_zip_link(self, href: str) -> bool:
        parsed_href = urlparse(href)
        return parsed_href.path.endswith(".zip") and self._is_base_url_link(href)

    def _html_text(self, html: str) -> str:
        return unescape(re.sub(r"<[^>]+>", " ", html)).lower()

    def _iter_links(self, html: str) -> list[tuple[str, str]]:
        return extract_links(html)
