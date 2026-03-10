"""
DLL-files.com download URL resolver.

Resolves DLL names into direct download URLs by scraping search and download pages.
"""

from dataclasses import dataclass, field
from urllib.parse import urljoin

from ...domain.entities.dll_file import Architecture, normalize_dll_name
from ...domain.errors import DownloadResolutionError
from ...domain.services.http_client import ITextHTTPClient
from .html_link_extractor import extract_links


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
        return self.http_client.get_text(url, headers={"User-Agent": "Mozilla/5.0"})

    def _extract_dll_page(self, html: str, dll_name: str) -> str | None:
        name_root = dll_name.lower().replace(".dll", "")
        for href, _ in self._iter_links(html):
            if href.endswith(".dll.html") and name_root in href.lower():
                return href
        return None

    def _extract_download_link(self, html: str, architecture: Architecture) -> str | None:
        links = [
            href
            for href, _ in self._iter_links(html)
            if self._is_valid_download_link(href)
        ]
        if not links:
            return None

        if architecture == Architecture.UNKNOWN:
            return links[0]

        arch_hint = "64" if architecture == Architecture.X64 else "32"
        for href, text in self._iter_links(html):
            if not self._is_valid_download_link(href):
                continue
            if arch_hint in text.lower():
                return href

        return links[0]

    def _is_valid_download_link(self, href: str) -> bool:
        if not href:
            return False
        base_download = self.base_url.rstrip("/") + "/download/"
        return href.startswith("/download/") or href.startswith(base_download)

    def _extract_direct_link(self, html: str) -> str | None:
        for href, _ in self._iter_links(html):
            if "download.zip.dll-files.com" in href:
                return href
        for href, _ in self._iter_links(html):
            if href.endswith(".zip"):
                return href
        return None

    def _iter_links(self, html: str) -> list[tuple[str, str]]:
        return extract_links(html)
