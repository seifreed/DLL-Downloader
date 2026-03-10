from collections.abc import Generator, Mapping
from pathlib import Path

import pytest

from dll_downloader.domain.entities.dll_file import Architecture
from dll_downloader.infrastructure.http.dll_files_resolver import (
    DllFilesResolver,
    DllFilesResolverError,
)
from dll_downloader.infrastructure.http.http_client import RequestsHTTPClient


class StubTextHTTPClient:
    def __init__(self, responses: dict[str, str]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def get_text(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> str:
        self.calls.append(url)
        return self._responses[url]


@pytest.fixture
def resolver_server(tmp_path: Path) -> Generator[str]:
    import http.server
    import socketserver
    import threading

    dll_page = """
    <html><body>
      <a href="/download/aaa/msvcp140.dll.html">x86 version 32-bit</a>
      <div><a href="/download/bbb/msvcp140.dll.html">Download 64-bit</a></div>
    </body></html>
    """
    search_page = '<a href="/msvcp140.dll.html">msvcp140</a>'
    download_page = '<a href="https://download.zip.dll-files.com/aaa/msvcp140.zip?token=1">zip</a>'

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.startswith("/search/"):
                body = search_page
            elif self.path.startswith("/msvcp140.dll.html"):
                body = dll_page
            elif self.path.startswith("/download/aaa/") or self.path.startswith("/download/bbb/"):
                body = download_page
            else:
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, format: str, *args: object) -> None:
            pass

    with socketserver.TCPServer(("", 0), Handler) as httpd:
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever)
        thread.daemon = True
        thread.start()
        yield f"http://localhost:{port}"
        httpd.shutdown()


@pytest.mark.unit
def test_resolver_resolves_x64(resolver_server: str) -> None:
    resolver = DllFilesResolver(
        http_client=RequestsHTTPClient(timeout=5),
        base_url=resolver_server,
    )
    url = resolver.resolve_download_url("msvcp140.dll", Architecture.X64)
    assert "download.zip.dll-files.com" in url


@pytest.mark.unit
def test_resolver_resolves_x86(resolver_server: str) -> None:
    resolver = DllFilesResolver(
        http_client=RequestsHTTPClient(timeout=5),
        base_url=resolver_server,
    )
    url = resolver.resolve_download_url("msvcp140.dll", Architecture.X86)
    assert "download.zip.dll-files.com" in url


@pytest.mark.unit
def test_resolver_uses_injected_http_contract() -> None:
    base_url = "http://example.com"
    client = StubTextHTTPClient(
        {
            f"{base_url}/search/?q=msvcp140.dll": '<a href="/msvcp140.dll.html">msvcp140</a>',
            f"{base_url}/msvcp140.dll.html": (
                '<a href="/download/bbb/msvcp140.dll.html">Download 64-bit</a>'
            ),
            f"{base_url}/download/bbb/msvcp140.dll.html": (
                '<a href="https://download.zip.dll-files.com/aaa/msvcp140.zip?token=1">zip</a>'
            ),
        }
    )
    resolver = DllFilesResolver(base_url=base_url, http_client=client)

    url = resolver.resolve_download_url("msvcp140.dll", Architecture.X64)

    assert url.endswith("token=1")
    assert client.calls == [
        f"{base_url}/search/?q=msvcp140.dll",
        f"{base_url}/msvcp140.dll.html",
        f"{base_url}/download/bbb/msvcp140.dll.html",
    ]


@pytest.mark.unit
def test_resolver_unknown_architecture_uses_first_link(resolver_server: str) -> None:
    resolver = DllFilesResolver(
        http_client=RequestsHTTPClient(timeout=5),
        base_url=resolver_server,
    )
    url = resolver.resolve_download_url("msvcp140.dll", Architecture.UNKNOWN)
    assert "download.zip.dll-files.com" in url


@pytest.mark.unit
def test_resolver_missing_dll_page_raises(
    resolver_server: str,
) -> None:
    class BrokenResolver(DllFilesResolver):
        def _extract_dll_page(self, html: str, dll_name: str) -> None:
            return None

    resolver = BrokenResolver(
        http_client=RequestsHTTPClient(timeout=5),
        base_url=resolver_server,
    )
    with pytest.raises(DllFilesResolverError):
        resolver.resolve_download_url("missing.dll", Architecture.X64)


@pytest.mark.unit
def test_resolver_missing_download_link_raises(
    resolver_server: str,
) -> None:
    class BrokenResolver(DllFilesResolver):
        def _extract_download_link(
            self,
            html: str,
            architecture: Architecture,
        ) -> None:
            return None

    resolver = BrokenResolver(
        http_client=RequestsHTTPClient(timeout=5),
        base_url=resolver_server,
    )
    with pytest.raises(DllFilesResolverError):
        resolver.resolve_download_url("msvcp140.dll", Architecture.X64)


@pytest.mark.unit
def test_resolver_missing_direct_link_raises(
    resolver_server: str,
) -> None:
    class BrokenResolver(DllFilesResolver):
        def _extract_direct_link(self, html: str) -> None:
            return None

    resolver = BrokenResolver(
        http_client=RequestsHTTPClient(timeout=5),
        base_url=resolver_server,
    )
    with pytest.raises(DllFilesResolverError):
        resolver.resolve_download_url("msvcp140.dll", Architecture.X64)


@pytest.mark.unit
def test_extract_dll_page_no_match() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    assert resolver._extract_dll_page("<html></html>", "missing.dll") is None


@pytest.mark.unit
def test_extract_dll_page_non_matching_link() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = '<a href="/other.dll.html">Other</a>'
    assert resolver._extract_dll_page(html, "missing.dll") is None


@pytest.mark.unit
def test_extract_download_link_no_links() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    assert resolver._extract_download_link("<html></html>", Architecture.X64) is None


@pytest.mark.unit
def test_extract_download_link_ignores_external_non_download() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = (
        '<a href="https://www.microsoft.com/en-us/download/details.aspx?id=53840">'
        'Microsoft</a>'
        '<a href="/download/abc/file.dll.html">Download</a>'
    )
    assert resolver._extract_download_link(html, Architecture.X64) == "/download/abc/file.dll.html"


@pytest.mark.unit
def test_is_valid_download_link_variants() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    assert resolver._is_valid_download_link("") is False
    assert resolver._is_valid_download_link("/download/abc/file.dll.html") is True
    assert resolver._is_valid_download_link(
        "http://example.com/download/abc/file.dll.html"
    ) is True
    assert resolver._is_valid_download_link("http://example.com/other") is False


@pytest.mark.unit
def test_extract_direct_link_fallback_zip() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = '<a href="https://example.com/file.zip">zip</a>'
    direct_link = resolver._extract_direct_link(html)
    assert direct_link is not None
    assert direct_link.endswith(".zip")


@pytest.mark.unit
def test_extract_download_link_fallback_first() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = (
        '<a href="/other/link.html">Other</a>'
        '<a href="/download/aaa/file.dll.html">Download</a>'
    )
    assert resolver._extract_download_link(html, Architecture.X64) == "/download/aaa/file.dll.html"


@pytest.mark.unit
def test_extract_direct_link_none() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = '<a href="https://example.com/file.txt">txt</a>'
    assert resolver._extract_direct_link(html) is None


@pytest.mark.unit
def test_iter_links_anchor_without_href() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    links = resolver._iter_links('<a class="x">NoHref</a>')
    assert links == [("", "NoHref")]


@pytest.mark.unit
def test_get_uses_injected_http_client() -> None:
    client = StubTextHTTPClient({"http://example.com/search/?q=test.dll": "ok"})
    resolver = DllFilesResolver(http_client=client, base_url="http://example.com")

    assert resolver._get("http://example.com/search/?q=test.dll") == "ok"
