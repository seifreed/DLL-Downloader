from collections.abc import Generator, Mapping
from pathlib import Path

import pytest

from dll_downloader.domain.entities.dll_file import Architecture
from dll_downloader.infrastructure.http.dll_files_resolver import (
    DllFilesResolver,
    DllFilesResolverError,
)
from dll_downloader.infrastructure.http.http_client import (
    HTTPClientError,
    RequestsHTTPClient,
)


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


class FailingTextHTTPClient:
    def get_text(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> str:
        del headers
        raise HTTPClientError("transport failed", url=url)


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
        http_client=RequestsHTTPClient(timeout=5, verify_ssl=False, allowed_redirect_domains={"localhost"}),
        base_url=resolver_server,
    )
    url = resolver.resolve_download_url("msvcp140.dll", Architecture.X64)
    assert "download.zip.dll-files.com" in url


@pytest.mark.unit
def test_resolver_resolves_x86(resolver_server: str) -> None:
    resolver = DllFilesResolver(
        http_client=RequestsHTTPClient(timeout=5, verify_ssl=False, allowed_redirect_domains={"localhost"}),
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
        http_client=RequestsHTTPClient(timeout=5, verify_ssl=False, allowed_redirect_domains={"localhost"}),
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
def test_extract_dll_page_requires_exact_basename_match() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = (
        '<a href="/not-msvcp140.dll.html">Wrong</a>'
        '<a href="/msvcp140.dll.html">Right</a>'
    )

    assert resolver._extract_dll_page(html, "msvcp140.dll") == "/msvcp140.dll.html"


@pytest.mark.unit
def test_extract_dll_page_rejects_external_absolute_link() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="https://evil.example/msvcp140.dll.html">Wrong host</a>'

    assert resolver._extract_dll_page(html, "msvcp140.dll") is None


@pytest.mark.unit
def test_extract_dll_page_rejects_non_http_scheme() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="javascript:/msvcp140.dll.html">Wrong scheme</a>'

    assert resolver._extract_dll_page(html, "msvcp140.dll") is None


@pytest.mark.unit
def test_extract_dll_page_rejects_http_base_host_downgrade() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="http://es.dll-files.com/msvcp140.dll.html">Downgrade</a>'

    assert resolver._extract_dll_page(html, "msvcp140.dll") is None


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
    # The download link has no architecture hints, so a specific
    # architecture request returns None (only UNKNOWN falls back
    # to the first candidate).
    assert resolver._extract_download_link(html, Architecture.X64) is None
    assert resolver._extract_download_link(html, Architecture.UNKNOWN) == "/download/abc/file.dll.html"


@pytest.mark.unit
def test_extract_download_link_uses_section_context_for_architecture() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = """
    <section>
      <div class="right-pane"><p>Version</p><p>64</p></div>
      <div class="download-link"><a href="/download/x64/file.dll.html">Download</a></div>
    </section>
    <section>
      <div class="right-pane"><p>Version</p><p>32</p></div>
      <div class="download-link"><a href="/download/x86/file.dll.html">Download</a></div>
    </section>
    """

    assert resolver._extract_download_link(html, Architecture.X64) == (
        "/download/x64/file.dll.html"
    )
    assert resolver._extract_download_link(html, Architecture.X86) == (
        "/download/x86/file.dll.html"
    )


@pytest.mark.unit
def test_extract_download_link_uses_case_insensitive_section_context() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = """
    <SECTION>
      <p>Architecture: 64-bit</p>
      <div class="download-link"><a href="/download/aaa/file.dll.html">Download</a></div>
    </SECTION>
    <SECTION>
      <p>Architecture: 32-bit</p>
      <div class="download-link"><a href="/download/bbb/file.dll.html">Download</a></div>
    </SECTION>
    """

    assert resolver._extract_download_link(html, Architecture.X64) == (
        "/download/aaa/file.dll.html"
    )
    assert resolver._extract_download_link(html, Architecture.X86) == (
        "/download/bbb/file.dll.html"
    )


@pytest.mark.unit
def test_extract_download_link_does_not_inherit_closed_section_context() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = """
    <section>
      <p>Architecture: 64-bit</p>
    </section>
    <a href="/download/x86/file.dll.html">Download</a>
    """

    assert resolver._extract_download_link(html, Architecture.X64) is None
    assert resolver._extract_download_link(html, Architecture.X86) == (
        "/download/x86/file.dll.html"
    )


@pytest.mark.unit
def test_extract_download_link_uses_link_text_for_sibling_architecture_links() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = """
    <section>
      <a href="/download/aaa/file.dll.html">Download 64-bit</a>
      <a href="/download/bbb/file.dll.html">Download 32-bit</a>
    </section>
    """

    assert resolver._extract_download_link(html, Architecture.X64) == (
        "/download/aaa/file.dll.html"
    )
    assert resolver._extract_download_link(html, Architecture.X86) == (
        "/download/bbb/file.dll.html"
    )


@pytest.mark.unit
def test_extract_download_link_does_not_use_compatibility_text_as_architecture() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = """
    <section>
      <p>Architecture: 64-bit</p>
      <p>Works with 32-bit and 64-bit applications.</p>
      <div class="download-link"><a href="/download/x64/file.dll.html">Download</a></div>
    </section>
    <section>
      <p>Architecture: 32-bit</p>
      <div class="download-link"><a href="/download/x86/file.dll.html">Download</a></div>
    </section>
    """

    assert resolver._extract_download_link(html, Architecture.X86) == (
        "/download/x86/file.dll.html"
    )
    assert resolver._extract_download_link(html, Architecture.X64) == (
        "/download/x64/file.dll.html"
    )


@pytest.mark.unit
def test_extract_download_link_context_overrides_incidental_href_architecture() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = """
    <section>
      <p>Architecture: 32-bit</p>
      <div class="download-link">
        <a href="/download/build-64/file.dll.html">Download</a>
      </div>
    </section>
    <section>
      <p>Architecture: 64-bit</p>
      <div class="download-link">
        <a href="/download/real/file.dll.html">Download</a>
      </div>
    </section>
    """

    assert resolver._extract_download_link(html, Architecture.X86) == (
        "/download/build-64/file.dll.html"
    )
    assert resolver._extract_download_link(html, Architecture.X64) == (
        "/download/real/file.dll.html"
    )


@pytest.mark.unit
def test_extract_download_link_uses_actual_anchor_when_href_is_repeated() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = """
    <section>
      <p>Cached path: /download/x86/file.dll.html</p>
      <p>Architecture: 64-bit</p>
    </section>
    <section>
      <p>Architecture: 32-bit</p>
      <a href="/download/x86/file.dll.html">Download 32-bit</a>
    </section>
    <section>
      <p>Architecture: 64-bit</p>
      <a href="/download/x64/file.dll.html">Download 64-bit</a>
    </section>
    """

    assert resolver._extract_download_link(html, Architecture.X86) == (
        "/download/x86/file.dll.html"
    )
    assert resolver._extract_download_link(html, Architecture.X64) == (
        "/download/x64/file.dll.html"
    )


@pytest.mark.unit
def test_extract_download_link_falls_back_to_x86_href_when_context_is_ambiguous() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = '<a href="/download/x86/file.dll.html">Download</a>'

    assert resolver._extract_download_link(html, Architecture.X86) == (
        "/download/x86/file.dll.html"
    )


@pytest.mark.unit
def test_context_architecture_rejects_conflicting_explicit_architectures() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    context = "<p>Architecture: 64-bit</p><p>Architecture: 32-bit</p>"

    assert resolver._context_architecture(context) is None


@pytest.mark.unit
def test_href_matches_architecture_handles_x86_and_unknown_values() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )

    assert resolver._href_matches_architecture(
        "/download/x86/file.dll.html",
        Architecture.X86,
    )
    assert not resolver._href_matches_architecture(
        "/download/arm/file.dll.html",
        Architecture.ARM,
    )


@pytest.mark.unit
def test_extract_download_link_does_not_fallback_to_x64_for_x86_request() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = """
    <section>
      <div class="right-pane"><p>Version</p><p>64</p></div>
      <div class="download-link"><a href="/download/x64/file.dll.html">Download</a></div>
    </section>
    """

    assert resolver._extract_download_link(html, Architecture.X86) is None


@pytest.mark.unit
def test_extract_download_link_rejects_unsupported_architecture() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = '<a href="/download/abc/file.dll.html">Download</a>'

    assert resolver._extract_download_link(html, Architecture.ARM) is None


@pytest.mark.unit
def test_extract_link_context_at_returns_text_when_position_not_found() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )

    assert resolver._extract_link_context_at("<html></html>", -1, "Download") == (
        "Download"
    )


@pytest.mark.unit
def test_extract_link_context_at_handles_unclosed_section() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="http://example.com",
    )
    html = '<section><a href="/download/abc/file.dll.html">Download</a>'

    assert resolver._extract_link_context_at(
        html,
        html.find("/download/abc/file.dll.html"),
        "Download",
    ) == html


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
    assert resolver._is_valid_download_link(
        "//example.com/download/abc/file.dll.html"
    ) is True
    assert resolver._is_valid_download_link("http://example.com/other") is False


@pytest.mark.unit
def test_extract_download_link_accepts_protocol_relative_base_host() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = (
        '<a href="//es.dll-files.com/download/abc/msvcp140.dll.html">'
        "Download 64-bit</a>"
    )

    assert resolver._extract_download_link(html, Architecture.X64) == (
        "//es.dll-files.com/download/abc/msvcp140.dll.html"
    )


@pytest.mark.unit
def test_extract_download_link_rejects_single_slash_http_url() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="http:/download/abc/msvcp140.dll.html">Download 64-bit</a>'

    assert resolver._extract_download_link(html, Architecture.X64) is None


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
def test_extract_direct_link_fallback_zip_with_query_string() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://mirror.example.com",
    )
    html = '<a href="https://mirror.example.com/file.zip?token=abc">zip</a>'

    assert resolver._extract_direct_link(html) == (
        "https://mirror.example.com/file.zip?token=abc"
    )


@pytest.mark.unit
def test_extract_direct_link_accepts_uppercase_official_zip_extension() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="https://download.zip.dll-files.com/file.ZIP?token=1">zip</a>'

    assert resolver._extract_direct_link(html) == (
        "https://download.zip.dll-files.com/file.ZIP?token=1"
    )


@pytest.mark.unit
def test_extract_direct_link_accepts_uppercase_base_zip_extension() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://mirror.example.com",
    )
    html = '<a href="https://mirror.example.com/file.ZIP?token=abc">zip</a>'

    assert resolver._extract_direct_link(html) == (
        "https://mirror.example.com/file.ZIP?token=abc"
    )


@pytest.mark.unit
def test_extract_direct_link_rejects_external_zip_with_official_host_in_query() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = (
        '<a href="https://evil.example/payload.zip?next=download.zip.dll-files.com">'
        "zip</a>"
    )

    assert resolver._extract_direct_link(html) is None


@pytest.mark.unit
def test_extract_direct_link_rejects_non_http_base_zip() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="ftp://es.dll-files.com/file.zip">zip</a>'

    assert resolver._extract_direct_link(html) is None


@pytest.mark.unit
def test_extract_direct_link_rejects_non_http_official_zip() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="ftp://download.zip.dll-files.com/file.zip">zip</a>'

    assert resolver._extract_direct_link(html) is None


@pytest.mark.unit
def test_extract_direct_link_rejects_http_official_zip_downgrade() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="http://download.zip.dll-files.com/file.zip">zip</a>'

    assert resolver._extract_direct_link(html) is None


@pytest.mark.unit
def test_extract_direct_link_rejects_http_base_zip_downgrade() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="http://es.dll-files.com/file.zip">zip</a>'

    assert resolver._extract_direct_link(html) is None


@pytest.mark.unit
def test_extract_direct_link_rejects_single_slash_http_zip_url() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="http:/file.zip">zip</a>'

    assert resolver._extract_direct_link(html) is None


@pytest.mark.unit
def test_extract_direct_link_normalizes_protocol_relative_official_zip() -> None:
    resolver = DllFilesResolver(
        http_client=StubTextHTTPClient({}),
        base_url="https://es.dll-files.com",
    )
    html = '<a href="//download.zip.dll-files.com/file.zip?token=1">zip</a>'

    assert resolver._extract_direct_link(html) == (
        "https://download.zip.dll-files.com/file.zip?token=1"
    )


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
    # No architecture hints in the HTML; X64 request returns None.
    assert resolver._extract_download_link(html, Architecture.X64) is None
    # UNKNOWN architecture falls back to the first valid download link.
    assert resolver._extract_download_link(html, Architecture.UNKNOWN) == "/download/aaa/file.dll.html"


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


@pytest.mark.unit
def test_get_wraps_http_client_failures() -> None:
    resolver = DllFilesResolver(
        http_client=FailingTextHTTPClient(),
        base_url="http://example.com",
    )

    with pytest.raises(DllFilesResolverError, match="transport failed"):
        resolver.resolve_download_url("test.dll", Architecture.X64)
