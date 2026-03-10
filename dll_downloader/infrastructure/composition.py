"""
Default production composition for the DLL downloader runtime.
"""

from pathlib import Path
from typing import cast

from ..application.use_cases.download_dll import DownloadDLLUseCase
from ..bootstrap import (
    CloseableSecurityScanner,
    DownloadApplication,
    DownloadApplicationAssembler,
    DownloadComponentFactory,
)
from ..domain.repositories.dll_repository import IDLLRepository
from ..domain.services import IDownloadURLResolver, IHTTPClient, ISecurityScanner
from .config.settings import Settings
from .http.dll_files_resolver import DllFilesResolver
from .http.http_client import RequestsHTTPClient
from .http.user_agents import RandomUserAgentProvider
from .persistence.file_repository import FileSystemDLLRepository
from .services.virustotal import VirusTotalScanner


class DefaultDownloadComponentFactory:
    """Default concrete adapter factory for production runtime wiring."""

    def create_repository(self, output_path: Path) -> IDLLRepository:
        return FileSystemDLLRepository(output_path)

    def create_http_client(self, settings: Settings) -> RequestsHTTPClient:
        user_agent_provider = None
        if settings.user_agent_pool:
            user_agent_provider = RandomUserAgentProvider(settings.user_agent_pool)
        return RequestsHTTPClient(
            timeout=settings.http_timeout,
            user_agent=settings.user_agent,
            max_retries=settings.http_max_retries,
            retry_backoff_seconds=settings.http_retry_backoff_seconds,
            retry_jitter_seconds=settings.http_retry_jitter_seconds,
            verify_ssl=settings.verify_ssl,
            user_agent_provider=user_agent_provider,
        )

    def create_scanner(
        self,
        settings: Settings,
    ) -> CloseableSecurityScanner | None:
        if not settings.virustotal_api_key:
            return None
        return VirusTotalScanner(
            api_key=settings.virustotal_api_key,
            malicious_threshold=settings.malicious_threshold,
            suspicious_threshold=settings.suspicious_threshold,
        )

    def create_resolver(
        self,
        settings: Settings,
        http_client: IHTTPClient,
    ) -> IDownloadURLResolver:
        return DllFilesResolver(
            http_client=http_client,
            base_url=settings.download_base_url,
        )


class FactoryBackedDownloadApplicationAssembler:
    """Assemble the runtime by delegating concrete adapter creation to a factory."""

    def __init__(self, factory: DownloadComponentFactory) -> None:
        self._factory = factory

    def build(
        self,
        settings: Settings,
        output_dir: str | None = None,
    ) -> DownloadApplication:
        download_path = Path(output_dir) if output_dir else settings.downloads_path

        repository = self._factory.create_repository(download_path)
        http_client = self._factory.create_http_client(settings)
        scanner = self._factory.create_scanner(settings)
        resolver = self._factory.create_resolver(settings, http_client)

        use_case = DownloadDLLUseCase(
            repository=repository,
            http_client=http_client,
            download_base_url=settings.download_base_url,
            scanner=cast(ISecurityScanner | None, scanner),
            resolver=resolver,
        )

        return DownloadApplication(
            use_case=use_case,
            http_client=http_client,
            scanner=scanner,
        )


def build_default_download_application(
    settings: Settings,
    output_dir: str | None = None,
    factory: DownloadComponentFactory | None = None,
) -> DownloadApplication:
    """Build the default production runtime with concrete infrastructure adapters."""
    assembler: DownloadApplicationAssembler = FactoryBackedDownloadApplicationAssembler(
        factory or DefaultDownloadComponentFactory()
    )
    return assembler.build(settings, output_dir=output_dir)
