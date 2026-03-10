"""
Console presenters for download use cases.
"""

from ...application.use_cases.download_batch import DownloadBatchResponse
from ...application.use_cases.download_dll import DownloadDLLResponse


class DownloadConsolePresenter:
    """Render a single download result for console output."""

    def format(self, response: DownloadDLLResponse, dll_name: str) -> str:
        if not response.success:
            return f"[FAILED] {dll_name}: {response.error_message}"

        dll_file = response.dll_file
        lines: list[str] = []
        if response.was_cached:
            if not dll_file:
                return f"[FAILED] {dll_name}: cached file info missing"
            lines.append(f"[CACHED] {dll_name} already exists at: {dll_file.file_path}")
        else:
            lines.append(f"[OK] Downloaded: {dll_name}")
            if dll_file:
                lines.append(f"     Path: {dll_file.file_path}")
                if dll_file.file_hash:
                    lines.append(f"     SHA256: {dll_file.file_hash}")
                if dll_file.file_size:
                    lines.append(f"     Size: {dll_file.file_size / 1024:.2f} KB")

        if response.security_warning:
            lines.append(f"     {response.security_warning}")

        return "\n".join(lines)


class DownloadBatchConsolePresenter:
    """Render batch progress and summary for console output."""

    def __init__(self, item_presenter: DownloadConsolePresenter | None = None) -> None:
        self._item_presenter = item_presenter or DownloadConsolePresenter()

    @staticmethod
    def progress_line(dll_name: str, architecture_label: str) -> str:
        return f"\nSearching and downloading: {dll_name} ({architecture_label})"

    def render_item(self, response: DownloadDLLResponse, dll_name: str) -> str:
        return self._item_presenter.format(response, dll_name)

    def render_batch(
        self,
        response: DownloadBatchResponse,
        architecture_label: str,
    ) -> list[str]:
        lines: list[str] = []
        for item in response.items:
            lines.append(self.progress_line(item.dll_name, architecture_label))
            lines.append(self.render_item(item.response, item.dll_name))
        return lines

    @staticmethod
    def summary(response: DownloadBatchResponse) -> str:
        return f"\nSummary: {response.success_count} succeeded, {response.failure_count} failed"

    @staticmethod
    def summary_counts(success_count: int, failure_count: int) -> str:
        return f"\nSummary: {success_count} succeeded, {failure_count} failed"

    @staticmethod
    def boundary_error(error_message: str) -> str:
        return f"[ERROR] Batch download failed: {error_message}"
