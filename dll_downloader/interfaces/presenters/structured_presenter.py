"""
Structured presenters for machine-readable CLI output.
"""

import json
from datetime import datetime
from typing import Any

from ...application.use_cases.download_batch import (
    DownloadBatchItem,
    DownloadBatchResponse,
)
from ...application.use_cases.download_dll import DownloadDLLResponse
from ...domain.entities.dll_file import DLLFile

STRUCTURED_OUTPUT_VERSION = "1.0"


def _serialize_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _serialize_dll_file(dll_file: DLLFile | None) -> dict[str, Any] | None:
    if dll_file is None:
        return None

    return {
        "name": dll_file.name,
        "version": dll_file.version,
        "architecture": dll_file.architecture.value,
        "file_hash": dll_file.file_hash,
        "file_path": dll_file.file_path,
        "download_url": dll_file.download_url,
        "file_size": dll_file.file_size,
        "security_status": dll_file.security_status.value,
        "vt_detection_ratio": dll_file.vt_detection_ratio,
        "vt_scan_date": _serialize_datetime(dll_file.vt_scan_date),
        "created_at": _serialize_datetime(dll_file.created_at),
    }


def _serialize_response(
    dll_name: str,
    response: DownloadDLLResponse,
) -> dict[str, Any]:
    return {
        "dll_name": dll_name,
        "success": response.success,
        "was_cached": response.was_cached,
        "error_message": response.error_message,
        "security_warning": response.security_warning,
        "dll_file": _serialize_dll_file(response.dll_file),
    }


class DownloadBatchJSONPresenter:
    """Render batch responses as one JSON document."""

    def render_batch(
        self,
        response: DownloadBatchResponse,
        architecture_label: str,
    ) -> list[str]:
        payload = {
            "format": "json",
            "schema_version": STRUCTURED_OUTPUT_VERSION,
            "tool": "dll_downloader",
            "architecture": architecture_label,
            "success_count": response.success_count,
            "failure_count": response.failure_count,
            "items": [
                _serialize_response(item.dll_name, item.response)
                for item in response.items
            ],
        }
        return [json.dumps(payload, sort_keys=True)]

    def summary_counts(self, success_count: int, failure_count: int) -> str | None:
        return None

    def boundary_error(self, error_message: str) -> str:
        payload = {
            "format": "json",
            "schema_version": STRUCTURED_OUTPUT_VERSION,
            "tool": "dll_downloader",
            "success": False,
            "error": {
                "kind": "boundary",
                "message": error_message,
            },
        }
        return json.dumps(payload, sort_keys=True)


class DownloadBatchSARIFPresenter:
    """Render batch responses as a SARIF v2.1.0 log."""

    _DOWNLOAD_FAILED_RULE = "dll-downloader/download-failed"
    _DOWNLOAD_SUCCEEDED_RULE = "dll-downloader/download-succeeded"
    _DOWNLOAD_CACHED_RULE = "dll-downloader/download-cached"
    _SECURITY_WARNING_RULE = "dll-downloader/security-warning"
    _BOUNDARY_FAILURE_RULE = "dll-downloader/boundary-failure"

    def render_batch(
        self,
        response: DownloadBatchResponse,
        architecture_label: str,
    ) -> list[str]:
        payload = self._build_log(
            results=self._build_batch_results(response.items, architecture_label),
            properties={
                "architecture": architecture_label,
                "successCount": response.success_count,
                "failureCount": response.failure_count,
                "structuredOutputVersion": STRUCTURED_OUTPUT_VERSION,
            },
        )
        return [json.dumps(payload, sort_keys=True)]

    def summary_counts(self, success_count: int, failure_count: int) -> str | None:
        return None

    def boundary_error(self, error_message: str) -> str:
        payload = self._build_log(
            results=[
                {
                    "ruleId": self._BOUNDARY_FAILURE_RULE,
                    "level": "error",
                    "message": {"text": error_message},
                    "properties": {"kind": "boundary"},
                }
            ],
            properties={
                "successCount": 0,
                "failureCount": 1,
                "structuredOutputVersion": STRUCTURED_OUTPUT_VERSION,
            },
        )
        return json.dumps(payload, sort_keys=True)

    def _build_batch_results(
        self,
        items: list[DownloadBatchItem],
        architecture_label: str,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for item in items:
            results.append(
                self._build_item_result(item.dll_name, item.response, architecture_label)
            )
            if item.response.security_warning:
                results.append(
                    self._build_security_warning_result(
                        item.dll_name,
                        item.response,
                        architecture_label,
                    )
                )
        return results

    def _build_item_result(
        self,
        dll_name: str,
        response: DownloadDLLResponse,
        architecture_label: str,
    ) -> dict[str, Any]:
        if not response.success:
            return {
                "ruleId": self._DOWNLOAD_FAILED_RULE,
                "level": "error",
                "message": {
                    "text": response.error_message or f"Failed to download {dll_name}"
                },
                "properties": {
                    "dllName": dll_name,
                    "architecture": architecture_label,
                    "success": False,
                },
            }

        file_properties = _serialize_dll_file(response.dll_file)
        result: dict[str, Any] = {
            "ruleId": (
                self._DOWNLOAD_CACHED_RULE
                if response.was_cached
                else self._DOWNLOAD_SUCCEEDED_RULE
            ),
            "level": "note",
            "message": {
                "text": (
                    f"Using cached DLL for {dll_name}"
                    if response.was_cached
                    else f"Downloaded DLL {dll_name}"
                )
            },
            "properties": {
                "dllName": dll_name,
                "architecture": architecture_label,
                "success": True,
                "wasCached": response.was_cached,
                "dllFile": file_properties,
            },
        }
        if response.dll_file and response.dll_file.file_path:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": response.dll_file.file_path}
                    }
                }
            ]
        return result

    def _build_security_warning_result(
        self,
        dll_name: str,
        response: DownloadDLLResponse,
        architecture_label: str,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ruleId": self._SECURITY_WARNING_RULE,
            "level": "warning",
            "message": {"text": response.security_warning or "Security warning"},
            "properties": {
                "dllName": dll_name,
                "architecture": architecture_label,
                "success": response.success,
            },
        }
        if response.dll_file and response.dll_file.file_path:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": response.dll_file.file_path}
                    }
                }
            ]
        return result

    def _build_log(
        self,
        results: list[dict[str, Any]],
        properties: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "$schema": (
                "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
                "cs01/schemas/sarif-schema-2.1.0.json"
            ),
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "dll_downloader",
                            "informationUri": "https://github.com/seifreed/DLL-Downloader",
                            "rules": [
                                {
                                    "id": self._DOWNLOAD_FAILED_RULE,
                                    "name": "download-failed",
                                },
                                {
                                    "id": self._DOWNLOAD_SUCCEEDED_RULE,
                                    "name": "download-succeeded",
                                },
                                {
                                    "id": self._DOWNLOAD_CACHED_RULE,
                                    "name": "download-cached",
                                },
                                {
                                    "id": self._SECURITY_WARNING_RULE,
                                    "name": "security-warning",
                                },
                                {
                                    "id": self._BOUNDARY_FAILURE_RULE,
                                    "name": "boundary-failure",
                                },
                            ],
                        }
                    },
                    "results": results,
                    "properties": properties,
                }
            ],
        }
