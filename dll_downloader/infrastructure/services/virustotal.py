"""
VirusTotal Scanner Implementation

Implements the ISecurityScanner interface using the VirusTotal API
for malware analysis and threat detection.
"""

import contextlib
import errno
import json
import logging
import os
import stat
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from ...domain.entities.dll_file import DLLFile, SecurityStatus
from ...domain.errors import SecurityServiceError
from ...domain.services import calculate_sha256
from ...domain.services.security_scanner import ISecurityScanner, ScanResult
from ..http.transport import header_value as _header_value
from ..http_session import (
    HTTPResponseProtocol,
    HTTPSessionProtocol,
    HTTPSessionResource,
)
from ..net import hostname_resolves_to_private_ip, strip_url_credentials
from ..validation import is_finite_number, is_hex_digest, validate_positive_timeout

logger = logging.getLogger(__name__)
_API_KEY_MISSING = "VirusTotal API key not configured"
_VT_UPLOAD_MAX_BYTES = 32 * 1024 * 1024  # 32 MiB
_VT_RESPONSE_MAX_BYTES = 64 * 1024 * 1024  # 64 MiB
_READ_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)


def _is_valid_hash(value: str) -> bool:
    """Return True when value is a hex hash with valid length for VirusTotal lookups."""
    return is_hex_digest(value, (32, 40, 64))  # MD5, SHA-1, SHA-256


def _validate_detection_thresholds(
    malicious_threshold: int,
    suspicious_threshold: int,
) -> None:
    """Reject thresholds that would invert or collapse VT status semantics."""
    if (
        isinstance(malicious_threshold, bool)
        or not isinstance(malicious_threshold, int)
        or malicious_threshold <= 0
    ):
        raise ValueError("malicious_threshold must be a positive integer")
    if (
        isinstance(suspicious_threshold, bool)
        or not isinstance(suspicious_threshold, int)
        or suspicious_threshold <= 0
    ):
        raise ValueError("suspicious_threshold must be a positive integer")
    if suspicious_threshold >= malicious_threshold:
        raise ValueError("suspicious_threshold must be less than malicious_threshold")


class VirusTotalError(SecurityServiceError):
    """Exception raised for VirusTotal API errors."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class HashNotFoundError(VirusTotalError):
    """Exception raised when a hash has no VirusTotal results."""

    pass


def _safe_int(value: object, *, strict: bool = False) -> int:  # noqa: C901
    """Safely coerce API values to int, handling float-like strings.

    When *strict* is True (used for security-critical fields like
    ``malicious`` and ``suspicious`` counts), unparseable or negative
    values raise :class:`VirusTotalError` instead of defaulting to 0,
    ensuring the scanner fails closed rather than classifying a file as clean
    on malformed data.

    Unexpected types (None, list, dict, etc.) always raise VirusTotalError
    regardless of the strict flag, since defaulting to 0 would understate
    threat severity.
    """
    if isinstance(value, bool):
        raise VirusTotalError(f"VT API returned boolean for integer field: {value!r}")
    if isinstance(value, int):
        if value < 0:
            if strict:
                raise VirusTotalError(f"VT API returned negative count: {value}")
            logger.warning("VT API returned negative count: %r, defaulting to 0", value)
            return 0
        return value
    if isinstance(value, float):
        if not is_finite_number(value):
            raise VirusTotalError(f"VT API returned non-finite float: {value!r}")
        if not value.is_integer():
            if strict:
                raise VirusTotalError(f"VT API returned non-integer count: {value!r}")
            logger.warning(
                "VT API returned non-integer count: %r, defaulting to 0", value
            )
            return 0
        result = int(value)
        if result < 0:
            if strict:
                raise VirusTotalError(f"VT API returned negative count: {result}")
            logger.warning("VT API returned negative count: %r, defaulting to 0", value)
            return 0
        return result
    if isinstance(value, str):
        try:
            parsed = float(value)
        except ValueError as exc:
            if strict:
                raise VirusTotalError(
                    f"VT API returned unparseable integer value: {value!r}"
                ) from exc
            logger.warning(
                "VT API returned unparseable integer value: %r, defaulting to 0", value
            )
            return 0
        if not is_finite_number(parsed):
            if strict:
                raise VirusTotalError(f"VT API returned non-finite count: {value!r}")
            logger.warning(
                "VT API returned non-finite count: %r, defaulting to 0", value
            )
            return 0
        if not parsed.is_integer():
            if strict:
                raise VirusTotalError(f"VT API returned non-integer count: {value!r}")
            logger.warning(
                "VT API returned non-integer count: %r, defaulting to 0", value
            )
            return 0
        result = int(parsed)
        if result < 0:
            if strict:
                raise VirusTotalError(f"VT API returned negative count: {result}")
            logger.warning(
                "VT API returned negative count: %r, defaulting to 0",
                value,
            )
            return 0
        return result
    if value is None:
        raise VirusTotalError("VT API returned null for integer field")
    if isinstance(value, (dict, list)):
        raise VirusTotalError(
            f"VT API returned unexpected type for integer field: {value!r}"
        )
    raise VirusTotalError(
        f"VT API returned unexpected type for integer field: {value!r}"
    )


def _safe_json(response: HTTPResponseProtocol) -> dict[str, object]:
    """Normalize loosely typed HTTP JSON payloads into mappings."""
    payload = _response_json_payload(response)
    if not isinstance(payload, Mapping):
        raise VirusTotalError("VirusTotal response body must be a JSON object")
    return _normalize_json_mapping(payload)


def _response_json_payload(response: HTTPResponseProtocol) -> object:
    content_length = _response_content_length(response)
    if content_length is not None and content_length > _VT_RESPONSE_MAX_BYTES:
        raise VirusTotalError(
            f"VirusTotal response exceeds size limit ({content_length} bytes)"
        )

    body = _bounded_response_body(response)
    if body:
        return _loads_response_body(body)
    return _json_payload_from_method(response)


def _response_content_length(response: HTTPResponseProtocol) -> int | None:
    content_length: int | None = None
    raw_headers = getattr(response, "headers", {})
    if not isinstance(raw_headers, Mapping):
        return content_length
    cl_header = _header_value(raw_headers, "content-length")
    if cl_header:
        with contextlib.suppress(ValueError, TypeError):
            content_length = int(cl_header)
    return content_length


def _bounded_response_body(response: HTTPResponseProtocol) -> bytes | None:
    chunks = _response_chunks(response)
    if chunks is None:
        raw_content = getattr(response, "content", None)
        if not isinstance(raw_content, bytes):
            return None
        chunks = [raw_content]
    body = b"".join(chunks)
    if len(body) > _VT_RESPONSE_MAX_BYTES:
        raise VirusTotalError(
            f"VirusTotal response exceeds size limit ({_VT_RESPONSE_MAX_BYTES} bytes)"
        )
    return body


def _response_chunks(response: HTTPResponseProtocol) -> list[bytes] | None:
    iter_content = getattr(response, "iter_content", None)
    if not callable(iter_content):
        return None
    chunks: list[bytes] = []
    total_bytes = 0
    for chunk in iter_content(chunk_size=65536):
        if not chunk:
            continue
        total_bytes += len(chunk)
        if total_bytes > _VT_RESPONSE_MAX_BYTES:
            raise VirusTotalError(
                f"VirusTotal response exceeds size limit ({_VT_RESPONSE_MAX_BYTES} bytes)"
            )
        chunks.append(chunk)
    return chunks


def _loads_response_body(body: bytes) -> object:
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError, TypeError, RecursionError) as exc:
        raise VirusTotalError(f"Invalid JSON in VirusTotal response: {exc}") from exc


def _json_payload_from_method(response: HTTPResponseProtocol) -> object:
    try:
        payload = response.json()
    except (ValueError, UnicodeDecodeError, TypeError, RecursionError) as exc:
        raise VirusTotalError(f"Invalid JSON in VirusTotal response: {exc}") from exc
    serialized_size = len(json.dumps(payload, default=str))
    if serialized_size > _VT_RESPONSE_MAX_BYTES:
        raise VirusTotalError(
            f"VirusTotal response exceeds size limit ({serialized_size} bytes)"
        )
    return payload


def _normalize_json_mapping(payload: Mapping[object, object]) -> dict[str, object]:
    normalized: dict[str, object] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            raise VirusTotalError("VirusTotal response keys must be strings")
        normalized[key] = value
    return normalized


def _data_section(payload: Mapping[str, object]) -> dict[str, object]:
    data = payload.get("data", {})
    if not isinstance(data, Mapping):
        return {}

    normalized: dict[str, object] = {}
    for key, value in data.items():
        if isinstance(key, str):
            normalized[key] = value
        else:
            logger.warning("VT API response data section has non-string key: %r", key)
    return normalized


class VirusTotalScanner(ISecurityScanner):
    """
    Security scanner implementation using VirusTotal API.

    This implementation connects to the VirusTotal API to:
    - Look up files by hash to check existing scan results
    - Submit new files for scanning
    - Retrieve detailed analysis reports

    The scanner supports both API v2 and v3, with v3 being preferred.

    Architecture Notes:
        Uses a composed HTTPSessionResource for API communication and cleanup.
        That keeps the technical session lifecycle reusable without coupling
        scanner behavior to a shared infrastructure base class.

    Example:
        >>> scanner = VirusTotalScanner(api_key="your-api-key")
        >>> if scanner.is_available:
        ...     result = scanner.scan_hash("abc123...")
        ...     print(f"Detection ratio: {result.detection_ratio}")

    Attributes:
        MALICIOUS_THRESHOLD: Number of detections to consider malicious (default: 5)
        SUSPICIOUS_THRESHOLD: Number of detections to consider suspicious (default: 1)
    """

    VT_API_URL = "https://www.virustotal.com/api/v3"
    _VT_ALLOWED_DOMAINS = {"www.virustotal.com", "virustotal.com"}
    _VT_PRIVATE_IP_ALLOWED_DOMAINS: set[str] = set()
    MALICIOUS_THRESHOLD = 5
    SUSPICIOUS_THRESHOLD = 1
    _MAX_REDIRECT_HOPS = 5
    _MAX_LOCATION_HEADER_LENGTH = 8192

    def __init__(
        self,
        api_key: str | None = None,
        malicious_threshold: int = 5,
        suspicious_threshold: int = 1,
        timeout: float = 60.0,
        session_resource: HTTPSessionResource | None = None,
    ) -> None:
        """
        Initialize the VirusTotal scanner.

        Args:
            api_key: VirusTotal API key. If not provided, scanner will be unavailable.
            malicious_threshold: Number of positive detections to mark as malicious
            suspicious_threshold: Number of positive detections to mark as suspicious
            timeout: Timeout in seconds for VirusTotal API requests
        """
        _validate_detection_thresholds(malicious_threshold, suspicious_threshold)
        if api_key is not None and not isinstance(api_key, str):
            raise ValueError("api_key must be a string or None")
        self._api_key = api_key.strip() if api_key else None
        self._malicious_threshold = malicious_threshold
        self._suspicious_threshold = suspicious_threshold
        self._timeout = validate_positive_timeout(timeout)
        session_headers: dict[str, str] = {}
        if self._api_key:
            session_headers = {"x-apikey": self._api_key, "Accept": "application/json"}
        self._session_resource = session_resource or HTTPSessionResource(
            headers=session_headers
        )

    @property
    def session(self) -> HTTPSessionProtocol:
        return self._session_resource.session

    @property
    def has_active_session(self) -> bool:
        """Report whether this scanner currently owns a live session instance."""
        return self._session_resource.has_session

    def close(self) -> None:
        self._session_resource.close()

    @staticmethod
    def _hostname_is_allowed(hostname: str) -> bool:
        """Return True when *hostname* belongs to an allowlisted domain."""
        return hostname.lower() in VirusTotalScanner._VT_ALLOWED_DOMAINS

    @staticmethod
    def _hostname_private_ip_is_allowed(hostname: str) -> bool:
        """Return True for explicit local-test/private endpoint overrides."""
        return hostname.lower() in VirusTotalScanner._VT_PRIVATE_IP_ALLOWED_DOMAINS

    def _safe_get(
        self, url: str, **kwargs: object
    ) -> HTTPResponseProtocol:  # noqa: C901
        """Issue a GET request with SSRF and redirect validation."""
        kwargs["allow_redirects"] = False
        kwargs.setdefault("timeout", self._timeout)
        current_url = url
        for _hop in range(self._MAX_REDIRECT_HOPS):
            self._validate_api_url(current_url, redirect=False)
            response = self.session.get(current_url, **kwargs)
            if not response.is_redirect:
                return response
            location = _header_value(dict(response.headers), "location") or ""
            self._close_response(response)
            if not location:
                raise VirusTotalError(
                    f"Redirect response missing Location header for {current_url}"
                )
            if len(location) > self._MAX_LOCATION_HEADER_LENGTH:
                raise VirusTotalError(
                    f"Redirect Location header exceeds {self._MAX_LOCATION_HEADER_LENGTH} bytes"
                )
            current_url = self._resolve_redirect_url(current_url, location)
        raise VirusTotalError(f"Too many redirects (> {self._MAX_REDIRECT_HOPS})")

    def _safe_post(
        self, url: str, **kwargs: object
    ) -> HTTPResponseProtocol:  # noqa: C901
        """Issue a POST request with SSRF validation (no redirects for POST)."""
        kwargs["allow_redirects"] = False
        kwargs.setdefault("timeout", self._timeout)
        self._validate_api_url(url, redirect=False)
        response = self.session.post(url, **kwargs)
        # Follow redirects manually for POST requests to validate each hop.
        current_url = url
        hops = 0
        while response.is_redirect and hops < self._MAX_REDIRECT_HOPS:
            location = _header_value(dict(response.headers), "location") or ""
            self._close_response(response)
            if not location:
                raise VirusTotalError(
                    f"Redirect response missing Location header for {current_url}"
                )
            if len(location) > self._MAX_LOCATION_HEADER_LENGTH:
                raise VirusTotalError(
                    f"Redirect Location header exceeds {self._MAX_LOCATION_HEADER_LENGTH} bytes"
                )
            location = location.strip()
            current_url = self._resolve_redirect_url(current_url, location)
            self._validate_api_url(current_url, redirect=True)
            if response.status_code in (307, 308):
                response = self.session.post(
                    current_url,
                    allow_redirects=False,
                    timeout=self._timeout,
                    **{
                        k: v
                        for k, v in kwargs.items()
                        if k not in ("allow_redirects", "timeout")
                    },
                )
            else:
                response = self.session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=self._timeout,
                )
            hops += 1
        if response.is_redirect:
            self._close_response(response)
            raise VirusTotalError(f"Too many redirects (> {self._MAX_REDIRECT_HOPS})")
        return response

    def _validate_api_url(self, url: str, *, redirect: bool) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise VirusTotalError(f"Request to non-HTTP scheme rejected: {url}")
        hostname = parsed.hostname
        if hostname is None:
            raise VirusTotalError("Request to URL without hostname rejected")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise VirusTotalError(f"Request URL has invalid port: {url}") from exc
        if parsed.username is not None or parsed.password is not None:
            raise VirusTotalError("Request URL credentials rejected")
        if not self._hostname_is_allowed(hostname):
            prefix = "Redirect" if redirect else "Request"
            raise VirusTotalError(
                f"{prefix} to disallowed or private-address hostname rejected: {hostname}"
            )
        if hostname_resolves_to_private_ip(
            hostname
        ) and not self._hostname_private_ip_is_allowed(hostname):
            prefix = "Redirect" if redirect else "Request"
            raise VirusTotalError(
                f"{prefix} to hostname resolving to private IP rejected: {hostname}"
            )

    @staticmethod
    def _resolve_redirect_url(current_url: str, location: str) -> str:
        location = location.strip()
        location_lower = location.lower()
        if not location_lower.startswith(("http://", "https://")):
            resolved_url = urljoin(current_url, location)
        else:
            resolved_url = location
        if current_url.lower().startswith(
            "https://"
        ) and resolved_url.lower().startswith("http://"):
            raise VirusTotalError(f"HTTPS to HTTP redirect rejected: {resolved_url}")
        return VirusTotalScanner._strip_url_credentials(resolved_url)

    @staticmethod
    def _strip_url_credentials(location: str) -> str:
        try:
            return strip_url_credentials(location)
        except ValueError as exc:
            raise VirusTotalError(str(exc)) from exc

    def __enter__(self) -> "VirusTotalScanner":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        self.close()

    @property
    def is_available(self) -> bool:
        """
        Check if the scanner is available and properly configured.

        Returns:
            True if API key is set and valid
        """
        return bool(self._api_key and self._api_key.strip())

    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a file by uploading it to VirusTotal.

        Args:
            file_path: Path to the file to scan

        Returns:
            ScanResult with analysis results

        Raises:
            VirusTotalError: If the scan fails
        """
        if not self.is_available:
            computed_hash = self._hash_file_when_unavailable(file_path)
            return ScanResult(
                file_hash=computed_hash,
                status=SecurityStatus.UNKNOWN,
                error_message=_API_KEY_MISSING,
            )

        content = self._read_upload_content(file_path)
        file_hash = calculate_sha256(content)
        upload_content = content

        try:
            return self.scan_hash(file_hash)
        except HashNotFoundError:
            pass
        except VirusTotalError as exc:
            # Re-raise non-retryable errors (auth failures, forbidden, etc.)
            # and transient errors (rate limits, server errors) rather than
            # silently falling through to a second doomed request.
            error_message = str(exc).lower()
            if any(
                indicator in error_message
                for indicator in ("unauthorized", "forbidden", "rate limit")
            ):
                raise
            status_code = getattr(exc, "status_code", None)
            if status_code is not None:
                raise
            logger.info(
                "Hash lookup failed for %s, proceeding with upload: %s", file_hash, exc
            )

        response: HTTPResponseProtocol | None = None
        try:
            filename = Path(file_path).name
            files = {"file": (filename, upload_content)}
            response = self._safe_post(
                f"{self.VT_API_URL}/files",
                files=files,
            )

            if response.status_code != 200:
                raise VirusTotalError(
                    f"Upload failed: {response.status_code}",
                    status_code=response.status_code,
                )

            logger.info(
                "File submitted for analysis: %s",
                _data_section(_safe_json(response)).get("id"),
            )
            return ScanResult(
                file_hash=file_hash,
                status=SecurityStatus.UNKNOWN,
                error_message="File submitted for analysis. Results pending.",
            )

        except (
            OSError,
            requests.RequestException,
            RuntimeError,
        ) as e:
            logger.error("Failed to upload file to VirusTotal: %s", e)
            raise VirusTotalError(f"File upload failed: {e}") from e
        finally:
            if response is not None:
                self._close_response(response)

    def _hash_file_when_unavailable(self, file_path: str) -> str | None:
        try:
            return calculate_sha256(self._read_regular_file_content(file_path))
        except VirusTotalError:
            return None

    def _read_upload_content(self, file_path: str) -> bytes:
        content = self._read_regular_file_content(file_path)
        if len(content) > _VT_UPLOAD_MAX_BYTES:
            raise VirusTotalError(
                f"File exceeds {_VT_UPLOAD_MAX_BYTES // (1024 * 1024)} MiB upload limit"
            )
        return content

    def _read_regular_file_content(self, file_path: str) -> bytes:
        path = Path(file_path)
        fd = -1
        try:
            fd = os.open(str(path), _READ_FILE_FLAGS)
        except FileNotFoundError:
            raise VirusTotalError("File upload failed: path does not exist") from None
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise VirusTotalError("File upload failed: path is a symlink") from e
            raise VirusTotalError(f"File upload failed: {e}") from e

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                os.close(fd)
                fd = -1
                raise VirusTotalError("File upload failed: path is not a regular file")
            file_size = st.st_size
            if file_size > _VT_UPLOAD_MAX_BYTES:
                raise VirusTotalError(
                    f"File exceeds {_VT_UPLOAD_MAX_BYTES // (1024 * 1024)} MiB upload limit"
                )
            # Clear O_NONBLOCK for regular files so read() works normally.
            os.set_blocking(fd, True)
            with os.fdopen(fd, "rb") as f:
                fd = -1
                content = f.read()
        except VirusTotalError:
            raise
        except OSError as e:
            raise VirusTotalError(f"File upload failed: {e}") from e
        finally:
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)
        return content

    def scan_hash(self, file_hash: str) -> ScanResult:
        """
        Look up scan results by file hash.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            ScanResult with cached analysis results

        Raises:
            HashNotFoundError: If no results exist for this hash
            VirusTotalError: If the lookup fails
        """
        if not self.is_available:
            return ScanResult(
                file_hash=file_hash,
                status=SecurityStatus.UNKNOWN,
                error_message=_API_KEY_MISSING,
            )

        if not _is_valid_hash(file_hash):
            raise VirusTotalError(f"Invalid file hash: {file_hash!r}")

        file_hash = file_hash.lower()

        response: HTTPResponseProtocol | None = None
        try:
            response = self._safe_get(
                f"{self.VT_API_URL}/files/{file_hash}",
            )
            if response.status_code == 404:
                raise HashNotFoundError(f"No results found for hash: {file_hash}")
            if response.status_code != 200:
                raise VirusTotalError(
                    f"API request failed with status {response.status_code}",
                    status_code=response.status_code,
                )
            return self._parse_response(file_hash, _safe_json(response))
        except HashNotFoundError:
            raise
        except (requests.RequestException, RuntimeError) as e:
            logger.error("Failed to query VirusTotal: %s", e)
            raise VirusTotalError(f"Hash lookup failed: {e}") from e
        finally:
            if response is not None:
                self._close_response(response)

    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        """
        Scan a DLL entity and update its security status.

        Args:
            dll_file: The DLL entity to scan

        Returns:
            Updated DLLFile with security information
        """
        if not dll_file.file_hash:
            raise VirusTotalError(f"Cannot scan DLL without file hash: {dll_file.name}")

        try:
            result = self.scan_hash(dll_file.file_hash)

            # Create updated DLL with scan results
            return replace(
                dll_file,
                security_status=result.status,
                vt_detection_ratio=result.detection_ratio,
                vt_scan_date=result.scan_date,
            )

        except HashNotFoundError:
            logger.info(
                "No VT results for %s, file not previously scanned", dll_file.name
            )
            return replace(
                dll_file,
                security_status=SecurityStatus.UNKNOWN,
                vt_detection_ratio=None,
            )

        except VirusTotalError as e:
            logger.error("VT scan failed for %s: %s", dll_file.name, e)
            raise

    def get_detailed_report(self, file_hash: str) -> dict[str, object]:
        """
        Get a detailed scan report for a file.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            Full API response as dictionary

        Raises:
            VirusTotalError: If the report retrieval fails
        """
        if not self.is_available:
            raise VirusTotalError(_API_KEY_MISSING)

        if not _is_valid_hash(file_hash):
            raise VirusTotalError(f"Invalid file hash: {file_hash!r}")

        file_hash = file_hash.lower()

        response: HTTPResponseProtocol | None = None
        try:
            url = f"{self.VT_API_URL}/files/{file_hash}"
            response = self._safe_get(url)

            if response.status_code == 404:
                raise HashNotFoundError(f"No report found for hash: {file_hash}")
            if response.status_code != 200:
                raise VirusTotalError(
                    f"Failed to get report: {response.status_code}",
                    status_code=response.status_code,
                )

            return dict(_safe_json(response))

        except (requests.RequestException, RuntimeError) as e:
            logger.error("Failed to get detailed report: %s", e)
            raise VirusTotalError(f"Report retrieval failed: {e}") from e
        finally:
            if response is not None:
                self._close_response(response)

    @staticmethod
    def _close_response(response: HTTPResponseProtocol) -> None:
        close_response = getattr(response, "close", None)
        if not callable(close_response):
            return
        try:
            close_response()
        except (OSError, requests.RequestException) as exc:
            logger.warning("Failed to close VirusTotal response: %s", exc)

    def _determine_security_status(
        self, total_positives: int, total: int
    ) -> SecurityStatus:
        """
        Determine the security status based on detection thresholds.

        Args:
            total_positives: Combined count of malicious and suspicious detections
            total: Total number of engines that analyzed the file

        Returns:
            SecurityStatus based on threshold comparison
        """
        if total_positives >= self._malicious_threshold:
            return SecurityStatus.MALICIOUS
        if total_positives >= self._suspicious_threshold:
            return SecurityStatus.SUSPICIOUS
        return SecurityStatus.CLEAN if total > 0 else SecurityStatus.UNKNOWN

    def _extract_engine_detections(
        self,
        data: Mapping[str, object],
    ) -> dict[str, str]:
        """
        Extract individual engine detection results from API response.

        Args:
            data: Raw API response data

        Returns:
            Dictionary mapping engine names to their detection verdicts
        """
        attributes = self._extract_attributes(data)
        results = attributes.get("last_analysis_results", {})
        if not isinstance(results, dict):
            return {}
        detections: dict[str, str] = {}
        for engine, result in results.items():
            if not isinstance(engine, str):
                continue
            if not isinstance(result, dict):
                continue
            verdict = result.get("result")
            if isinstance(verdict, str) and verdict:
                detections[engine] = verdict
        return detections

    def _parse_response(
        self,
        file_hash: str,
        data: Mapping[str, object],
    ) -> ScanResult:
        """
        Parse VirusTotal API response into ScanResult.

        Orchestrates the extraction of scan statistics, security status
        determination, and detection details from the API response.

        Args:
            file_hash: The file hash that was queried
            data: Raw API response data

        Returns:
            Parsed ScanResult
        """
        attributes = self._extract_attributes(data)
        stats = attributes.get("last_analysis_stats", {})
        if not isinstance(stats, dict):
            stats = {}

        malicious = _safe_int(stats.get("malicious", 0), strict=True)
        suspicious = _safe_int(stats.get("suspicious", 0), strict=True)
        total = sum(_safe_int(v) for v in stats.values())
        total_positives = malicious + suspicious

        status = self._determine_security_status(total_positives, total)

        detection_ratio = f"{total_positives}/{total}" if total > 0 else None

        scan_timestamp = attributes.get("last_analysis_date")
        scan_date: datetime | None = None
        if isinstance(scan_timestamp, (int, float)) and not isinstance(
            scan_timestamp, bool
        ):
            try:
                scan_date = datetime.fromtimestamp(float(scan_timestamp), tz=UTC)
            except (OverflowError, OSError, ValueError):
                scan_date = None

        detections = self._extract_engine_detections(data)

        return ScanResult(
            file_hash=file_hash,
            status=status,
            detection_ratio=detection_ratio,
            detections=detections,
            scan_date=scan_date,
            permalink=f"https://www.virustotal.com/gui/file/{file_hash}",
        )

    @staticmethod
    def _extract_attributes(data: Mapping[str, object]) -> Mapping[str, object]:
        data_section = data.get("data")
        if isinstance(data_section, dict):
            attributes = data_section.get("attributes")
            if isinstance(attributes, dict):
                return attributes
        return {}
