# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for domain entities.

This module tests the domain layer entities including DLLFile, Architecture,
and SecurityStatus enums. Tests validate entity creation, validation,
properties, and business logic.
"""

from dataclasses import replace
from datetime import datetime

import pytest

from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
)

# ============================================================================
# Architecture Enum Tests
# ============================================================================

@pytest.mark.unit
def test_architecture_enum_values() -> None:
    """
    Test that Architecture enum has correct values.

    Purpose:
        Verify all expected CPU architectures are defined with correct values.

    Expected Behavior:
        Each architecture constant has the expected string value.
    """
    assert Architecture.X86.value == "x86"
    assert Architecture.X64.value == "x64"
    assert Architecture.ARM.value == "arm"
    assert Architecture.ARM64.value == "arm64"
    assert Architecture.UNKNOWN.value == "unknown"


@pytest.mark.unit
def test_architecture_enum_comparison() -> None:
    """
    Test that Architecture enum values can be compared.

    Purpose:
        Verify enum identity and equality semantics.

    Expected Behavior:
        Same architecture constants are equal, different ones are not.
    """
    assert Architecture.X64 == Architecture.X64
    assert Architecture.X86 != Architecture.X64
    assert Architecture.ARM != Architecture.ARM64


# ============================================================================
# SecurityStatus Enum Tests
# ============================================================================

@pytest.mark.unit
def test_security_status_enum_values() -> None:
    """
    Test that SecurityStatus enum has correct values.

    Purpose:
        Verify all security status states are defined with correct values.

    Expected Behavior:
        Each status constant has the expected string value.
    """
    assert SecurityStatus.NOT_SCANNED.value == "not_scanned"
    assert SecurityStatus.CLEAN.value == "clean"
    assert SecurityStatus.SUSPICIOUS.value == "suspicious"
    assert SecurityStatus.MALICIOUS.value == "malicious"
    assert SecurityStatus.UNKNOWN.value == "unknown"


@pytest.mark.unit
def test_security_status_enum_comparison() -> None:
    """
    Test that SecurityStatus enum values can be compared.

    Purpose:
        Verify enum identity and equality semantics.

    Expected Behavior:
        Same status constants are equal, different ones are not.
    """
    assert SecurityStatus.CLEAN == SecurityStatus.CLEAN
    assert SecurityStatus.CLEAN != SecurityStatus.MALICIOUS
    assert SecurityStatus.SUSPICIOUS != SecurityStatus.UNKNOWN


# ============================================================================
# DLLFile Entity Creation Tests
# ============================================================================

@pytest.mark.unit
def test_dll_file_creation_minimal() -> None:
    """
    Test creating DLLFile with minimal required fields.

    Purpose:
        Verify that DLLFile can be created with just a name.

    Expected Behavior:
        - Entity is created successfully
        - Name is set correctly
        - Optional fields have appropriate defaults
    """
    dll = DLLFile(name="kernel32.dll")

    assert dll.name == "kernel32.dll"
    assert dll.architecture == Architecture.UNKNOWN
    assert dll.security_status == SecurityStatus.NOT_SCANNED
    assert dll.file_hash is None
    assert dll.file_path is None


@pytest.mark.unit
def test_dll_file_creation_with_all_fields() -> None:
    """
    Test creating DLLFile with all fields populated.

    Purpose:
        Verify that DLLFile correctly stores all provided attributes.

    Expected Behavior:
        All provided fields are correctly stored in the entity.
    """
    scan_date = datetime.now()
    dll = DLLFile(
        name="msvcp140.dll",
        version="14.0.24215.1",
        architecture=Architecture.X64,
        file_hash="abc123def456",
        file_path="/path/to/msvcp140.dll",
        download_url="https://example.com/msvcp140.dll",
        file_size=642304,
        security_status=SecurityStatus.CLEAN,
        vt_detection_ratio="0/72",
        vt_scan_date=scan_date
    )

    assert dll.name == "msvcp140.dll"
    assert dll.version == "14.0.24215.1"
    assert dll.architecture == Architecture.X64
    assert dll.file_hash == "abc123def456"
    assert dll.file_path == "/path/to/msvcp140.dll"
    assert dll.download_url == "https://example.com/msvcp140.dll"
    assert dll.file_size == 642304
    assert dll.security_status == SecurityStatus.CLEAN
    assert dll.vt_detection_ratio == "0/72"
    assert dll.vt_scan_date == scan_date


@pytest.mark.unit
def test_dll_file_creation_sets_timestamp() -> None:
    """
    Test that DLLFile automatically sets created_at timestamp.

    Purpose:
        Verify automatic timestamp generation on entity creation.

    Expected Behavior:
        created_at is set to a datetime close to now.
    """
    before = datetime.now()
    dll = DLLFile(name="test.dll")
    after = datetime.now()

    assert before <= dll.created_at <= after


# ============================================================================
# DLLFile Validation Tests
# ============================================================================

@pytest.mark.unit
def test_dll_file_validation_empty_name_raises_error() -> None:
    """
    Test that DLLFile raises ValueError for empty name.

    Purpose:
        Verify that entity validation prevents creation with invalid data.

    Expected Behavior:
        ValueError is raised when name is empty string.
    """
    with pytest.raises(ValueError, match="DLL name cannot be empty"):
        DLLFile(name="")


@pytest.mark.unit
def test_dll_file_auto_adds_extension() -> None:
    """
    Test that DLLFile automatically adds .dll extension if missing.

    Purpose:
        Verify automatic normalization of DLL names.

    Expected Behavior:
        Name without .dll extension gets it appended automatically.
    """
    dll = DLLFile(name="kernel32")

    assert dll.name == "kernel32.dll"


@pytest.mark.unit
def test_dll_file_preserves_extension_if_present() -> None:
    """
    Test that DLLFile preserves .dll extension if already present.

    Purpose:
        Verify that extension normalization doesn't create duplicates.

    Expected Behavior:
        Name with .dll extension is not modified.
    """
    dll = DLLFile(name="kernel32.dll")

    assert dll.name == "kernel32.dll"
    assert dll.name != "kernel32.dll.dll"


@pytest.mark.unit
def test_dll_file_extension_case_insensitive() -> None:
    """
    Test that DLLFile handles extension in case-insensitive manner.

    Purpose:
        Verify that .DLL, .dll, .Dll are all recognized as valid extensions.

    Expected Behavior:
        Various cases of .dll extension are recognized without adding another.
    """
    dll1 = DLLFile(name="test.DLL")
    dll2 = DLLFile(name="test.Dll")

    # Original case should be preserved, no duplicate extension added
    assert dll1.name == "test.DLL"
    assert dll2.name == "test.Dll"


# ============================================================================
# DLLFile Property Tests
# ============================================================================

@pytest.mark.unit
def test_dll_file_is_scanned_property() -> None:
    """
    Test the is_scanned property.

    Purpose:
        Verify that is_scanned correctly indicates scanning status.

    Expected Behavior:
        - Returns False when status is NOT_SCANNED
        - Returns True for any other security status
    """
    dll_not_scanned = DLLFile(
        name="test.dll",
        security_status=SecurityStatus.NOT_SCANNED
    )
    dll_clean = DLLFile(
        name="test.dll",
        security_status=SecurityStatus.CLEAN
    )
    dll_malicious = DLLFile(
        name="test.dll",
        security_status=SecurityStatus.MALICIOUS
    )

    assert dll_not_scanned.is_scanned is False
    assert dll_clean.is_scanned is True
    assert dll_malicious.is_scanned is True


@pytest.mark.unit
def test_dll_file_is_safe_property() -> None:
    """
    Test the is_safe property.

    Purpose:
        Verify that is_safe correctly indicates file safety.

    Expected Behavior:
        - Returns True only when status is CLEAN
        - Returns False for all other statuses
    """
    dll_clean = DLLFile(
        name="test.dll",
        security_status=SecurityStatus.CLEAN
    )
    dll_suspicious = DLLFile(
        name="test.dll",
        security_status=SecurityStatus.SUSPICIOUS
    )
    dll_malicious = DLLFile(
        name="test.dll",
        security_status=SecurityStatus.MALICIOUS
    )
    dll_not_scanned = DLLFile(
        name="test.dll",
        security_status=SecurityStatus.NOT_SCANNED
    )

    assert dll_clean.is_safe is True
    assert dll_suspicious.is_safe is False
    assert dll_malicious.is_safe is False
    assert dll_not_scanned.is_safe is False


@pytest.mark.unit
def test_dll_file_display_name_without_version() -> None:
    """
    Test display_name property without version.

    Purpose:
        Verify display name formatting when no version is available.

    Expected Behavior:
        Returns just the filename when version is None.
    """
    dll = DLLFile(name="kernel32.dll")

    assert dll.display_name == "kernel32.dll"


@pytest.mark.unit
def test_dll_file_display_name_with_version() -> None:
    """
    Test display_name property with version.

    Purpose:
        Verify display name formatting includes version when available.

    Expected Behavior:
        Returns filename with version in parentheses.
    """
    dll = DLLFile(
        name="msvcp140.dll",
        version="14.0.24215.1"
    )

    assert dll.display_name == "msvcp140.dll (v14.0.24215.1)"


# ============================================================================
# DLLFile Business Logic Tests
# ============================================================================

@pytest.mark.unit
def test_dll_file_immutability_of_created_at() -> None:
    """
    Test that created_at timestamp remains constant.

    Purpose:
        Verify that the creation timestamp doesn't change after initialization.

    Expected Behavior:
        created_at value remains the same across multiple accesses.
    """
    dll = DLLFile(name="test.dll")
    original_timestamp = dll.created_at

    # Access multiple times with delay
    import time
    time.sleep(0.01)

    assert dll.created_at == original_timestamp


@pytest.mark.unit
def test_dll_file_immutability_with_replace() -> None:
    """
    Test that DLLFile is immutable and updates require replace().

    Purpose:
        Verify that DLLFile is frozen and updates create new instances.

    Expected Behavior:
        Using replace() creates a new instance with updated fields,
        original instance remains unchanged.
    """
    dll = DLLFile(
        name="test.dll",
        security_status=SecurityStatus.NOT_SCANNED
    )

    # Use replace to create updated copy (since DLLFile is frozen)
    scanned_dll = replace(
        dll,
        security_status=SecurityStatus.CLEAN,
        vt_detection_ratio="0/72",
        vt_scan_date=datetime.now()
    )

    # Original is unchanged
    assert dll.security_status == SecurityStatus.NOT_SCANNED
    assert dll.vt_detection_ratio is None

    # New instance has updated values
    assert scanned_dll.is_scanned is True
    assert scanned_dll.is_safe is True
    assert scanned_dll.vt_detection_ratio == "0/72"


@pytest.mark.unit
def test_dll_file_multiple_architectures() -> None:
    """
    Test creating DLLFile entities with different architectures.

    Purpose:
        Verify that architecture field correctly distinguishes between platforms.

    Expected Behavior:
        Different architecture values are properly stored and distinguishable.
    """
    dll_x86 = DLLFile(name="lib.dll", architecture=Architecture.X86)
    dll_x64 = DLLFile(name="lib.dll", architecture=Architecture.X64)
    dll_arm = DLLFile(name="lib.dll", architecture=Architecture.ARM)

    assert dll_x86.architecture == Architecture.X86
    assert dll_x64.architecture == Architecture.X64
    assert dll_arm.architecture == Architecture.ARM


@pytest.mark.unit
def test_dll_file_size_validation() -> None:
    """
    Test that file_size field accepts valid values.

    Purpose:
        Verify that file size is stored correctly for various realistic sizes.

    Expected Behavior:
        File sizes from small to large are correctly stored.
    """
    dll_small = DLLFile(name="small.dll", file_size=1024)  # 1 KB
    dll_medium = DLLFile(name="medium.dll", file_size=1048576)  # 1 MB
    dll_large = DLLFile(name="large.dll", file_size=104857600)  # 100 MB

    assert dll_small.file_size == 1024
    assert dll_medium.file_size == 1048576
    assert dll_large.file_size == 104857600


@pytest.mark.unit
def test_dll_file_hash_format() -> None:
    """
    Test that file_hash field accepts SHA-256 format hashes.

    Purpose:
        Verify that hash values are stored correctly.

    Expected Behavior:
        64-character hexadecimal hashes are properly stored.
    """
    test_hash = "a" * 64  # Simulated SHA-256 hash
    dll = DLLFile(name="test.dll", file_hash=test_hash)

    assert dll.file_hash == test_hash
    assert len(dll.file_hash) == 64


@pytest.mark.unit
def test_dll_file_equality_different_instances() -> None:
    """
    Test that DLLFile instances are distinct objects.

    Purpose:
        Verify that each DLLFile instance is independent.

    Expected Behavior:
        Two DLLFile instances with same data are not the same object.
    """
    dll1 = DLLFile(name="test.dll")
    dll2 = DLLFile(name="test.dll")

    # They are different objects
    assert dll1 is not dll2

    # But have same name
    assert dll1.name == dll2.name
