# DLL-Downloader Test Suite

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.

## Overview

This directory contains a comprehensive unit test suite for the DLL-Downloader project. The test suite follows strict **realistic testing principles** - all tests execute real code without mocks or artificial abstractions.

## Philosophy

Our testing approach is based on these core principles:

1. **No Mocks, No Shortcuts**: Tests execute actual production code paths
2. **Real Data Structures**: Use authentic data, not test doubles
3. **Deterministic Results**: All tests produce repeatable, consistent results
4. **True Behavior Validation**: Tests verify both correctness and side effects
5. **Realistic Scenarios**: Tests represent cases that will genuinely occur

## Test Structure

```
tests/
├── conftest.py           # Shared pytest fixtures and configuration
├── test_entities.py      # Tests for domain entities (21 tests)
├── test_use_cases.py     # Tests for application use cases (10 tests)
└── README.md            # This file
```

## Running Tests

### Run All Tests

```bash
pytest tests/
```

### Run Specific Test Files

```bash
pytest tests/test_entities.py
pytest tests/test_use_cases.py
```

### Run Tests by Marker

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration
```

### Run with Coverage

```bash
pytest tests/ --cov=dll_downloader --cov-report=term-missing --cov-report=html
```

This generates:
- Terminal output with line-by-line coverage
- HTML report in `htmlcov/` directory

### Verbose Output

```bash
pytest tests/ -v
```

### Show Test Duration

```bash
pytest tests/ --durations=10
```

## Test Files

### `conftest.py`

Provides shared fixtures for all tests:

- **tmp_download_dir**: Temporary directory for test files
- **sample_dll_file**: Mock DLL file with PE header structure
- **sample_zip_with_dll**: ZIP archive containing a test DLL
- **mock_config**: Test configuration dictionary
- **config_file**: Temporary configuration file
- **sample_html_file**: HTML file for error detection tests
- **empty_zip_file**: Empty ZIP for error condition tests
- **reset_debug_mode**: Automatic debug mode cleanup between tests

### `test_entities.py` (21 tests)

Tests for domain layer entities:

#### Architecture Enum (2 tests)
- Enum value correctness
- Enum comparison semantics

#### SecurityStatus Enum (2 tests)
- Security status values
- Status comparison semantics

#### DLLFile Entity Creation (3 tests)
- Minimal field creation
- Full field creation
- Automatic timestamp generation

#### DLLFile Validation (4 tests)
- Empty name validation
- Automatic .dll extension addition
- Extension preservation
- Case-insensitive extension handling

#### DLLFile Properties (3 tests)
- `is_scanned` property logic
- `is_safe` property logic
- `display_name` formatting

#### DLLFile Business Logic (7 tests)
- Timestamp immutability
- Security status updates
- Multiple architecture support
- File size validation
- Hash format validation
- Instance independence

### `test_use_cases.py` (10 tests)

Tests for application layer use cases:

#### DownloadDLLUseCase (10 tests)
- Successful download orchestration
- SHA-256 hash calculation
- Cached file retrieval
- Force download bypass
- Security scanning (clean result)
- Security scanning (malicious result)
- Security scanning (suspicious result)
- Scanner unavailability handling
- Download failure handling
- Multi-architecture support

## Test Design

### Lightweight Test Implementations

Instead of mocks, we use **real, lightweight implementations**:

#### `InMemoryRepository`
A fully functional repository that stores DLL files in memory instead of on disk:
- Implements complete IDLLRepository interface
- Provides same guarantees as filesystem repository
- No I/O overhead
- Automatic cleanup

#### `TestHTTPClient`
Deterministic HTTP client without network access:
- Configurable predefined responses
- Simulates download operations
- Failure mode testing
- No external dependencies

#### `TestSecurityScanner`
Realistic security scanner without API calls:
- Configurable scan results
- Availability simulation
- Hash-based result mapping
- No VirusTotal API usage

## Coverage Report

As of the last run:

```
Module                                  Coverage
--------------------------------------------------
dll_downloader/domain/entities/         100%
dll_downloader/application/use_cases/    94%
--------------------------------------------------
Total Unit Test Coverage                 28%*
```

*Total includes infrastructure code not yet covered by unit tests (HTTP client, VirusTotal integration, etc.)

## Test Markers

Tests are categorized with pytest markers:

- `@pytest.mark.unit` - Unit tests (isolated function/method testing)
- `@pytest.mark.integration` - Integration tests (multi-component testing)
- `@pytest.mark.slow` - Tests that take longer to execute
- `@pytest.mark.network` - Tests requiring network access (should be minimal)

## Continuous Integration

These tests are designed to run in CI/CD pipelines:

- No external dependencies (no internet, no databases)
- Fast execution (< 1 second for all 60 tests)
- Deterministic results (no flaky tests)
- Clear failure messages

## Writing New Tests

When adding new tests, follow these guidelines:

### 1. Use Real Implementations

```python
# ✅ GOOD: Use temporary files
def test_file_operation(tmp_download_dir):
    file_path = tmp_download_dir / "test.dll"
    file_path.write_bytes(b"content")
    result = process_file(str(file_path))
    assert result is not None

# ❌ BAD: Use mocks
def test_file_operation_mocked():
    mock_file = Mock()
    mock_file.read.return_value = b"content"
    result = process_file(mock_file)
    assert result is not None
```

### 2. Validate Side Effects

```python
# ✅ GOOD: Check actual file creation
def test_download(tmp_download_dir):
    download_file("test.dll", tmp_download_dir)
    assert (tmp_download_dir / "test.dll").exists()
    assert (tmp_download_dir / "test.dll").stat().st_size > 0

# ❌ BAD: Only check return value
def test_download():
    result = download_file("test.dll", "/tmp")
    assert result is True
```

### 3. Use AAA Pattern

```python
def test_feature():
    # Arrange: Set up test data
    config = {"enabled": True}

    # Act: Execute the function
    result = process_config(config)

    # Assert: Verify results
    assert result.is_valid is True
    assert result.errors == []
```

### 4. Test Error Conditions

```python
def test_invalid_input_raises_error():
    with pytest.raises(ValueError, match="cannot be empty"):
        create_dll_file(name="")
```

## License

All test code is released under the **GNU General Public License v3 (GPLv3)**.

Any derivative work must:
1. Attribute authorship to Marc Rivero López
2. Be distributed under GPLv3
3. Publish modified source code if redistributed

## Contact

Author: Marc Rivero López (@seifreed)
Project: DLL-Downloader
License: GPLv3
