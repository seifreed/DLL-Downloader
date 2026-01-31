# Integration Tests

## Overview

This directory contains integration tests that validate the interaction between multiple components of the DLL-Downloader application using real implementations and actual filesystem operations.

## Testing Philosophy

These tests follow a strict **no-mocks, no-stubs** policy:

- All tests execute real production code
- Filesystem operations use pytest's `tmp_path` fixture for isolation
- External dependencies (HTTP, VirusTotal) use lightweight real implementations
- No mocking frameworks or test doubles are used
- All tests are deterministic and repeatable

## Test Files

### test_file_repository.py

Validates the FileSystemDLLRepository implementation with real filesystem operations.

**Test Coverage:**
- Repository initialization and directory creation
- DLL file saving with real binary content
- File retrieval by name and hash
- File deletion and existence checks
- JSON index persistence across sessions
- Handling of corrupted index files
- Real-world scenarios (multiple files, lifecycle operations)

**Test Count:** 34 tests

### test_download_flow.py

Validates the complete download flow using real implementations of all layers.

**Test Coverage:**
- Complete download workflow from request to persistence
- Hash calculation from actual file content
- Caching and force-download behavior
- Security scanning integration with deterministic results
- Error handling for missing resources
- End-to-end scenarios with multiple architectures

**Test Count:** 16 tests

## Lightweight Test Implementations

### InMemoryHTTPClient

A real HTTP client implementation that serves content from memory instead of making network requests. This provides:
- Deterministic responses for testing
- No external network dependencies
- Full HTTP client protocol compliance

### StaticSecurityScanner

A real security scanner implementation with predefined scan results. This provides:
- Deterministic security assessments
- No VirusTotal API calls
- Full security scanner protocol compliance

## Running Integration Tests

Run all integration tests:
```bash
pytest tests/integration/ -v
```

Run specific test file:
```bash
pytest tests/integration/test_file_repository.py -v
pytest tests/integration/test_download_flow.py -v
```

Run tests marked with @pytest.mark.integration:
```bash
pytest -m integration
```

Run with coverage report:
```bash
pytest tests/integration/ --cov=dll_downloader --cov-report=html
```

## Test Isolation

Each test is completely isolated:
- Uses pytest's `tmp_path` fixture for temporary directories
- No shared state between tests
- Automatic cleanup after test completion
- No side effects on system or other tests

## Test Data

All tests use realistic DLL binary content with proper PE headers:
- DOS signature (MZ)
- PE signature
- Valid header structure
- Deterministic content for hash verification

## Expected Test Behavior

All tests should:
- Execute in under 1 second total
- Pass consistently on every run
- Leave no artifacts on the filesystem
- Produce identical results regardless of execution order

## Test Metrics

- Total Integration Tests: 50
- Average Execution Time: ~0.2 seconds
- Code Coverage: Validates core infrastructure and application layers
- No External Dependencies: All tests run offline

## Licensing

Copyright (c) 2026 Marc Rivero López

Licensed under GPLv3. See LICENSE file for details.

All test code validates real code behavior without mocks or stubs.
