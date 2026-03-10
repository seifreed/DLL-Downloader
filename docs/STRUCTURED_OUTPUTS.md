# Structured CLI Outputs

This document defines the stable machine-readable CLI output contracts.

## Supported Formats

- `--json`
- `--sarif`

Both formats are part of the supported CLI surface and must be treated as
versioned contracts for pipeline consumers.

## Version

- Structured output contract version: `1.0`
- SARIF version: `2.1.0`

## JSON Contract

Top-level fields:

- `format`
- `schema_version`
- `tool`
- `architecture`
- `success_count`
- `failure_count`
- `items`

Each item contains:

- `dll_name`
- `success`
- `was_cached`
- `error_message`
- `security_warning`
- `dll_file`

Boundary failures use:

- `format`
- `schema_version`
- `tool`
- `success`
- `error.kind`
- `error.message`

## SARIF Contract

- Uses SARIF `2.1.0`
- Stores the local contract version in `runs[0].properties.structuredOutputVersion`
- Uses stable rule ids:
  - `dll-downloader/download-failed`
  - `dll-downloader/download-succeeded`
  - `dll-downloader/download-cached`
  - `dll-downloader/security-warning`
  - `dll-downloader/boundary-failure`

## Compatibility Rules

- Adding optional fields is allowed with documentation updates.
- Renaming or removing fields requires a major-version compatibility decision.
- Changing SARIF rule ids requires explicit contract review and documentation updates.
