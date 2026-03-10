# ADR 004: CLI Adapters and Batch Orchestration

## Status
Accepted

## Context

The CLI contained an increasing amount of orchestration logic for multi-file
downloads. That made the interface layer heavier than necessary.

## Decision

- Single-file orchestration stays in `DownloadDLLUseCase`.
- Batch coordination moves into `DownloadBatchUseCase`.
- Console formatting is handled by presenters instead of being embedded in the
  control flow.

## Consequences

- The CLI is thinner and closer to an adapter.
- Batch logic is reusable outside the command line.
- Output formatting can evolve without affecting application orchestration.
