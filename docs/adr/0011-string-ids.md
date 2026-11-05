# ADR-0011: String IDs in domain and ports

Status: Accepted · Date: 2026-11-05

## Context
[PRD](../prd.md) and [ADR-0004](0004-data-model.md) left the ID type open: a fixed `string` or a generic type parameter. The choice shapes every domain struct and storage port.

## Decision
All entity IDs in core domain structs and ports are `string`. Adapters convert to and from their native column type (UUID, ULID, integer). ID generation is done by the adapter or the database, not by core.

## Consequences
- Small, readable public API without type parameters spreading through every port and service.
- Works with any storage key type through adapter-side conversion.
- Integer-keyed schemas pay a small parse/format cost and lose compile-time type distinction between ID kinds.
