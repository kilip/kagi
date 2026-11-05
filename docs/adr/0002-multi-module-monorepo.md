# ADR-0002: Multi-module monorepo

Status: Accepted · Date: 2026-11-05

## Context
Users should not pull ent, gorm, sqlc, Redis and Fiber just to use one of them.

## Decision
One repository, module path `github.com/kilip/kagi`. Core is the root module. Each adapter and wrapper has its own `go.mod`: `adapter/ent`, `adapter/gorm`, `adapter/sqlc`, `adapter/redis`, `http/fiber`, and `examples/*`. `go.work` is used for local development. Shared conformance tests live in core under `adaptertest/`.

## Consequences
- Minimal dependency footprint for users.
- Submodules need path-prefixed tags (e.g. `adapter/ent/v0.1.0`); release strategy is still open.
