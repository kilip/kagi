# ADR-0010: Expiry handling and cleanup

Status: Accepted · Date: 2026-11-05

## Context
Sessions, verifications and rate-limit counters expire. Without Redis TTLs, expired rows accumulate in the database.

## Decision
- Expiry is always checked on read (`expires_at > now`), so correctness never depends on cleanup.
- Kagi exposes a single `Cleanup(ctx)` covering sessions, verifications and rate limits. It is idempotent and deletes in batches to avoid long locks.
- Scheduling is the host app's responsibility. Kagi starts no goroutines by default. An optional `RunCleanup(ctx, interval)` helper runs only when called.
- Expiry columns are indexed; rate-limit counters use atomic upserts.

## Consequences
- Predictable behavior and no hidden background work.
- Host apps must schedule cleanup (cron, ticker, or `RunCleanup`).
- Lazy-only cleanup was rejected: untouched keys never get removed and delete cost lands on the hot path.
