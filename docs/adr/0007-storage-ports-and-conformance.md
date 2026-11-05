# ADR-0007: Storage ports, optional secondary storage, conformance suite

Status: Accepted · Date: 2026-11-05

## Context
Multiple adapters (ent, gorm, sqlc) plus an optional Redis must behave identically.

## Decision
Core defines the ports: `UserStore`, `AccountStore`, `SessionStore`, `VerificationStore`, `RateLimitStore`, and `SecondaryStorage`. No adapter types leak into core.

`SecondaryStorage` is **optional**. When it is not configured, session lookups go to the database and rate limiting uses `RateLimitStore`. When it is configured (Redis), it is used for session cache and rate limits; the database stays the source of truth for sessions.

Expired data is cleaned up through `Cleanup(ctx)` (see [ADR-0010](0010-expiry-and-cleanup.md)).

`adaptertest` is a shared conformance suite every adapter must pass. Mocks use `go.uber.org/mock`.

## Consequences
- Adapters are interchangeable; Redis can be added later without code changes in the host app beyond configuration.
- Contract changes require updating the suite and all adapters.
