# ADR-0003: Opaque session tokens

Status: Accepted · Date: 2026-11-05

## Context
Sessions can be stateless (JWT) or stateful (opaque token).

## Decision
MVP uses opaque tokens. The token is random, only its hash is stored in the DB, and it is delivered via cookie (`HttpOnly`, `Secure`, `SameSite`). Redis, when configured, caches session lookups. A `SessionStrategy` interface leaves room for JWT later.

## Consequences
- Instant revocation (logout, password change, logout-all-devices).
- Every request needs a session lookup (mitigated by Redis).
- Services that must verify sessions without calling Kagi are not served by the MVP.
