# ADR-0004: Data model — user, account, session, verification, rate_limit

Status: Accepted · Date: 2026-11-05

## Context
A user may sign in with several methods (password, OAuth providers, OTP). Rate limiting must work without Redis.

## Decision
Separate entities:
- **user**: identity (id, email, name, `email_verified`, `two_factor_enabled`, timestamps)
- **account**: one row per login method (`user_id`, `provider`, `provider_account_id`, `password_hash` for credential, OAuth tokens)
- **session**: `user_id`, token hash, expiry, IP, user agent, and a pending-2FA state
- **verification**: `type` (`login`, `two_factor`, `email_verify`), hashed code, TTL, attempt count
- **rate_limit**: `key`, `count`, `expires_at`; counters are updated with an atomic upsert

Multi-method linking is part of the MVP. All time-bound entities have an index on their expiry column.

## Consequences
- Adding a login method means adding an account row, not changing `user`.
- Rate limiting works with the database alone; Redis is optional (see [ADR-0007](0007-storage-ports-and-conformance.md)).
- Open: ID type (string vs generic) and extra-field mapping are decided during implementation.
