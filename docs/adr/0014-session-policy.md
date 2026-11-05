# ADR-0014: Session policy — lifetimes, sliding renewal, token rotation and revocation

Status: Accepted · Date: 2026-11-05

## Context
Kagi uses opaque session tokens stored as hashes in the database with optional Redis caching ([ADR-0003](0003-opaque-sessions.md)). [ADR-0004](0004-data-model.md) defined the session entity with `user_id`, token hash, expiry, IP, user agent, and a pending-2FA flag, and [ADR-0010](0010-expiry-and-cleanup.md) established that expiry is always checked on read (`expires_at > now`).

To complete the session model, Kagi needs unambiguous policies on token entropy and encoding, session lifetimes, sliding renewal without database write amplification, pending-2FA isolation across login methods, atomic token rotation, device management, and deterministic Redis cache invalidation.

## Decision

### 1. Token entropy, encoding, and hashing
- **Generation & wire format:** Session tokens are generated from 32 bytes (256 bits) of `crypto/rand` and encoded using unpadded `base64.RawURLEncoding`, producing a fixed **43-character ASCII string**. Core rejects any incoming `rawToken` with `len(rawToken) != 43` before hashing.
- **Storage hash:** Only the `SHA-256` (`crypto/sha256`) digest encoded as a **64-character lowercase hex `string`** is stored in `session.token_hash` and used as the lookup key across SQL and `SecondaryStorage`. Because 256-bit random tokens cannot be brute-forced offline, fast cryptographic hashing (`SHA-256`) is used instead of `argon2id` to avoid per-request CPU latency and denial-of-service vectors. After lookup, core verifies the returned `session.TokenHash` with `crypto/subtle.ConstantTimeCompare` as defense in depth against adapter collation bugs.

### 2. Session lifetimes
Every session is governed by three limits:
- **Idle timeout (sliding TTL):** A session expires if no authenticated request is observed within the idle window. Default: `7 days`.
- **Absolute timeout (maximum lifetime):** Hard upper bound on total session duration measured from the session's initial `created_at` timestamp, preventing indefinitely prolonged sessions. Default: `30 days`. Both initial creation and renewals strictly clamp `expires_at` to `min(now + IdleTimeout, created_at + AbsoluteTimeout)`.
- **Pending-2FA timeout:** An intermediate session awaiting two-factor verification has a short, fixed, non-sliding TTL. Default: `10 minutes`.

### 3. Sliding renewal threshold and write-amplification guard
Sliding renewal extends `expires_at` on active use. To prevent read-heavy workloads from causing a database write on every request (especially when running without Redis):
- `ValidateSession(ctx, rawToken)` returns `(*Session, renewed bool, error)`.
- On session validation, compute `newExpiresAt = min(now + IdleTimeout, session.CreatedAt + AbsoluteTimeout)`.
- A session's `expires_at` is updated in `SessionStore` and `SecondaryStorage` **only** when:
  1. Remaining time `session.ExpiresAt - now <= IdleTimeout * RenewalThreshold` (default threshold: `0.5`, i.e., `<= 3.5 days` remaining in a 7-day idle window), **and**
  2. `newExpiresAt > session.ExpiresAt` (preventing redundant writes on every request during the final days when `session.ExpiresAt` has already reached the `AbsoluteTimeout` cap).
- When `renewed == true`, `http/*` wrappers re-issue `Set-Cookie` (`Max-Age` and `Expires` derived from `session.ExpiresAt`) so browser cookie expiration stays synchronized with server-side `expires_at`.

### 4. Session states, multi-method 2FA rules, and pending-2FA isolation
A session has two states reflected in `session.pending_2fa`:
- **Pending 2FA (`pending_2fa = true`):**
  - **When created:** Created when primary authentication succeeds via **email/password** or **OAuth** for a user with `two_factor_enabled = true` (after verifying the 2FA OTP rate limit so attackers cannot flood `session` rows). Passwordless email OTP sign-in ([ADR-0005](0005-email-otp.md)) already proves possession of the user's email inbox in the primary step, so it creates an active (`pending_2fa = false`) session directly rather than sending a duplicate email OTP.
  - **Strict isolation:** Standard `ValidateSession` rejects `pending_2fa = true` sessions by returning `(nil, false, ErrSessionPending2FA)`—never returning a non-nil `*Session` alongside an error—so protected routes cannot accidentally accept a partial session.
  - **Allowed operations:** Only 2FA OTP verification (`Verify2FA`), 2FA OTP resend (`Resend2FA`, subject to rate limits), and `SignOut` accept a pending-2FA token via a dedicated internal validation helper that binds the pending session's `user_id` to the `two_factor` verification record.
  - **No Redis caching:** `pending_2fa = true` sessions are short-lived, single-use records and are not cached in `SecondaryStorage`.
- **Active (`pending_2fa = false`):** Fully authenticated session granting standard access.

### 5. Token rotation and concurrency
Rotating a session generates a new 256-bit random token, atomically updates `token_hash` on the existing session record (`WHERE id = $1 AND token_hash = $2 AND expires_at > $3`) while **preserving `created_at`** (so rotation never resets the 30-day `AbsoluteTimeout` clock), and immediately deletes the old `token_hash` entry from `SecondaryStorage` (Redis) before writing the new entry.

Rotation and session invalidation are triggered exclusively on synchronous security-boundary transitions (never during background sliding renewal):
- **Graduating from pending 2FA to active:** When the 2FA OTP is verified, `pending_2fa` is set to `false`, the token is rotated (`token_hash` updated, old token invalidated), and `expires_at` is set to `min(now + IdleTimeout, created_at + AbsoluteTimeout)`. The new raw token is returned to the caller. This prevents session fixation across the 2FA step.
- **Password reset (unauthenticated recovery):** Revokes **all** sessions for the user (`SignOutAll`) before or atomically with consuming the reset token.
- **Password change, 2FA enablement/disablement, or account unlinking ([ADR-0012](0012-account-linking-policy.md)):** Revokes all **other** sessions for the user (`SignOutOthers`) and rotates the current session token, returning the new raw token so the user remains signed in on the active device.
- **Explicit rotation API:** Core exposes `RotateSession(ctx, rawToken) (newRawToken string, *Session, error)` for host applications to call on privilege elevation. `RotateSession` rejects `pending_2fa = true` sessions with `ErrSessionPending2FA`.

### 6. Revocation, device management, and Redis cache invalidation
Kagi provides revocation and device-management operations:
- **`SignOut(ctx, rawToken)` (single session):** Deletes the session matching `sha256(rawToken)` in `SessionStore` and deletes its key in `SecondaryStorage`.
- **`RevokeSession(ctx, userID, sessionID)` (specific device):** Deletes a specific session owned by `userID` and evicts its `token_hash` from `SecondaryStorage`.
- **`SignOutOthers(ctx, userID, currentSessionID)` (other devices):** Revokes all sessions for `userID` except `currentSessionID` and evicts their cached entries in `SecondaryStorage`.
- **`SignOutAll(ctx, userID)` (all devices):** Revokes all sessions for `userID` and evicts all cached sessions for `userID` in `SecondaryStorage`.
- **`ListSessions(ctx, userID)` (active devices):** Returns active (`expires_at > now`, `pending_2fa = false`) sessions for `userID` (exposing `id`, `ip`, `user_agent`, `created_at`, `expires_at` while never exposing `token_hash`).

**Deterministic cache invalidation contract:**
- `SessionStore` deletion methods (`DeleteByID`, `DeleteByUserID`, `DeleteOthersByUserID`) return the deleted `token_hash` values (`[]string`), allowing core to delete the exact `session:<token_hash>` keys from `SecondaryStorage` without requiring secondary user-index sets in Redis.
- Mutations always commit to `SessionStore` (database) **first** and evict/update `SecondaryStorage` (Redis) **second**. Eviction errors on revocation are retried and surfaced rather than silently ignored.

### 7. Default configuration and validation
Core exposes configurable options with safe defaults and validates invariants on initialization (`0 < RenewalThreshold < 1`, `0 < Pending2FATimeout <= IdleTimeout <= AbsoluteTimeout`):

```go
type SessionConfig struct {
    IdleTimeout       time.Duration // Default: 7 * 24 * time.Hour
    AbsoluteTimeout   time.Duration // Default: 30 * 24 * time.Hour
    RenewalThreshold  float64       // Default: 0.5 (renew when <= 50% idle time remains)
    Pending2FATimeout time.Duration // Default: 10 * time.Minute
}
```

## Consequences
- Defends against session fixation, offline database leaks (64-char hex `SHA-256` token hashing + constant-time verify), oversized token DoS (43-char length check), CPU DoS on session lookups, and indefinitely surviving sessions (`created_at` preservation across rotation).
- Throttled sliding renewal with the `AbsoluteTimeout` cap guard eliminates write amplification on read-heavy workloads.
- Strict `(nil, false, ErrSessionPending2FA)` contract and explicit multi-method 2FA rules prevent partial-authentication bypasses and duplicate email OTP friction.
- Having `SessionStore` return deleted `token_hash` slices keeps `SecondaryStorage` a simple key-value store while guaranteeing immediate Redis eviction on single or bulk revocation.
