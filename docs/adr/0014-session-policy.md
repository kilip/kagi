# ADR-0014: Session policy — lifetimes, sliding renewal, token rotation and revocation

Status: Accepted · Date: 2026-11-05

## Context
Kagi uses opaque session tokens stored as hashes in the database with optional Redis caching ([ADR-0003](0003-opaque-sessions.md)). [ADR-0004](0004-data-model.md) defined the session entity with `user_id`, token hash, expiry, IP, user agent, and a pending-2FA flag, and [ADR-0010](0010-expiry-and-cleanup.md) established that expiry is always checked on read (`expires_at > now`).

To complete the session model, Kagi needs unambiguous policies on token entropy and hashing, session lifetimes, sliding renewal without database write amplification, pending-2FA isolation, token rotation triggers, and revocation with immediate cache invalidation.

## Decision

### 1. Token entropy and hashing
- **Generation:** Session tokens are generated with 32 bytes (256 bits) from `crypto/rand` and encoded as unpadded `base64.RawURLEncoding` strings for safe cookie transport.
- **Storage hash:** Only the `SHA-256` (`crypto/sha256`) hex/bytes digest of the raw token is stored in `session.token_hash` and used as the lookup key. Because 256-bit random tokens cannot be brute-forced offline, fast cryptographic hashing (`SHA-256` + constant-time comparison where applicable) is used instead of `argon2id` to avoid per-request CPU latency and denial-of-service vectors.

### 2. Session lifetimes
Every session is governed by three limits:
- **Idle timeout (sliding TTL):** A session expires if no authenticated request is observed within the idle window. Default: `7 days`.
- **Absolute timeout (maximum lifetime):** Hard upper bound on total session duration measured from the session's initial `created_at` timestamp, preventing indefinitely prolonged sessions. Default: `30 days`. `expires_at` is strictly capped at `created_at + AbsoluteTimeout`.
- **Pending-2FA timeout:** An intermediate session awaiting two-factor verification has a short, fixed, non-sliding TTL. Default: `10 minutes`.

### 3. Sliding renewal threshold and write-amplification guard
Sliding renewal extends `expires_at` on active use. To prevent read-heavy workloads from causing a database write on every request (especially when running without Redis):
- On session validation, compute `newExpiresAt = min(now + IdleTimeout, session.CreatedAt + AbsoluteTimeout)`.
- A session's `expires_at` is updated in the database and `SecondaryStorage` **only** when:
  1. Remaining time `session.ExpiresAt - now <= IdleTimeout * RenewalThreshold` (default threshold: `0.5`, i.e., `<= 3.5 days` remaining in a 7-day idle window), **and**
  2. `newExpiresAt > session.ExpiresAt` (preventing redundant writes on every request during the final days when `session.ExpiresAt` has already hit the `AbsoluteTimeout` cap).
- Core indicates when a session was renewed so `http/*` wrappers can re-issue `Set-Cookie` with the updated cookie expiration, keeping browser cookie lifetime synchronized with server-side `expires_at`.

### 4. Session states and pending-2FA isolation
A session has two states reflected in `session.pending_2fa`:
- **Pending 2FA (`pending_2fa = true`):** Created when primary authentication succeeds for a user with `two_factor_enabled = true`. Standard session validation (`ValidateSession`) rejects `pending_2fa = true` sessions with sentinel error `ErrSessionPending2FA` so they can never access protected application routes. Only the 2FA verification flow and `SignOut` accept a pending-2FA session.
- **Active (`pending_2fa = false`):** Fully authenticated session granting standard access.

### 5. Token rotation
Rotating a session generates a new 256-bit random token and updates `token_hash` on the existing session record while **preserving `created_at`** (so rotation never resets the 30-day `AbsoluteTimeout` clock), and immediately deletes the old `token_hash` entry from `SecondaryStorage` (Redis).

Rotation and session invalidation are triggered on security boundaries:
- **Graduating from pending 2FA to active:** When the 2FA OTP is verified, `pending_2fa` is set to `false`, the token is rotated (`token_hash` updated, old token invalidated), and `expires_at` is set to `min(now + IdleTimeout, created_at + AbsoluteTimeout)`. The new raw token is returned to the caller. This prevents session fixation across the 2FA step.
- **Password reset (unauthenticated recovery):** Revokes **all** sessions for the user (`SignOutAll`).
- **Password change or 2FA enablement/disablement (authenticated):** Revokes all **other** sessions for the user (`SignOutOthers`) and rotates the current session token, returning the new raw token so the user remains signed in on the active device.
- **Explicit rotation API:** Core exposes `RotateSession(ctx, rawToken) (newRawToken string, *Session, error)` for host applications to call on privilege elevation.

### 6. Revocation semantics and Redis cache invalidation
Kagi provides three revocation operations:
- **`SignOut(ctx, rawToken)` (single session):** Deletes the session matching `sha256(rawToken)` in `SessionStore` and deletes its cache key in `SecondaryStorage`.
- **`SignOutOthers(ctx, userID, currentSessionID)` (other devices):** Revokes all sessions for `userID` except `currentSessionID` and invalidates their cached entries in `SecondaryStorage`.
- **`SignOutAll(ctx, userID)` (all devices):** Revokes all sessions for `userID` and invalidates all cached sessions for `userID` in `SecondaryStorage`.

To guarantee instant revocation when Redis is enabled ([ADR-0003](0003-opaque-sessions.md)), bulk revocation (`SignOutAll` / `SignOutOthers`) must never leave orphaned `token_hash` keys alive in `SecondaryStorage` until TTL expiry. Either `SessionStore` returns the deleted token hashes or `SecondaryStorage` indexes cached session keys by `userID`.

### 7. Default configuration
Core exposes configurable options with safe defaults:

```go
type SessionConfig struct {
    IdleTimeout       time.Duration // Default: 7 * 24 * time.Hour
    AbsoluteTimeout   time.Duration // Default: 30 * 24 * time.Hour
    RenewalThreshold  float64       // Default: 0.5 (renew when <= 50% idle time remains)
    Pending2FATimeout time.Duration // Default: 10 * time.Minute
}
```

## Consequences
- Defends against session fixation, offline database leaks (`SHA-256` token hashing), CPU DoS on session lookups, and indefinitely surviving sessions (`created_at` preservation across rotation).
- Throttled sliding renewal with the `AbsoluteTimeout` cap guard eliminates write amplification on read-heavy workloads.
- Strict `ErrSessionPending2FA` sentinel error prevents partial-authentication bypasses in HTTP middleware.
- Requires `SessionStore` and `SecondaryStorage` ports to support in-place rotation (`token_hash` update), `SignOutOthers`, and immediate cache eviction on user-wide revocation.
