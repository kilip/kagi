# ADR-0014: Session policy — lifetimes, sliding renewal, token rotation and revocation

Status: Accepted · Date: 2026-11-05

## Context
Kagi uses opaque session tokens stored as hashes in the database with optional Redis caching ([ADR-0003](0003-opaque-sessions.md)). [ADR-0004](0004-data-model.md) defined the session entity with `user_id`, token hash, expiry, IP, user agent, and a pending-2FA flag, and [ADR-0010](0010-expiry-and-cleanup.md) established that expiry is always checked on read (`expires_at > now`).

To complete the session model, Kagi needs unambiguous policies on session lifetimes, sliding renewal without database write exhaustion, token rotation triggers, and revocation semantics (logout vs logout-all).

## Decision

### 1. Session lifetimes
Every session is governed by two limits:
- **Idle timeout (sliding TTL):** A session expires if no authenticated request is observed within the idle window. Default: `7 days`.
- **Absolute timeout (maximum lifetime):** Hard upper bound on total session duration from creation, preventing indefinitely prolonged sessions. Default: `30 days`. `expires_at` is capped at `created_at + absolute_timeout`.
- **Pending-2FA timeout:** An intermediate session awaiting two-factor verification has a short, fixed, non-sliding TTL. Default: `10 minutes`.

### 2. Sliding renewal threshold
Sliding renewal extends `expires_at` on active use. To prevent read-heavy workloads from causing a database write on every single request (especially when running without Redis):
- A session's `expires_at` is only updated when remaining idle time drops below the **renewal threshold** (default: `50%` of the idle window, i.e., after 3.5 days of inactivity in a 7-day window).
- When renewed, `expires_at` is extended by the idle timeout, capped by the absolute lifetime.
- If Redis is configured, the cache TTL is synchronized with the new `expires_at`.

### 3. Session states
A session has two states reflected in the data model (`pending_2fa` boolean):
- **Pending 2FA (`pending_2fa = true`):** Created when a first factor succeeds but the user has `two_factor_enabled = true`. Restricted: cannot access protected user resources; only permitted to access OTP challenge verification or sign-out.
- **Active (`pending_2fa = false`):** Fully authenticated session granting standard access.

### 4. Token rotation
Session tokens are rotated (a new high-entropy token is generated with `crypto/rand`, and its hash replaces the existing record or creates a new session while invalidating the old one) on key security boundaries:
- **Graduating from pending 2FA to active:** When the 2FA OTP is verified, the pending session token is invalidated, and a new token is issued with active status and standard idle/absolute timeouts. This prevents session fixation.
- **Password reset:** Invalidate all existing sessions for the user.
- **Password change:** By default, revoke all other active sessions for the user; the current session token is rotated.
- **Explicit rotation API:** Core exposes a `RotateSession(ctx, sessionID)` method for host applications to invoke upon privilege escalation or custom security events.

### 5. Revocation semantics
Kagi supports two revocation modes:
- **`SignOut(ctx, sessionToken)` (single session):** Deletes or marks expired the specific session and removes it from Redis cache.
- **`SignOutAll(ctx, userID)` (logout all devices):** Revokes all active sessions for the given `userID` in a single operation. Triggered automatically on password reset and available as an explicit user action.

### 6. Default configuration
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
- Predictable session lifecycles with defenses against session fixation and indefinitely surviving sessions.
- Throttled sliding renewal protects database I/O on hot paths without requiring Redis.
- Clear separation between unverified 2FA state and fully authenticated access.
- Requires adapters to support updating `expires_at` and token hash, and revoking by session ID or by user ID.
