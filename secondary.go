package kagi

import (
	"context"
	"time"
)

// SecondaryStorage defines the optional fast-tier storage port (typically Redis) per ADR-0007.
//
// When configured via Config.SecondaryStorage, it provides low-latency caching for active user
// sessions and fast, distributed rate limiting, reducing load on primary database stores
// (SessionStore and RateLimitStore).
//
// # Optional Architecture (ADR-0007)
//
// SecondaryStorage is strictly optional. When nil, Kagi transparently executes all session queries
// and mutations against SessionStore and manages rate limiting via RateLimitStore. The host application
// can introduce Redis at any point without changing domain code or business logic.
//
// # Multi-Tier Mutation Ordering: Primary-First Write Principle (ADR-0007, ADR-0014)
//
// Primary storage (SessionStore) is ALWAYS the authoritative source of truth:
//   - Writes: All session mutations (creation, sliding renewal updates, token rotation, and revocations)
//     MUST commit to SessionStore FIRST before updating or evicting cache entries in SecondaryStorage.
//   - Consistency: If a secondary cache update or eviction fails following a primary store commit,
//     the primary database remains consistent. Cache eviction failures during revocation are surfaced
//     to prevent stale session reuse.
//
// # Cache Hit and Miss Semantics (ADR-0007, ADR-0014)
//
// GetSession implements transparent fallback semantics:
//   - Cache Hit: Returns (*Session, nil) when an active, unexpired session is found.
//   - Cache Miss: Returns (nil, nil) when the key is absent or expired. Callers must treat (nil, nil)
//     not as an error, but as a cache miss, immediately falling back to SessionStore.GetByTokenHash.
//   - Operational Failure: Returns (nil, error) only on transport or operational errors (e.g. Redis
//     timeout, network disconnect, serialization failure), allowing callers to log the failure and
//     optionally degrade gracefully by querying primary storage.
//
// # Expiry Contract and TTL Handling (ADR-0010, ADR-0014)
//
// SecondaryStorage relies on storage-level TTLs (e.g. Redis EXPIRE / PEXPIRE) to automatically evict
// inactive sessions. However, per ADR-0010, correctness never relies solely on background cleanup:
// GetSession MUST verify that session.ExpiresAt > now. Any session where session.ExpiresAt <= now
// must be treated as a cache miss and return (nil, nil).
//
// # Active-Only Session Caching & Pending-2FA Prohibition (ADR-0014 §4)
//
// SecondaryStorage MUST ONLY cache fully authenticated active sessions (session.Pending2FA == false).
// Intermediate sessions awaiting two-factor verification (pending_2fa = true) are short-lived,
// single-use security barriers. Per ADR-0014 section 4, pending-2FA sessions MUST NEVER be cached
// in SecondaryStorage.
//
// # Deterministic Cache Invalidation (ADR-0014 §6)
//
// SessionStore deletion methods (DeleteByID, DeleteByUserID, DeleteOthersByUserID) return the deleted
// token_hash strings. This enables direct eviction from SecondaryStorage via DeleteSession or
// DeleteSessions without maintaining secondary index sets (e.g. user-to-session sets) in Redis.
// DeleteSessions with an empty slice is an idempotent no-op returning nil.
//
//go:generate mockgen -destination=mock/secondary_storage.go -package=mock github.com/kilip/kagi SecondaryStorage
type SecondaryStorage interface {
	// GetSession retrieves an active session from the fast-tier cache by its SHA-256 token hash (ADR-0014).
	//
	// Cache Hit / Miss Semantics:
	//   - Cache Hit: Returns (*Session, nil) if an active, unexpired session matching tokenHash exists.
	//   - Cache Miss: Returns (nil, nil) if the session key does not exist or has expired. A cache
	//     miss is NOT an error; callers use (nil, nil) to transparently fall back to querying the
	//     primary database via SessionStore.GetByTokenHash.
	//   - Operational Failure: Returns (nil, error) only when an underlying operational or transport
	//     failure occurs (e.g. Redis connection timeout, network partition, serialization error).
	//
	// Expiry Contract (ADR-0010):
	// The implementation must verify that the session has not expired (session.ExpiresAt > now).
	// If an entry is present in cache but its ExpiresAt timestamp has elapsed (e.g. before native TTL
	// eviction has run), the implementation MUST treat it as a cache miss and return (nil, nil).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - tokenHash: 64-character lowercase hex SHA-256 digest of the session token.
	//
	// Return values:
	//   - (*Session, nil) on cache hit for an active, unexpired session.
	//   - (nil, nil) on cache miss (key absent or expired).
	//   - (nil, error) on operational or transport failure.
	GetSession(ctx context.Context, tokenHash string) (*Session, error)

	// SetSession caches an active session in secondary storage with a specified time-to-live (ADR-0014).
	//
	// Primary-First Write Ordering (ADR-0007, ADR-0014):
	// SetSession MUST ONLY be called AFTER the session has successfully committed to the primary
	// SessionStore. The primary database remains the authoritative source of truth at all times.
	//
	// Active-Only Session Caching & Pending-2FA Prohibition (ADR-0014 §4):
	// SetSession MUST ONLY be called for active sessions (session.Pending2FA == false). Intermediate
	// sessions awaiting two-factor verification (pending_2fa = true) are short-lived, single-use
	// records and MUST NEVER be cached in SecondaryStorage. Implementations must reject or ignore
	// any session where session.Pending2FA == true.
	//
	// TTL Handling (ADR-0010, ADR-0014):
	// The ttl parameter specifies the duration until the cache entry expires (typically derived from
	// session.ExpiresAt.Sub(now)). The implementation must configure native key expiration (e.g. Redis
	// SET ... EX or PEXPIRE) matching ttl. If ttl <= 0, the session is already expired and the adapter
	// should treat the call as an immediate no-op returning nil or evict the key.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - session: the active Session entity to cache. Must have Pending2FA == false and contain a
	//     valid 64-character hex TokenHash.
	//   - ttl: duration until the cache entry expires.
	//
	// Return values:
	//   - nil on successful caching.
	//   - An error if the cache write or serialization fails.
	SetSession(ctx context.Context, session *Session, ttl time.Duration) error

	// DeleteSession evicts a single cached session by its SHA-256 token hash (ADR-0014).
	//
	// Primary-First Write Ordering (ADR-0007, ADR-0014):
	// Invoked during single session revocation (SignOut, RevokeSession) or token rotation (RotateSession)
	// AFTER the session record has been deleted or updated in the primary SessionStore.
	//
	// Idempotency Contract:
	// If tokenHash does not exist in the cache (already evicted, expired, or never cached), DeleteSession
	// succeeds and returns nil. It MUST NOT return an error for absent keys.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - tokenHash: 64-character lowercase hex SHA-256 digest of the session to evict.
	//
	// Return values:
	//   - nil on successful eviction or if the key does not exist.
	//   - An error if the underlying cache infrastructure fails.
	DeleteSession(ctx context.Context, tokenHash string) error

	// DeleteSessions bulk-evicts multiple cached sessions by their SHA-256 token hashes (ADR-0014).
	//
	// Deterministic Cache Invalidation (ADR-0014 §6):
	// Invoked during multi-session revocations (SignOutOthers, SignOutAll, password reset) AFTER
	// primary storage deletion has committed. Primary SessionStore deletion methods return the exact
	// slice of deleted token_hash values, which are passed directly to DeleteSessions for batch
	// invalidation (e.g. Redis DEL key1 key2 ...), eliminating the need for secondary user-session
	// index sets in Redis.
	//
	// Empty Slice & Idempotency Contract:
	// When len(tokenHashes) == 0, DeleteSessions is an idempotent no-op that immediately returns nil
	// without performing any network operations or returning an error. If any or all of the specified
	// keys do not exist in the cache, the operation succeeds and returns nil.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - tokenHashes: slice of 64-character lowercase hex SHA-256 digests to evict.
	//
	// Return values:
	//   - nil on successful bulk eviction, if keys were absent, or if len(tokenHashes) == 0.
	//   - An error if the underlying bulk deletion fails.
	DeleteSessions(ctx context.Context, tokenHashes []string) error

	// IncrementRateLimit atomically increments a request counter for key within a fixed time window (ADR-0004, ADR-0007).
	//
	// Fast Distributed Rate Limiting:
	// When SecondaryStorage is configured, high-volume rate-limiting checks (per-IP, per-email, OTP
	// requests, login attempts) bypass RateLimitStore in the primary database and are routed here to
	// eliminate database write load.
	//
	// Atomic Fixed-Window Semantics:
	// The implementation MUST execute the counter increment and window expiration atomically (e.g.
	// Redis INCR followed by EXPIRE on first creation, or an equivalent atomic Lua script):
	//   1. Reset / initialize when missing:
	//      If key does not exist, sets its counter to 1 and attaches a TTL equal to window.
	//   2. Increment when active:
	//      If key exists and is within an active window, increments counter by 1 without extending
	//      or resetting the existing window TTL.
	//   3. Reset when expired:
	//      If key has expired, resets its counter to 1 and sets a new TTL equal to window.
	//
	// Concurrency & Atomicity:
	// The increment operation must be safe against concurrent requests across multiple distributed
	// application nodes without race conditions or counter loss.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - key: unique rate-limiting bucket identifier (e.g. "ratelimit:login:ip:192.0.2.1").
	//   - window: duration of the fixed rate limiting window.
	//
	// Return values:
	//   - (count, nil) where count >= 1 is the updated counter value after increment or reset.
	//   - (0, error) if the atomic cache operation or network connection fails.
	IncrementRateLimit(ctx context.Context, key string, window time.Duration) (count int, err error)
}
