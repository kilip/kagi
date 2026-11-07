// Package ratelimit provides a storage-agnostic, atomic fixed-window rate limiter.
//
// # Architecture
//
// The ratelimit package is intentionally decoupled from core kagi types to prevent
// circular dependencies and enable independent reuse. It relies solely on the Go
// standard library and defines a minimal [Store] interface:
//
//	type Store interface {
//	    Increment(ctx context.Context, key string, window time.Duration) (count int, err error)
//	}
//
// Any storage backend implementing atomic fixed-window counter increments—such as
// primary database adapters (kagi.RateLimitStore) or distributed caching tiers
// (kagi.SecondaryStorage via [StoreFunc])—can be wired into [Limiter].
//
// # Atomic Fixed-Window Model
//
// Under the fixed-window model, requests are counted within discrete time buckets
// of duration window. The underlying [Store] is responsible for atomically incrementing
// the counter for key or initializing it if expired/absent.
//
// # Evaluation Methods
//
// [Limiter] provides three evaluation methods to accommodate different caller patterns:
//
//   - [Limiter.Take]: returns [ErrLimitExceeded] when the count exceeds limit, or nil if allowed.
//   - [Limiter.Allow]: returns a boolean indicating whether the action is permitted, along with any operational error.
//   - [Limiter.Check]: returns a detailed [Result] containing allowed status, current count, limit, and remaining capacity.
//
// When limit <= 0, rate limiting is considered disabled or bypassed; the evaluation
// methods immediately permit the request without calling the underlying store.
//
// # Key Formatting
//
// Helpers are provided to format canonical rate limit bucket keys:
//
//   - [KeyIP]: formats an IP address bucket key with prefix "rl:ip:".
//   - [KeyAuth]: formats an authentication identifier (e.g. email) bucket key with prefix "rl:auth:".
package ratelimit
