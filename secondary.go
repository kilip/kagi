package kagi

import (
	"context"
	"time"
)

// SecondaryStorage defines the optional fast-tier storage port (e.g. Redis) - ADR-0007.
// When configured, it caches active sessions and provides fast, distributed rate limiting.
// The primary database remains the source of truth; all mutations commit to primary storage first.
type SecondaryStorage interface {
	// Session Caching
	GetSession(ctx context.Context, tokenHash string) (*Session, error)
	SetSession(ctx context.Context, session *Session, ttl time.Duration) error
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteSessions(ctx context.Context, tokenHashes []string) error

	// Fast Rate Limiting
	IncrementRateLimit(ctx context.Context, key string, window time.Duration) (count int, err error)
}
