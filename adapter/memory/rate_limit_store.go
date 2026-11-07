package memory

import (
	"context"
	"sync"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/internal/clock"
)

// RateLimitStore provides an in-memory implementation of kagi.RateLimitStore.
type RateLimitStore struct {
	mu      sync.Mutex
	clock   clock.Clock
	entries map[string]*kagi.RateLimitEntry
}

var _ kagi.RateLimitStore = (*RateLimitStore)(nil)

// NewRateLimitStore constructs a new in-memory RateLimitStore.
func NewRateLimitStore(opts ...Option) *RateLimitStore {
	cfg := defaultOptions()
	for _, opt := range opts {
		opt(cfg)
	}
	return &RateLimitStore{
		clock:   cfg.clock,
		entries: make(map[string]*kagi.RateLimitEntry),
	}
}

// Increment atomically increments the request counter for key within a fixed time window.
//
// Atomic Fixed-Window Semantics:
//  1. Reset / initialize when missing:
//     If no entry exists for key, inserts a new record with count = 1 and expires_at = now + window.
//  2. Reset when expired (expires_at <= now):
//     If an entry exists and has expired, resets the record with count = 1 and sets expires_at = now + window.
//  3. Increment when active (expires_at > now):
//     If an entry exists and is active, increments count = count + 1 while strictly preserving existing expires_at.
func (s *RateLimitStore) Increment(ctx context.Context, key string, window time.Duration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now().UTC()
	entry, exists := s.entries[key]
	if !exists || !entry.ExpiresAt.After(now) {
		// Reset or initialize: count = 1, expires_at = now + window
		s.entries[key] = &kagi.RateLimitEntry{
			Key:       key,
			Count:     1,
			ExpiresAt: now.Add(window),
		}
		return 1, nil
	}

	// Active: increment count, preserve expires_at
	entry.Count++
	return entry.Count, nil
}

// DeleteExpired removes expired rate limit counter entries in bounded batches.
func (s *RateLimitStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now().UTC()
	var toDelete []string
	for key, entry := range s.entries {
		if !entry.ExpiresAt.After(now) {
			toDelete = append(toDelete, key)
			if len(toDelete) >= batchSize {
				break
			}
		}
	}

	for _, key := range toDelete {
		delete(s.entries, key)
	}

	return len(toDelete), nil
}
