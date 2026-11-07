package ratelimit

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	// ErrLimitExceeded is returned when the number of requests exceeds the allowed limit.
	ErrLimitExceeded = errors.New("ratelimit: limit exceeded")

	// ErrInvalidWindow is returned when the rate limit window duration is not positive.
	ErrInvalidWindow = errors.New("ratelimit: window must be positive")

	// ErrEmptyKey is returned when an empty key is provided for rate limiting.
	ErrEmptyKey = errors.New("ratelimit: key cannot be empty")

	// ErrNilStore is returned when the Limiter has no store configured.
	ErrNilStore = errors.New("ratelimit: nil store")
)

const (
	// PrefixIP is the key prefix for IP address rate limit buckets.
	PrefixIP = "rl:ip:"

	// PrefixAuth is the key prefix for authentication identifier rate limit buckets.
	PrefixAuth = "rl:auth:"
)

// Store defines the storage interface for atomic fixed-window rate limiting.
type Store interface {
	// Increment atomically increments the request counter for key within a fixed time window.
	// It returns the updated counter value.
	Increment(ctx context.Context, key string, window time.Duration) (count int, err error)
}

// StoreFunc is an adapter allowing the use of ordinary functions as a Store.
type StoreFunc func(ctx context.Context, key string, window time.Duration) (int, error)

// Increment calls f(ctx, key, window).
func (f StoreFunc) Increment(ctx context.Context, key string, window time.Duration) (int, error) {
	return f(ctx, key, window)
}

// Result describes the outcome of a rate limit evaluation.
type Result struct {
	Allowed   bool
	Count     int
	Limit     int
	Remaining int
}

// Limiter coordinates rate limit evaluation against a Store backend.
type Limiter struct {
	store Store
}

// New constructs a Limiter backed by the given Store.
func New(store Store) *Limiter {
	return &Limiter{store: store}
}

// Take evaluates whether an action should be allowed under the given limit and window.
// If limit <= 0, rate limiting is disabled and Take returns nil without calling the store.
// If count > limit, Take returns ErrLimitExceeded.
// If the store fails, Take returns the store error unmasked.
func (l *Limiter) Take(ctx context.Context, key string, limit int, window time.Duration) error {
	if limit <= 0 {
		return nil
	}
	if key == "" {
		return ErrEmptyKey
	}
	if window <= 0 {
		return ErrInvalidWindow
	}
	if l == nil || l.store == nil {
		return ErrNilStore
	}

	count, err := l.store.Increment(ctx, key, window)
	if err != nil {
		return err
	}
	if count > limit {
		return ErrLimitExceeded
	}
	return nil
}

// Allow evaluates whether an action is permitted within the given limit and window.
// It returns true if within limit or if limit <= 0.
// It returns false and nil error if count > limit.
// It returns false and the store error if the store fails.
func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return true, nil
	}
	if key == "" {
		return false, ErrEmptyKey
	}
	if window <= 0 {
		return false, ErrInvalidWindow
	}
	if l == nil || l.store == nil {
		return false, ErrNilStore
	}

	count, err := l.store.Increment(ctx, key, window)
	if err != nil {
		return false, err
	}
	return count <= limit, nil
}

// Check evaluates rate limiting and returns detailed accounting in a Result.
// If limit <= 0, Check returns an allowed Result with Count=0 and Remaining=0 without calling the store.
func (l *Limiter) Check(ctx context.Context, key string, limit int, window time.Duration) (*Result, error) {
	if limit <= 0 {
		return &Result{
			Allowed:   true,
			Count:     0,
			Limit:     limit,
			Remaining: 0,
		}, nil
	}
	if key == "" {
		return nil, ErrEmptyKey
	}
	if window <= 0 {
		return nil, ErrInvalidWindow
	}
	if l == nil || l.store == nil {
		return nil, ErrNilStore
	}

	count, err := l.store.Increment(ctx, key, window)
	if err != nil {
		return nil, err
	}
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	return &Result{
		Allowed:   count <= limit,
		Count:     count,
		Limit:     limit,
		Remaining: remaining,
	}, nil
}

// KeyIP formats an IP address into a standardized rate limit bucket key.
// Leading and trailing whitespace is trimmed.
func KeyIP(ip string) string {
	return PrefixIP + strings.TrimSpace(ip)
}

// KeyAuth formats an authentication identifier (e.g. email) into a standardized rate limit bucket key.
// Leading and trailing whitespace is trimmed, and the string is converted to lowercase for case-insensitive bucketing.
func KeyAuth(email string) string {
	return PrefixAuth + strings.ToLower(strings.TrimSpace(email))
}
