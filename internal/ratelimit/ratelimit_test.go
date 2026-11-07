package ratelimit_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kilip/kagi/internal/ratelimit"
)

type mockStore struct {
	mu          sync.Mutex
	counts      map[string]int
	calls       int
	err         error
	onIncrement func(ctx context.Context, key string, window time.Duration) (int, error)
}

func newMockStore() *mockStore {
	return &mockStore{
		counts: make(map[string]int),
	}
}

func (m *mockStore) Increment(ctx context.Context, key string, window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++

	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if m.onIncrement != nil {
		return m.onIncrement(ctx, key, window)
	}
	if m.err != nil {
		return 0, m.err
	}
	m.counts[key]++
	return m.counts[key], nil
}

func (m *mockStore) getCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestLimiter_Take(t *testing.T) {
	t.Parallel()

	errStoreFailure := errors.New("storage connection failed")

	tests := []struct {
		name       string
		limit      int
		window     time.Duration
		key        string
		storeCount int
		storeErr   error
		wantErr    error
		wantCalls  int
	}{
		{
			name:      "limit zero bypasses without calling store",
			limit:     0,
			window:    time.Minute,
			key:       "any-key",
			wantErr:   nil,
			wantCalls: 0,
		},
		{
			name:      "negative limit bypasses without calling store",
			limit:     -5,
			window:    time.Minute,
			key:       "any-key",
			wantErr:   nil,
			wantCalls: 0,
		},
		{
			name:      "empty key returns ErrEmptyKey",
			limit:     5,
			window:    time.Minute,
			key:       "",
			wantErr:   ratelimit.ErrEmptyKey,
			wantCalls: 0,
		},
		{
			name:      "zero window duration returns ErrInvalidWindow",
			limit:     5,
			window:    0,
			key:       "key1",
			wantErr:   ratelimit.ErrInvalidWindow,
			wantCalls: 0,
		},
		{
			name:      "negative window duration returns ErrInvalidWindow",
			limit:     5,
			window:    -time.Second,
			key:       "key1",
			wantErr:   ratelimit.ErrInvalidWindow,
			wantCalls: 0,
		},
		{
			name:       "under limit succeeds",
			limit:      5,
			window:     time.Minute,
			key:        "key1",
			storeCount: 3,
			wantErr:    nil,
			wantCalls:  1,
		},
		{
			name:       "exactly at limit succeeds",
			limit:      5,
			window:     time.Minute,
			key:        "key1",
			storeCount: 5,
			wantErr:    nil,
			wantCalls:  1,
		},
		{
			name:       "over limit returns ErrLimitExceeded",
			limit:      5,
			window:     time.Minute,
			key:        "key1",
			storeCount: 6,
			wantErr:    ratelimit.ErrLimitExceeded,
			wantCalls:  1,
		},
		{
			name:      "store error is propagated without masking",
			limit:     5,
			window:    time.Minute,
			key:       "key1",
			storeErr:  errStoreFailure,
			wantErr:   errStoreFailure,
			wantCalls: 1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newMockStore()
			if tc.storeErr != nil {
				store.err = tc.storeErr
			} else if tc.storeCount > 0 {
				store.onIncrement = func(ctx context.Context, key string, window time.Duration) (int, error) {
					return tc.storeCount, nil
				}
			}

			limiter := ratelimit.New(store)
			err := limiter.Take(context.Background(), tc.key, tc.limit, tc.window)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
			if store.getCalls() != tc.wantCalls {
				t.Fatalf("expected %d store calls, got %d", tc.wantCalls, store.getCalls())
			}
		})
	}
}

func TestLimiter_Allow(t *testing.T) {
	t.Parallel()

	errStoreFailure := errors.New("db error")

	tests := []struct {
		name        string
		limit       int
		window      time.Duration
		key         string
		storeCount  int
		storeErr    error
		wantAllowed bool
		wantErr     error
		wantCalls   int
	}{
		{
			name:        "limit zero is allowed without calling store",
			limit:       0,
			window:      time.Minute,
			key:         "key1",
			wantAllowed: true,
			wantErr:     nil,
			wantCalls:   0,
		},
		{
			name:        "negative limit is allowed without calling store",
			limit:       -1,
			window:      time.Minute,
			key:         "key1",
			wantAllowed: true,
			wantErr:     nil,
			wantCalls:   0,
		},
		{
			name:        "empty key returns ErrEmptyKey",
			limit:       5,
			window:      time.Minute,
			key:         "",
			wantAllowed: false,
			wantErr:     ratelimit.ErrEmptyKey,
			wantCalls:   0,
		},
		{
			name:        "invalid window returns ErrInvalidWindow",
			limit:       5,
			window:      0,
			key:         "key1",
			wantAllowed: false,
			wantErr:     ratelimit.ErrInvalidWindow,
			wantCalls:   0,
		},
		{
			name:        "under limit allowed",
			limit:       5,
			window:      time.Minute,
			key:         "key1",
			storeCount:  4,
			wantAllowed: true,
			wantErr:     nil,
			wantCalls:   1,
		},
		{
			name:        "at limit allowed",
			limit:       5,
			window:      time.Minute,
			key:         "key1",
			storeCount:  5,
			wantAllowed: true,
			wantErr:     nil,
			wantCalls:   1,
		},
		{
			name:        "over limit rejected with no error",
			limit:       5,
			window:      time.Minute,
			key:         "key1",
			storeCount:  6,
			wantAllowed: false,
			wantErr:     nil,
			wantCalls:   1,
		},
		{
			name:        "store error propagated",
			limit:       5,
			window:      time.Minute,
			key:         "key1",
			storeErr:    errStoreFailure,
			wantAllowed: false,
			wantErr:     errStoreFailure,
			wantCalls:   1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newMockStore()
			if tc.storeErr != nil {
				store.err = tc.storeErr
			} else if tc.storeCount > 0 {
				store.onIncrement = func(ctx context.Context, key string, window time.Duration) (int, error) {
					return tc.storeCount, nil
				}
			}

			limiter := ratelimit.New(store)
			allowed, err := limiter.Allow(context.Background(), tc.key, tc.limit, tc.window)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
			if allowed != tc.wantAllowed {
				t.Fatalf("expected allowed=%v, got %v", tc.wantAllowed, allowed)
			}
			if store.getCalls() != tc.wantCalls {
				t.Fatalf("expected %d store calls, got %d", tc.wantCalls, store.getCalls())
			}
		})
	}
}

func TestLimiter_Check(t *testing.T) {
	t.Parallel()

	errStoreFailure := errors.New("store offline")

	tests := []struct {
		name       string
		limit      int
		window     time.Duration
		key        string
		storeCount int
		storeErr   error
		wantResult *ratelimit.Result
		wantErr    error
		wantCalls  int
	}{
		{
			name:   "limit zero returns allowed with zero count and remaining",
			limit:  0,
			window: time.Minute,
			key:    "key1",
			wantResult: &ratelimit.Result{
				Allowed:   true,
				Count:     0,
				Limit:     0,
				Remaining: 0,
			},
			wantErr:   nil,
			wantCalls: 0,
		},
		{
			name:   "negative limit returns allowed with zero count and remaining",
			limit:  -3,
			window: time.Minute,
			key:    "key1",
			wantResult: &ratelimit.Result{
				Allowed:   true,
				Count:     0,
				Limit:     -3,
				Remaining: 0,
			},
			wantErr:   nil,
			wantCalls: 0,
		},
		{
			name:       "empty key returns ErrEmptyKey",
			limit:      5,
			window:     time.Minute,
			key:        "",
			wantResult: nil,
			wantErr:    ratelimit.ErrEmptyKey,
			wantCalls:  0,
		},
		{
			name:       "zero window returns ErrInvalidWindow",
			limit:      5,
			window:     0,
			key:        "key1",
			wantResult: nil,
			wantErr:    ratelimit.ErrInvalidWindow,
			wantCalls:  0,
		},
		{
			name:       "under limit computes remaining accurately",
			limit:      5,
			window:     time.Minute,
			key:        "key1",
			storeCount: 2,
			wantResult: &ratelimit.Result{
				Allowed:   true,
				Count:     2,
				Limit:     5,
				Remaining: 3,
			},
			wantErr:   nil,
			wantCalls: 1,
		},
		{
			name:       "at limit has zero remaining and allowed",
			limit:      5,
			window:     time.Minute,
			key:        "key1",
			storeCount: 5,
			wantResult: &ratelimit.Result{
				Allowed:   true,
				Count:     5,
				Limit:     5,
				Remaining: 0,
			},
			wantErr:   nil,
			wantCalls: 1,
		},
		{
			name:       "over limit has zero remaining and not allowed",
			limit:      5,
			window:     time.Minute,
			key:        "key1",
			storeCount: 8,
			wantResult: &ratelimit.Result{
				Allowed:   false,
				Count:     8,
				Limit:     5,
				Remaining: 0,
			},
			wantErr:   nil,
			wantCalls: 1,
		},
		{
			name:       "store error propagates",
			limit:      5,
			window:     time.Minute,
			key:        "key1",
			storeErr:   errStoreFailure,
			wantResult: nil,
			wantErr:    errStoreFailure,
			wantCalls:  1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newMockStore()
			if tc.storeErr != nil {
				store.err = tc.storeErr
			} else if tc.storeCount > 0 {
				store.onIncrement = func(ctx context.Context, key string, window time.Duration) (int, error) {
					return tc.storeCount, nil
				}
			}

			limiter := ratelimit.New(store)
			res, err := limiter.Check(context.Background(), tc.key, tc.limit, tc.window)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
			if tc.wantResult == nil {
				if res != nil {
					t.Fatalf("expected nil result, got %+v", res)
				}
			} else {
				if res == nil {
					t.Fatalf("expected non-nil result, got nil")
				}
				if *res != *tc.wantResult {
					t.Fatalf("expected result %+v, got %+v", *tc.wantResult, *res)
				}
			}
			if store.getCalls() != tc.wantCalls {
				t.Fatalf("expected %d store calls, got %d", tc.wantCalls, store.getCalls())
			}
		})
	}
}

func TestLimiter_NilStore(t *testing.T) {
	t.Parallel()

	// limit <= 0 should still succeed even with nil store
	nilLimiter := ratelimit.New(nil)
	if err := nilLimiter.Take(context.Background(), "k", 0, time.Minute); err != nil {
		t.Fatalf("expected nil error for bypassed limit on nil store, got %v", err)
	}

	allowed, err := nilLimiter.Allow(context.Background(), "k", 0, time.Minute)
	if err != nil || !allowed {
		t.Fatalf("expected true, nil for bypassed limit on nil store, got %v, %v", allowed, err)
	}

	res, err := nilLimiter.Check(context.Background(), "k", 0, time.Minute)
	if err != nil || res == nil || !res.Allowed {
		t.Fatalf("expected allowed result for bypassed limit on nil store, got %+v, %v", res, err)
	}

	// limit > 0 returns ErrNilStore
	if err := nilLimiter.Take(context.Background(), "k", 5, time.Minute); !errors.Is(err, ratelimit.ErrNilStore) {
		t.Fatalf("expected ErrNilStore from Take, got %v", err)
	}
	if _, err := nilLimiter.Allow(context.Background(), "k", 5, time.Minute); !errors.Is(err, ratelimit.ErrNilStore) {
		t.Fatalf("expected ErrNilStore from Allow, got %v", err)
	}
	if _, err := nilLimiter.Check(context.Background(), "k", 5, time.Minute); !errors.Is(err, ratelimit.ErrNilStore) {
		t.Fatalf("expected ErrNilStore from Check, got %v", err)
	}
}

func TestStoreFunc_Adapter(t *testing.T) {
	t.Parallel()

	var calledWithKey string
	var calledWithWindow time.Duration
	adapter := ratelimit.StoreFunc(func(ctx context.Context, key string, window time.Duration) (int, error) {
		calledWithKey = key
		calledWithWindow = window
		return 42, nil
	})

	limiter := ratelimit.New(adapter)
	res, err := limiter.Check(context.Background(), "test-store-func", 100, 10*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected allowed")
	}
	if res.Count != 42 {
		t.Fatalf("expected count 42, got %d", res.Count)
	}
	if calledWithKey != "test-store-func" {
		t.Fatalf("expected key 'test-store-func', got %q", calledWithKey)
	}
	if calledWithWindow != 10*time.Minute {
		t.Fatalf("expected window 10m, got %v", calledWithWindow)
	}
}

func TestKeyHelpers(t *testing.T) {
	t.Parallel()

	t.Run("KeyIP", func(t *testing.T) {
		tests := []struct {
			input string
			want  string
		}{
			{input: "192.0.2.1", want: "rl:ip:192.0.2.1"},
			{input: "  192.0.2.1  ", want: "rl:ip:192.0.2.1"},
			{input: "2001:db8::1", want: "rl:ip:2001:db8::1"},
			{input: "  2001:db8::1\t\n", want: "rl:ip:2001:db8::1"},
			{input: "", want: "rl:ip:"},
		}

		for _, tc := range tests {
			got := ratelimit.KeyIP(tc.input)
			if got != tc.want {
				t.Errorf("KeyIP(%q) = %q, want %q", tc.input, got, tc.want)
			}
		}
	})

	t.Run("KeyAuth", func(t *testing.T) {
		tests := []struct {
			input string
			want  string
		}{
			{input: "user@example.com", want: "rl:auth:user@example.com"},
			{input: "User@Example.COM", want: "rl:auth:user@example.com"},
			{input: "  Alice.Smith@Domain.Co  ", want: "rl:auth:alice.smith@domain.co"},
			{input: "", want: "rl:auth:"},
		}

		for _, tc := range tests {
			got := ratelimit.KeyAuth(tc.input)
			if got != tc.want {
				t.Errorf("KeyAuth(%q) = %q, want %q", tc.input, got, tc.want)
			}
		}
	})
}

func TestLimiter_Take_Concurrency_SingleKey(t *testing.T) {
	t.Parallel()

	store := newMockStore()
	limiter := ratelimit.New(store)

	const (
		limit       = 20
		concurrency = 50
		window      = 15 * time.Minute
		key         = "concurrent:key:single"
	)

	var (
		wg        sync.WaitGroup
		allowed   atomic.Int64
		exceeded  atomic.Int64
		otherErrs atomic.Int64
	)

	wg.Add(concurrency)
	for range concurrency {
		go func() {
			defer wg.Done()
			err := limiter.Take(context.Background(), key, limit, window)
			switch {
			case err == nil:
				allowed.Add(1)
			case errors.Is(err, ratelimit.ErrLimitExceeded):
				exceeded.Add(1)
			default:
				otherErrs.Add(1)
			}
		}()
	}

	wg.Wait()

	if allowed.Load() != limit {
		t.Errorf("expected %d allowed requests, got %d", limit, allowed.Load())
	}
	if exceeded.Load() != concurrency-limit {
		t.Errorf("expected %d exceeded requests, got %d", concurrency-limit, exceeded.Load())
	}
	if otherErrs.Load() != 0 {
		t.Errorf("expected 0 unexpected errors, got %d", otherErrs.Load())
	}
	if store.getCalls() != concurrency {
		t.Errorf("expected %d store calls, got %d", concurrency, store.getCalls())
	}
}

func TestLimiter_Take_Concurrency_MultipleKeys(t *testing.T) {
	t.Parallel()

	store := newMockStore()
	limiter := ratelimit.New(store)

	const (
		numKeys          = 5
		reqsPerKey       = 20
		limitPerKey      = 8
		window           = 10 * time.Minute
		expectedAllowed  = numKeys * limitPerKey
		expectedExceeded = numKeys * (reqsPerKey - limitPerKey)
	)

	var (
		wg       sync.WaitGroup
		allowed  atomic.Int64
		exceeded atomic.Int64
	)

	for k := range numKeys {
		keyName := fmt.Sprintf("concurrent:key:%d", k)
		for range reqsPerKey {
			wg.Add(1)
			go func(key string) {
				defer wg.Done()
				err := limiter.Take(context.Background(), key, limitPerKey, window)
				switch {
				case err == nil:
					allowed.Add(1)
				case errors.Is(err, ratelimit.ErrLimitExceeded):
					exceeded.Add(1)
				default:
					t.Errorf("unexpected error for key %s: %v", key, err)
				}
			}(keyName)
		}
	}

	wg.Wait()

	if allowed.Load() != expectedAllowed {
		t.Errorf("expected %d allowed requests across keys, got %d", expectedAllowed, allowed.Load())
	}
	if exceeded.Load() != expectedExceeded {
		t.Errorf("expected %d exceeded requests across keys, got %d", expectedExceeded, exceeded.Load())
	}
	if store.getCalls() != numKeys*reqsPerKey {
		t.Errorf("expected %d total store calls, got %d", numKeys*reqsPerKey, store.getCalls())
	}
}

func TestLimiter_ContextCancellation(t *testing.T) {
	t.Parallel()

	store := newMockStore()
	limiter := ratelimit.New(store)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := limiter.Take(ctx, "canceled-key", 5, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	_, err = limiter.Allow(ctx, "canceled-key", 5, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from Allow, got %v", err)
	}

	_, err = limiter.Check(ctx, "canceled-key", 5, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from Check, got %v", err)
	}
}
