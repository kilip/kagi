package kagi_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/adapter/memory"
	"github.com/kilip/kagi/internal/clock"
	"github.com/kilip/kagi/internal/crypto"
	"github.com/kilip/kagi/mock"
	"go.uber.org/mock/gomock"
)

// mockStores provides stub implementations for validation tests.
type mockUserStore struct{ kagi.UserStore }
type mockAccountStore struct{ kagi.AccountStore }
type mockSessionStore struct{ kagi.SessionStore }
type mockVerificationStore struct{ kagi.VerificationStore }
type mockRateLimitStore struct{ kagi.RateLimitStore }

func TestNew_Validation(t *testing.T) {
	validSecret := "a-very-long-master-secret-at-least-32-bytes-long"

	tests := []struct {
		name    string
		cfg     kagi.Config
		wantErr error
	}{
		{
			name: "valid config with safe defaults",
			cfg: kagi.Config{
				UserStore:         &mockUserStore{},
				AccountStore:      &mockAccountStore{},
				SessionStore:      &mockSessionStore{},
				VerificationStore: &mockVerificationStore{},
				RateLimitStore:    &mockRateLimitStore{},
				Secret:            validSecret,
			},
			wantErr: nil,
		},
		{
			name: "missing user store",
			cfg: kagi.Config{
				AccountStore:      &mockAccountStore{},
				SessionStore:      &mockSessionStore{},
				VerificationStore: &mockVerificationStore{},
				RateLimitStore:    &mockRateLimitStore{},
				Secret:            validSecret,
			},
			wantErr: kagi.ErrNilStore,
		},
		{
			name: "secret shorter than 32 bytes",
			cfg: kagi.Config{
				UserStore:         &mockUserStore{},
				AccountStore:      &mockAccountStore{},
				SessionStore:      &mockSessionStore{},
				VerificationStore: &mockVerificationStore{},
				RateLimitStore:    &mockRateLimitStore{},
				Secret:            "too-short",
			},
			wantErr: kagi.ErrWeakMasterSecret,
		},
		{
			name: "invalid renewal threshold (> 1)",
			cfg: kagi.Config{
				UserStore:         &mockUserStore{},
				AccountStore:      &mockAccountStore{},
				SessionStore:      &mockSessionStore{},
				VerificationStore: &mockVerificationStore{},
				RateLimitStore:    &mockRateLimitStore{},
				Secret:            validSecret,
				Session: kagi.SessionConfig{
					IdleTimeout:       7 * 24 * time.Hour,
					AbsoluteTimeout:   30 * 24 * time.Hour,
					RenewalThreshold:  1.5,
					Pending2FATimeout: 10 * time.Minute,
				},
			},
			wantErr: kagi.ErrInvalidConfig,
		},
		{
			name: "pending 2FA timeout exceeds idle timeout",
			cfg: kagi.Config{
				UserStore:         &mockUserStore{},
				AccountStore:      &mockAccountStore{},
				SessionStore:      &mockSessionStore{},
				VerificationStore: &mockVerificationStore{},
				RateLimitStore:    &mockRateLimitStore{},
				Secret:            validSecret,
				Session: kagi.SessionConfig{
					IdleTimeout:       5 * time.Minute,
					AbsoluteTimeout:   30 * 24 * time.Hour,
					RenewalThreshold:  0.5,
					Pending2FATimeout: 10 * time.Minute,
				},
			},
			wantErr: kagi.ErrInvalidConfig,
		},
		{
			name: "negative rate limit",
			cfg: kagi.Config{
				UserStore:         &mockUserStore{},
				AccountStore:      &mockAccountStore{},
				SessionStore:      &mockSessionStore{},
				VerificationStore: &mockVerificationStore{},
				RateLimitStore:    &mockRateLimitStore{},
				Secret:            validSecret,
				RateLimit: kagi.RateLimitConfig{
					SignInEmail: kagi.LimitRule{Limit: -1, Window: 15 * time.Minute},
				},
			},
			wantErr: kagi.ErrInvalidConfig,
		},
		{
			name: "negative rate limit window",
			cfg: kagi.Config{
				UserStore:         &mockUserStore{},
				AccountStore:      &mockAccountStore{},
				SessionStore:      &mockSessionStore{},
				VerificationStore: &mockVerificationStore{},
				RateLimitStore:    &mockRateLimitStore{},
				Secret:            validSecret,
				RateLimit: kagi.RateLimitConfig{
					SignInIP: kagi.LimitRule{Limit: 10, Window: -1 * time.Minute},
				},
			},
			wantErr: kagi.ErrInvalidConfig,
		},
		{
			name: "rate limit with zero window",
			cfg: kagi.Config{
				UserStore:         &mockUserStore{},
				AccountStore:      &mockAccountStore{},
				SessionStore:      &mockSessionStore{},
				VerificationStore: &mockVerificationStore{},
				RateLimitStore:    &mockRateLimitStore{},
				Secret:            validSecret,
				RateLimit: kagi.RateLimitConfig{
					SignInEmail: kagi.LimitRule{Limit: 5, Window: 0},
				},
			},
			wantErr: kagi.ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance, err := kagi.New(tt.cfg)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				if instance != nil {
					t.Fatalf("expected nil instance on error, got %v", instance)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if instance == nil {
				t.Fatal("expected non-nil Kagi instance")
			}
			if instance.Credentials == nil || instance.Sessions == nil || instance.OTP == nil || instance.OAuth == nil {
				t.Fatal("expected initialized domain services")
			}
		})
	}
}

func TestNew_ClockInjection(t *testing.T) {
	validSecret := "a-very-long-master-secret-at-least-32-bytes-long"
	realClock := clock.RealClock{}

	cfg := kagi.Config{
		UserStore:         &mockUserStore{},
		AccountStore:      &mockAccountStore{},
		SessionStore:      &mockSessionStore{},
		VerificationStore: &mockVerificationStore{},
		RateLimitStore:    &mockRateLimitStore{},
		Secret:            validSecret,
		Clock:             realClock,
	}

	instance, err := kagi.New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if instance == nil {
		t.Fatal("expected non-nil Kagi instance")
	}
}

func TestNew_FakeClockIntegration(t *testing.T) {
	validSecret := "a-very-long-master-secret-at-least-32-bytes-long"
	initialTime := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	fakeClock := clock.NewFake(initialTime)

	cfg := kagi.Config{
		UserStore:         &mockUserStore{},
		AccountStore:      &mockAccountStore{},
		SessionStore:      &mockSessionStore{},
		VerificationStore: &mockVerificationStore{},
		RateLimitStore:    &mockRateLimitStore{},
		Secret:            validSecret,
		Clock:             fakeClock,
	}

	instance, err := kagi.New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if instance == nil {
		t.Fatal("expected non-nil Kagi instance")
	}

	// Verify FakeClock is injected and starts at initial time
	if !cfg.Clock.Now().Equal(initialTime) {
		t.Fatalf("expected clock to be %v, got %v", initialTime, cfg.Clock.Now())
	}

	// Verify advancing time deterministically through the injected FakeClock
	advanceDuration := 45 * time.Minute
	fakeClock.Advance(advanceDuration)

	expectedTime := initialTime.Add(advanceDuration)
	if !cfg.Clock.Now().Equal(expectedTime) {
		t.Fatalf("expected clock to advance to %v, got %v", expectedTime, cfg.Clock.Now())
	}

	if elapsed := cfg.Clock.Since(initialTime); elapsed != advanceDuration {
		t.Fatalf("expected elapsed duration %v, got %v", advanceDuration, elapsed)
	}

	futureTarget := expectedTime.Add(15 * time.Minute)
	if remaining := cfg.Clock.Until(futureTarget); remaining != 15*time.Minute {
		t.Fatalf("expected remaining duration %v, got %v", 15*time.Minute, remaining)
	}
}

func TestNew_RateLimitDefaults(t *testing.T) {
	validSecret := "a-very-long-master-secret-at-least-32-bytes-long"

	t.Run("default rate limits applied when zero-valued", func(t *testing.T) {
		cfg := kagi.Config{
			UserStore:         &mockUserStore{},
			AccountStore:      &mockAccountStore{},
			SessionStore:      &mockSessionStore{},
			VerificationStore: &mockVerificationStore{},
			RateLimitStore:    &mockRateLimitStore{},
			Secret:            validSecret,
		}

		k, err := kagi.New(cfg)
		if err != nil {
			t.Fatalf("kagi.New failed: %v", err)
		}
		limiter, rlCfg := kagi.CredentialServiceRateLimiterForTest(k.Credentials)
		if limiter == nil {
			t.Fatal("expected non-nil limiter when rate limiting enabled by default")
		}
		expectedDefaults := kagi.DefaultRateLimitConfig()
		if rlCfg.SignInEmail != expectedDefaults.SignInEmail {
			t.Errorf("expected SignInEmail %+v, got %+v", expectedDefaults.SignInEmail, rlCfg.SignInEmail)
		}
		if rlCfg.SignInIP != expectedDefaults.SignInIP {
			t.Errorf("expected SignInIP %+v, got %+v", expectedDefaults.SignInIP, rlCfg.SignInIP)
		}
	})

	t.Run("custom rate limits preserved", func(t *testing.T) {
		customCfg := kagi.RateLimitConfig{
			SignInEmail: kagi.LimitRule{Limit: 10, Window: 30 * time.Minute},
			SignInIP:    kagi.LimitRule{Limit: 100, Window: 30 * time.Minute},
		}
		cfg := kagi.Config{
			UserStore:         &mockUserStore{},
			AccountStore:      &mockAccountStore{},
			SessionStore:      &mockSessionStore{},
			VerificationStore: &mockVerificationStore{},
			RateLimitStore:    &mockRateLimitStore{},
			Secret:            validSecret,
			RateLimit:         customCfg,
		}

		k, err := kagi.New(cfg)
		if err != nil {
			t.Fatalf("kagi.New failed: %v", err)
		}
		limiter, rlCfg := kagi.CredentialServiceRateLimiterForTest(k.Credentials)
		if limiter == nil {
			t.Fatal("expected non-nil limiter")
		}
		if rlCfg.SignInEmail != customCfg.SignInEmail {
			t.Errorf("expected SignInEmail %+v, got %+v", customCfg.SignInEmail, rlCfg.SignInEmail)
		}
		if rlCfg.SignInIP != customCfg.SignInIP {
			t.Errorf("expected SignInIP %+v, got %+v", customCfg.SignInIP, rlCfg.SignInIP)
		}
	})

	t.Run("disabled rate limiting produces nil limiter", func(t *testing.T) {
		cfg := kagi.Config{
			UserStore:         &mockUserStore{},
			AccountStore:      &mockAccountStore{},
			SessionStore:      &mockSessionStore{},
			VerificationStore: &mockVerificationStore{},
			RateLimitStore:    &mockRateLimitStore{},
			Secret:            validSecret,
			RateLimit: kagi.RateLimitConfig{
				Disabled: true,
			},
		}

		k, err := kagi.New(cfg)
		if err != nil {
			t.Fatalf("kagi.New failed: %v", err)
		}
		limiter, rlCfg := kagi.CredentialServiceRateLimiterForTest(k.Credentials)
		if limiter != nil {
			t.Fatalf("expected nil limiter when disabled, got %v", limiter)
		}
		if !rlCfg.Disabled {
			t.Fatal("expected Disabled == true")
		}
	})
}

type configurableCleanupSessionStore struct {
	mockSessionStore
	deleteFn func(ctx context.Context, batchSize int) (int, error)
	calls    []int
}

func (s *configurableCleanupSessionStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	s.calls = append(s.calls, batchSize)
	if s.deleteFn != nil {
		return s.deleteFn(ctx, batchSize)
	}
	return 0, nil
}

type configurableCleanupVerificationStore struct {
	mockVerificationStore
	deleteFn func(ctx context.Context, batchSize int) (int, error)
	calls    []int
}

func (v *configurableCleanupVerificationStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	v.calls = append(v.calls, batchSize)
	if v.deleteFn != nil {
		return v.deleteFn(ctx, batchSize)
	}
	return 0, nil
}

type configurableCleanupRateLimitStore struct {
	mockRateLimitStore
	deleteFn func(ctx context.Context, batchSize int) (int, error)
	calls    []int
}

func (r *configurableCleanupRateLimitStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	r.calls = append(r.calls, batchSize)
	if r.deleteFn != nil {
		return r.deleteFn(ctx, batchSize)
	}
	return 0, nil
}

func TestKagi_Cleanup(t *testing.T) {
	validSecret := "a-very-long-master-secret-at-least-32-bytes-long"

	t.Run("multi-batch draining across stores", func(t *testing.T) {
		// Mock store draining 1,200 records in batches of 500 (500, 500, 200).
		sessionRemaining := 1200
		sessionStore := &configurableCleanupSessionStore{
			deleteFn: func(ctx context.Context, batchSize int) (int, error) {
				if sessionRemaining >= batchSize {
					sessionRemaining -= batchSize
					return batchSize, nil
				}
				deleted := sessionRemaining
				sessionRemaining = 0
				return deleted, nil
			},
		}

		// Verification store has 750 records (500, 250).
		verifRemaining := 750
		verificationStore := &configurableCleanupVerificationStore{
			deleteFn: func(ctx context.Context, batchSize int) (int, error) {
				if verifRemaining >= batchSize {
					verifRemaining -= batchSize
					return batchSize, nil
				}
				deleted := verifRemaining
				verifRemaining = 0
				return deleted, nil
			},
		}

		// Rate limit store has 500 records exactly (500, 0).
		rateRemaining := 500
		rateLimitStore := &configurableCleanupRateLimitStore{
			deleteFn: func(ctx context.Context, batchSize int) (int, error) {
				if rateRemaining >= batchSize {
					rateRemaining -= batchSize
					return batchSize, nil
				}
				deleted := rateRemaining
				rateRemaining = 0
				return deleted, nil
			},
		}

		instance, err := kagi.New(kagi.Config{
			UserStore:         &mockUserStore{},
			AccountStore:      &mockAccountStore{},
			SessionStore:      sessionStore,
			VerificationStore: verificationStore,
			RateLimitStore:    rateLimitStore,
			Secret:            validSecret,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := instance.Cleanup(context.Background()); err != nil {
			t.Fatalf("Cleanup failed: %v", err)
		}

		if len(sessionStore.calls) != 3 {
			t.Errorf("expected 3 session delete calls (500, 500, 200), got %d", len(sessionStore.calls))
		}
		if len(verificationStore.calls) != 2 {
			t.Errorf("expected 2 verification delete calls (500, 250), got %d", len(verificationStore.calls))
		}
		if len(rateLimitStore.calls) != 2 {
			t.Errorf("expected 2 rate limit delete calls (500, 0), got %d", len(rateLimitStore.calls))
		}
		if sessionRemaining != 0 || verifRemaining != 0 || rateRemaining != 0 {
			t.Errorf("expected all expired records drained, got rem: sess=%d, verif=%d, rl=%d",
				sessionRemaining, verifRemaining, rateRemaining)
		}
	})

	t.Run("context cancellation stops mid-batch", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		callCount := 0

		sessionStore := &configurableCleanupSessionStore{
			deleteFn: func(c context.Context, batchSize int) (int, error) {
				callCount++
				if callCount == 1 {
					cancel()
					return batchSize, nil
				}
				return 0, nil
			},
		}
		verificationStore := &configurableCleanupVerificationStore{}
		rateLimitStore := &configurableCleanupRateLimitStore{}

		instance, err := kagi.New(kagi.Config{
			UserStore:         &mockUserStore{},
			AccountStore:      &mockAccountStore{},
			SessionStore:      sessionStore,
			VerificationStore: verificationStore,
			RateLimitStore:    rateLimitStore,
			Secret:            validSecret,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = instance.Cleanup(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}

		if callCount != 1 {
			t.Errorf("expected exactly 1 call before cancellation check, got %d", callCount)
		}
		if len(verificationStore.calls) != 0 {
			t.Errorf("expected verification store to not be called, got %d calls", len(verificationStore.calls))
		}
		if len(rateLimitStore.calls) != 0 {
			t.Errorf("expected rate limit store to not be called, got %d calls", len(rateLimitStore.calls))
		}
	})

	t.Run("context already canceled returns immediately", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		sessionStore := &configurableCleanupSessionStore{}
		verificationStore := &configurableCleanupVerificationStore{}
		rateLimitStore := &configurableCleanupRateLimitStore{}

		instance, err := kagi.New(kagi.Config{
			UserStore:         &mockUserStore{},
			AccountStore:      &mockAccountStore{},
			SessionStore:      sessionStore,
			VerificationStore: verificationStore,
			RateLimitStore:    rateLimitStore,
			Secret:            validSecret,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = instance.Cleanup(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if len(sessionStore.calls) != 0 || len(verificationStore.calls) != 0 || len(rateLimitStore.calls) != 0 {
			t.Fatalf("expected 0 store calls when context already canceled")
		}
	})

	t.Run("error aggregation with errors.Join", func(t *testing.T) {
		errSession := errors.New("session store db error")
		errRateLimit := errors.New("rate limit store connection timeout")

		sessionStore := &configurableCleanupSessionStore{
			deleteFn: func(ctx context.Context, batchSize int) (int, error) {
				return 0, errSession
			},
		}
		verificationStore := &configurableCleanupVerificationStore{
			deleteFn: func(ctx context.Context, batchSize int) (int, error) {
				return 10, nil // deleted < batchSize, succeeds
			},
		}
		rateLimitStore := &configurableCleanupRateLimitStore{
			deleteFn: func(ctx context.Context, batchSize int) (int, error) {
				return 0, errRateLimit
			},
		}

		instance, err := kagi.New(kagi.Config{
			UserStore:         &mockUserStore{},
			AccountStore:      &mockAccountStore{},
			SessionStore:      sessionStore,
			VerificationStore: verificationStore,
			RateLimitStore:    rateLimitStore,
			Secret:            validSecret,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = instance.Cleanup(context.Background())
		if err == nil {
			t.Fatalf("expected composite error, got nil")
		}

		if !errors.Is(err, errSession) {
			t.Errorf("expected err to contain errSession: %v", err)
		}
		if !errors.Is(err, errRateLimit) {
			t.Errorf("expected err to contain errRateLimit: %v", err)
		}

		// Ensure verification store was not skipped despite session error
		if len(verificationStore.calls) != 1 {
			t.Errorf("expected verification store to be called despite session failure, got %d calls", len(verificationStore.calls))
		}
		if len(rateLimitStore.calls) != 1 {
			t.Errorf("expected rate limit store to be called, got %d calls", len(rateLimitStore.calls))
		}
	})

	t.Run("idempotency with zero expired records", func(t *testing.T) {
		sessionStore := &configurableCleanupSessionStore{}
		verificationStore := &configurableCleanupVerificationStore{}
		rateLimitStore := &configurableCleanupRateLimitStore{}

		instance, err := kagi.New(kagi.Config{
			UserStore:         &mockUserStore{},
			AccountStore:      &mockAccountStore{},
			SessionStore:      sessionStore,
			VerificationStore: verificationStore,
			RateLimitStore:    rateLimitStore,
			Secret:            validSecret,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i := 0; i < 3; i++ {
			if err := instance.Cleanup(context.Background()); err != nil {
				t.Fatalf("run %d failed: %v", i+1, err)
			}
		}

		// Each store should be queried once per Cleanup invocation
		if len(sessionStore.calls) != 3 {
			t.Errorf("expected 3 calls, got %d", len(sessionStore.calls))
		}
		if len(verificationStore.calls) != 3 {
			t.Errorf("expected 3 calls, got %d", len(verificationStore.calls))
		}
		if len(rateLimitStore.calls) != 3 {
			t.Errorf("expected 3 calls, got %d", len(rateLimitStore.calls))
		}
	})

	t.Run("configurable batch size vs default", func(t *testing.T) {
		tests := []struct {
			name              string
			configuredBatch   int
			expectedBatchSize int
		}{
			{
				name:              "default when 0",
				configuredBatch:   0,
				expectedBatchSize: kagi.DefaultCleanupBatchSize,
			},
			{
				name:              "default when negative",
				configuredBatch:   -10,
				expectedBatchSize: kagi.DefaultCleanupBatchSize,
			},
			{
				name:              "custom positive batch size",
				configuredBatch:   100,
				expectedBatchSize: 100,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				sessionStore := &configurableCleanupSessionStore{}
				verificationStore := &configurableCleanupVerificationStore{}
				rateLimitStore := &configurableCleanupRateLimitStore{}

				instance, err := kagi.New(kagi.Config{
					UserStore:         &mockUserStore{},
					AccountStore:      &mockAccountStore{},
					SessionStore:      sessionStore,
					VerificationStore: verificationStore,
					RateLimitStore:    rateLimitStore,
					Secret:            validSecret,
					CleanupBatchSize:  tc.configuredBatch,
				})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if err := instance.Cleanup(context.Background()); err != nil {
					t.Fatalf("unexpected cleanup error: %v", err)
				}

				if len(sessionStore.calls) == 0 || sessionStore.calls[0] != tc.expectedBatchSize {
					t.Errorf("expected batch size %d, got %v", tc.expectedBatchSize, sessionStore.calls)
				}
				if len(verificationStore.calls) == 0 || verificationStore.calls[0] != tc.expectedBatchSize {
					t.Errorf("expected batch size %d, got %v", tc.expectedBatchSize, verificationStore.calls)
				}
				if len(rateLimitStore.calls) == 0 || rateLimitStore.calls[0] != tc.expectedBatchSize {
					t.Errorf("expected batch size %d, got %v", tc.expectedBatchSize, rateLimitStore.calls)
				}
			})
		}
	})
}

func TestKagi_RunCleanup(t *testing.T) {
	validSecret := "a-very-long-master-secret-at-least-32-bytes-long"

	newTestKagi := func(t *testing.T, sStore kagi.SessionStore, vStore kagi.VerificationStore, rStore kagi.RateLimitStore) *kagi.Kagi {
		t.Helper()
		if sStore == nil {
			sStore = &configurableCleanupSessionStore{}
		}
		if vStore == nil {
			vStore = &configurableCleanupVerificationStore{}
		}
		if rStore == nil {
			rStore = &configurableCleanupRateLimitStore{}
		}
		inst, err := kagi.New(kagi.Config{
			UserStore:         &mockUserStore{},
			AccountStore:      &mockAccountStore{},
			SessionStore:      sStore,
			VerificationStore: vStore,
			RateLimitStore:    rStore,
			Secret:            validSecret,
		})
		if err != nil {
			t.Fatalf("failed to create kagi instance: %v", err)
		}
		return inst
	}

	t.Run("ticker triggers Cleanup", func(t *testing.T) {
		cleanupDone := make(chan struct{}, 10)
		sessionStore := &configurableCleanupSessionStore{
			deleteFn: func(ctx context.Context, batchSize int) (int, error) {
				select {
				case cleanupDone <- struct{}{}:
				default:
				}
				return 0, nil
			},
		}
		instance := newTestKagi(t, sessionStore, nil, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		instance.RunCleanup(ctx, 10*time.Millisecond)

		select {
		case <-cleanupDone:
			// cleanup was triggered by ticker
		case <-time.After(500 * time.Millisecond):
			t.Fatal("expected cleanup to be triggered by ticker, timed out")
		}
	})

	t.Run("stops on cancel", func(t *testing.T) {
		var callCount atomic.Int32
		sessionStore := &configurableCleanupSessionStore{
			deleteFn: func(ctx context.Context, batchSize int) (int, error) {
				callCount.Add(1)
				return 0, nil
			},
		}
		instance := newTestKagi(t, sessionStore, nil, nil)

		ctx, cancel := context.WithCancel(context.Background())

		instance.RunCleanup(ctx, 10*time.Millisecond)

		// Wait until at least 1 cleanup runs
		deadline := time.Now().Add(500 * time.Millisecond)
		for callCount.Load() == 0 {
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for first cleanup call")
			}
			time.Sleep(5 * time.Millisecond)
		}

		// Cancel context and verify no more cleanups occur
		cancel()
		snapshot := callCount.Load()

		// Sleep across multiple intervals to ensure goroutine stopped
		time.Sleep(50 * time.Millisecond)

		// Goroutine might have been midway through one call when canceled, so allow at most +1
		if after := callCount.Load(); after > snapshot+1 {
			t.Errorf("expected goroutine to stop after cancel, calls grew from %d to %d", snapshot, after)
		}
	})

	t.Run("invalid interval", func(t *testing.T) {
		intervals := []struct {
			name     string
			interval time.Duration
		}{
			{name: "zero interval", interval: 0},
			{name: "negative interval", interval: -10 * time.Millisecond},
		}

		for _, tc := range intervals {
			t.Run(tc.name, func(t *testing.T) {
				var callCount atomic.Int32
				sessionStore := &configurableCleanupSessionStore{
					deleteFn: func(ctx context.Context, batchSize int) (int, error) {
						callCount.Add(1)
						return 0, nil
					},
				}
				instance := newTestKagi(t, sessionStore, nil, nil)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				// Should return immediately without panicking or spawning a worker
				instance.RunCleanup(ctx, tc.interval)

				time.Sleep(30 * time.Millisecond)
				if calls := callCount.Load(); calls != 0 {
					t.Fatalf("expected 0 calls for interval %v, got %d", tc.interval, calls)
				}
			})
		}
	})

	t.Run("pre-canceled context", func(t *testing.T) {
		var callCount atomic.Int32
		sessionStore := &configurableCleanupSessionStore{
			deleteFn: func(ctx context.Context, batchSize int) (int, error) {
				callCount.Add(1)
				return 0, nil
			},
		}
		instance := newTestKagi(t, sessionStore, nil, nil)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // pre-cancel before calling RunCleanup

		instance.RunCleanup(ctx, 10*time.Millisecond)

		time.Sleep(30 * time.Millisecond)
		if calls := callCount.Load(); calls != 0 {
			t.Fatalf("expected 0 calls for pre-canceled context, got %d", calls)
		}
	})
}

func TestCredentialService_WiringAndDefaults(t *testing.T) {
	userStore := &mockUserStore{}
	accountStore := &mockAccountStore{}
	fakeClk := clock.NewFake(time.Now())

	t.Run("NewCredentialService with explicit dependencies", func(t *testing.T) {
		pwdCfg := kagi.PasswordConfig{
			MinLength:   10,
			MaxLength:   64,
			Memory:      32 * 1024,
			Iterations:  2,
			Parallelism: 1,
			SaltLength:  16,
			KeyLength:   32,
		}
		svc := kagi.NewCredentialService(userStore, accountStore, pwdCfg, fakeClk)
		if svc == nil {
			t.Fatal("expected non-nil CredentialService")
		}

		gotUsers, gotAccounts, gotPwd, gotClk := kagi.CredentialServiceDependenciesForTest(svc)
		if gotUsers != userStore {
			t.Errorf("expected userStore %v, got %v", userStore, gotUsers)
		}
		if gotAccounts != accountStore {
			t.Errorf("expected accountStore %v, got %v", accountStore, gotAccounts)
		}
		if gotPwd != pwdCfg {
			t.Errorf("expected password config %+v, got %+v", pwdCfg, gotPwd)
		}
		if gotClk != fakeClk {
			t.Errorf("expected clock %v, got %v", fakeClk, gotClk)
		}
	})

	t.Run("NewCredentialService with zero-value password config and nil clock", func(t *testing.T) {
		svc := kagi.NewCredentialService(userStore, accountStore, kagi.PasswordConfig{}, nil)
		if svc == nil {
			t.Fatal("expected non-nil CredentialService")
		}

		gotUsers, gotAccounts, gotPwd, gotClk := kagi.CredentialServiceDependenciesForTest(svc)
		if gotUsers != userStore {
			t.Errorf("expected userStore %v, got %v", userStore, gotUsers)
		}
		if gotAccounts != accountStore {
			t.Errorf("expected accountStore %v, got %v", accountStore, gotAccounts)
		}
		expectedPwd := kagi.DefaultPasswordConfig()
		if gotPwd != expectedPwd {
			t.Errorf("expected default password config %+v, got %+v", expectedPwd, gotPwd)
		}
		if _, ok := gotClk.(clock.RealClock); !ok {
			t.Errorf("expected clock.RealClock, got %T", gotClk)
		}
	})

	t.Run("kagi.New wires CredentialService with injected dependencies and defaults", func(t *testing.T) {
		cfg := kagi.Config{
			UserStore:         userStore,
			AccountStore:      accountStore,
			SessionStore:      &mockSessionStore{},
			VerificationStore: &mockVerificationStore{},
			RateLimitStore:    &mockRateLimitStore{},
			Secret:            "a-very-long-master-secret-at-least-32-bytes-long",
			Clock:             fakeClk,
		}

		instance, err := kagi.New(cfg)
		if err != nil {
			t.Fatalf("unexpected error from kagi.New: %v", err)
		}
		if instance.Credentials == nil {
			t.Fatal("expected non-nil instance.Credentials")
		}

		gotUsers, gotAccounts, gotPwd, gotClk := kagi.CredentialServiceDependenciesForTest(instance.Credentials)
		if gotUsers != userStore {
			t.Errorf("expected injected userStore %v, got %v", userStore, gotUsers)
		}
		if gotAccounts != accountStore {
			t.Errorf("expected injected accountStore %v, got %v", accountStore, gotAccounts)
		}
		expectedPwd := kagi.DefaultPasswordConfig()
		if gotPwd != expectedPwd {
			t.Errorf("expected default password config %+v, got %+v", expectedPwd, gotPwd)
		}
		if gotClk != fakeClk {
			t.Errorf("expected injected fakeClk %v, got %v", fakeClk, gotClk)
		}
		if instance.Sessions == nil {
			t.Fatal("expected non-nil instance.Sessions")
		}
		gotSessions := kagi.CredentialServiceSessionServiceForTest(instance.Credentials)
		if gotSessions != instance.Sessions {
			t.Errorf("expected CredentialService to have SessionService %v, got %v", instance.Sessions, gotSessions)
		}
	})
}

// inMemorySecondaryStorage implements kagi.SecondaryStorage for integration testing.
type inMemorySecondaryStorage struct {
	mu       sync.RWMutex
	sessions map[string]*kagi.Session
	clock    clock.Clock
}

var _ kagi.SecondaryStorage = (*inMemorySecondaryStorage)(nil)

func newInMemorySecondaryStorage(clk clock.Clock) *inMemorySecondaryStorage {
	return &inMemorySecondaryStorage{
		sessions: make(map[string]*kagi.Session),
		clock:    clk,
	}
}

func (s *inMemorySecondaryStorage) GetSession(ctx context.Context, tokenHash string) (*kagi.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, exists := s.sessions[tokenHash]
	if !exists {
		return nil, nil // Cache miss: (nil, nil) per ADR-0007 / ADR-0014
	}

	if s.clock != nil && !sess.ExpiresAt.After(s.clock.Now().UTC()) {
		return nil, nil // Expired: treated as cache miss per ADR-0010
	}

	cp := *sess
	return &cp, nil
}

func (s *inMemorySecondaryStorage) SetSession(ctx context.Context, session *kagi.Session, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if session == nil || session.Pending2FA {
		return nil // Active-only session caching; pending-2FA prohibited (ADR-0014 §4)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *session
	s.sessions[session.TokenHash] = &cp
	return nil
}

func (s *inMemorySecondaryStorage) DeleteSession(ctx context.Context, tokenHash string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, tokenHash)
	return nil
}

func (s *inMemorySecondaryStorage) DeleteSessions(ctx context.Context, tokenHashes []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, th := range tokenHashes {
		delete(s.sessions, th)
	}
	return nil
}

func (s *inMemorySecondaryStorage) IncrementRateLimit(ctx context.Context, key string, window time.Duration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 1, nil
}

func TestKagi_SignInSignOutLifecycle(t *testing.T) {
	fixedTime := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	validSecret := "a-very-long-master-secret-at-least-32-bytes-long"

	t.Run("complete SignUp -> SignIn -> SignOut lifecycle with secondary storage", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		fakeClk := clock.NewFake(fixedTime)
		memStores := memory.NewStores(memory.WithClock(fakeClk))
		secStorage := newInMemorySecondaryStorage(fakeClk)

		cfg := kagi.Config{
			UserStore:         memStores.User,
			AccountStore:      memStores.Account,
			SessionStore:      memStores.Session,
			VerificationStore: memStores.Verification,
			RateLimitStore:    memStores.RateLimit,
			SecondaryStorage:  secStorage,
			Secret:            validSecret,
			Password:          fastPasswordConfig(),
			Clock:             fakeClk,
		}

		k, err := kagi.New(cfg)
		if err != nil {
			t.Fatalf("kagi.New failed: %v", err)
		}

		// 1. User registers with SignUp
		signUpIn := kagi.SignUpInput{
			Email:    "alice@example.com",
			Password: "ValidPassword123!",
			Name:     "Alice Smith",
		}
		user, err := k.Credentials.SignUp(ctx, signUpIn)
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}
		if user.ID == "" {
			t.Fatal("expected registered user ID to be non-empty")
		}
		if user.Email != "alice@example.com" {
			t.Fatalf("expected email %q, got %q", "alice@example.com", user.Email)
		}

		// 2. User authenticates with SignIn -> gets AuthResult
		signInIn := kagi.SignInInput{
			Email:     "alice@example.com",
			Password:  "ValidPassword123!",
			IPAddress: "192.168.1.100",
			UserAgent: "Mozilla/5.0 TestBrowser",
		}
		authResult, err := k.Credentials.SignIn(ctx, signInIn)
		if err != nil {
			t.Fatalf("SignIn failed: %v", err)
		}
		if authResult == nil {
			t.Fatal("expected non-nil AuthResult")
		}

		// 3. Check AuthResult: 43-character RawToken, Session.UserID, Session.Pending2FA == false, Session.ExpiresAt
		if authResult.User == nil || authResult.User.ID != user.ID {
			t.Errorf("AuthResult.User mismatch: got %+v, want ID %q", authResult.User, user.ID)
		}
		if len(authResult.RawToken) != 43 {
			t.Errorf("expected 43-character RawToken, got length %d", len(authResult.RawToken))
		}
		if err := crypto.ValidateSessionTokenFormat(authResult.RawToken); err != nil {
			t.Errorf("expected URL-safe session token, got error: %v", err)
		}
		if authResult.Session == nil {
			t.Fatal("expected non-nil AuthResult.Session")
		}
		if authResult.Session.UserID != user.ID {
			t.Errorf("Session.UserID mismatch: got %q, want %q", authResult.Session.UserID, user.ID)
		}
		if authResult.Session.Pending2FA {
			t.Errorf("expected Pending2FA == false for standard sign-in, got true")
		}
		expectedExpiresAt := fixedTime.Add(kagi.DefaultSessionConfig().IdleTimeout)
		if !authResult.Session.ExpiresAt.Equal(expectedExpiresAt) {
			t.Errorf("Session.ExpiresAt mismatch: got %v, want %v", authResult.Session.ExpiresAt, expectedExpiresAt)
		}

		// 4. Verify session exists in SessionStore.GetByTokenHash
		tokenHash := crypto.HashToken(authResult.RawToken)
		storedSession, err := memStores.Session.GetByTokenHash(ctx, tokenHash)
		if err != nil {
			t.Fatalf("SessionStore.GetByTokenHash failed: %v", err)
		}
		if storedSession.ID != authResult.Session.ID {
			t.Errorf("stored session ID mismatch: got %q, want %q", storedSession.ID, authResult.Session.ID)
		}
		if storedSession.UserID != user.ID {
			t.Errorf("stored session UserID mismatch: got %q, want %q", storedSession.UserID, user.ID)
		}

		// 5. With SecondaryStorage: verify session was cached
		cachedSession, err := secStorage.GetSession(ctx, tokenHash)
		if err != nil {
			t.Fatalf("SecondaryStorage.GetSession failed: %v", err)
		}
		if cachedSession == nil {
			t.Fatal("expected session to be cached in SecondaryStorage, got nil")
		}
		if cachedSession.ID != authResult.Session.ID {
			t.Errorf("cached session ID mismatch: got %q, want %q", cachedSession.ID, authResult.Session.ID)
		}
		if cachedSession.UserID != user.ID {
			t.Errorf("cached session UserID mismatch: got %q, want %q", cachedSession.UserID, user.ID)
		}

		// 6. SignOut via k.Sessions.SignOut(ctx, authResult.RawToken): succeeds
		err = k.Sessions.SignOut(ctx, authResult.RawToken)
		if err != nil {
			t.Fatalf("SignOut failed: %v", err)
		}

		// 7. Verify session deleted from SessionStore.GetByTokenHash (returns ErrSessionNotFound)
		_, err = memStores.Session.GetByTokenHash(ctx, tokenHash)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound from SessionStore after SignOut, got %v", err)
		}

		// 8. Verify session evicted from SecondaryStorage (GetSession returns (nil, nil))
		cachedAfterSignOut, err := secStorage.GetSession(ctx, tokenHash)
		if err != nil {
			t.Fatalf("SecondaryStorage.GetSession after SignOut returned error: %v", err)
		}
		if cachedAfterSignOut != nil {
			t.Errorf("expected session evicted from SecondaryStorage, got %+v", cachedAfterSignOut)
		}

		// 9. Subsequent SignOut with same token returns ErrSessionNotFound
		err = k.Sessions.SignOut(ctx, authResult.RawToken)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound on subsequent SignOut, got %v", err)
		}
	})

	t.Run("2FA pending session lifecycle and secondary storage isolation", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		fakeClk := clock.NewFake(fixedTime)
		memStores := memory.NewStores(memory.WithClock(fakeClk))
		secStorage := newInMemorySecondaryStorage(fakeClk)

		cfg := kagi.Config{
			UserStore:         memStores.User,
			AccountStore:      memStores.Account,
			SessionStore:      memStores.Session,
			VerificationStore: memStores.Verification,
			RateLimitStore:    memStores.RateLimit,
			SecondaryStorage:  secStorage,
			Secret:            validSecret,
			Password:          fastPasswordConfig(),
			Clock:             fakeClk,
		}

		k, err := kagi.New(cfg)
		if err != nil {
			t.Fatalf("kagi.New failed: %v", err)
		}

		// Register user
		user, err := k.Credentials.SignUp(ctx, kagi.SignUpInput{
			Email:    "bob@example.com",
			Password: "BobPassword123!",
			Name:     "Bob Jones",
		})
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}

		// Enable TwoFactorEnabled on user
		user.TwoFactorEnabled = true
		if err := memStores.User.Update(ctx, user); err != nil {
			t.Fatalf("UserStore.Update failed: %v", err)
		}

		// Authenticate user with 2FA enabled
		authResult, err := k.Credentials.SignIn(ctx, kagi.SignInInput{
			Email:     "bob@example.com",
			Password:  "BobPassword123!",
			IPAddress: "10.0.0.1",
			UserAgent: "MobileApp/2.0",
		})
		if err != nil {
			t.Fatalf("SignIn failed: %v", err)
		}
		if authResult == nil {
			t.Fatal("expected non-nil AuthResult")
		}

		// AuthResult.Session.Pending2FA == true, lifetime 10 minutes (Pending2FATimeout)
		if authResult.Session == nil {
			t.Fatal("expected non-nil Session in AuthResult")
		}
		if !authResult.Session.Pending2FA {
			t.Errorf("expected AuthResult.Session.Pending2FA == true, got false")
		}
		expected2FAExpiresAt := fixedTime.Add(kagi.DefaultSessionConfig().Pending2FATimeout)
		if !authResult.Session.ExpiresAt.Equal(expected2FAExpiresAt) {
			t.Errorf("expected 2FA session lifetime to expire at %v, got %v", expected2FAExpiresAt, authResult.Session.ExpiresAt)
		}

		// Check 43-character URL-safe raw token
		if len(authResult.RawToken) != 43 {
			t.Errorf("expected 43-character RawToken, got length %d", len(authResult.RawToken))
		}
		if err := crypto.ValidateSessionTokenFormat(authResult.RawToken); err != nil {
			t.Errorf("expected URL-safe token, got %v", err)
		}

		tokenHash := crypto.HashToken(authResult.RawToken)

		// Verify session stored in primary SessionStore
		storedSession, err := memStores.Session.GetByTokenHash(ctx, tokenHash)
		if err != nil {
			t.Fatalf("SessionStore.GetByTokenHash failed: %v", err)
		}
		if !storedSession.Pending2FA {
			t.Errorf("expected stored session Pending2FA to be true")
		}

		// Verified NOT cached in SecondaryStorage
		cachedSession, err := secStorage.GetSession(ctx, tokenHash)
		if err != nil {
			t.Fatalf("SecondaryStorage.GetSession failed: %v", err)
		}
		if cachedSession != nil {
			t.Fatalf("pending-2FA session MUST NOT be cached in SecondaryStorage, got %+v", cachedSession)
		}

		// Revoke pending-2FA session via k.Sessions.SignOut(ctx, authResult.RawToken) -> succeeds
		err = k.Sessions.SignOut(ctx, authResult.RawToken)
		if err != nil {
			t.Fatalf("SignOut failed: %v", err)
		}

		// Verify removed from SessionStore
		_, err = memStores.Session.GetByTokenHash(ctx, tokenHash)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound from SessionStore after SignOut, got %v", err)
		}

		// Subsequent SignOut returns ErrSessionNotFound
		err = k.Sessions.SignOut(ctx, authResult.RawToken)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound on subsequent SignOut, got %v", err)
		}
	})

	t.Run("secondary storage eviction on SignOut with mock verification", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		ctx := context.Background()
		fakeClk := clock.NewFake(fixedTime)
		memStores := memory.NewStores(memory.WithClock(fakeClk))

		cfg := kagi.Config{
			UserStore:         memStores.User,
			AccountStore:      memStores.Account,
			SessionStore:      memStores.Session,
			VerificationStore: memStores.Verification,
			RateLimitStore:    memStores.RateLimit,
			SecondaryStorage:  mockSec,
			Secret:            validSecret,
			Password:          fastPasswordConfig(),
			Clock:             fakeClk,
		}

		k, err := kagi.New(cfg)
		if err != nil {
			t.Fatalf("kagi.New failed: %v", err)
		}

		// Register user
		_, err = k.Credentials.SignUp(ctx, kagi.SignUpInput{
			Email:    "charlie@example.com",
			Password: "CharliePassword123!",
			Name:     "Charlie Day",
		})
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}

		// Rate limiting calls IncrementRateLimit for auth identifier (and IP if provided)
		mockSec.EXPECT().IncrementRateLimit(gomock.Any(), "rl:auth:charlie@example.com", 15*time.Minute).Return(1, nil).Times(1)

		// SetSession must be called on SignIn with exact idle TTL
		expectedTTL := kagi.DefaultSessionConfig().IdleTimeout
		mockSec.EXPECT().SetSession(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Session{}), expectedTTL).Return(nil).Times(1)
		authResult, err := k.Credentials.SignIn(ctx, kagi.SignInInput{
			Email:    "charlie@example.com",
			Password: "CharliePassword123!",
		})
		if err != nil {
			t.Fatalf("SignIn failed: %v", err)
		}

		tokenHash := crypto.HashToken(authResult.RawToken)

		// DeleteSession must be called on SecondaryStorage with exact tokenHash during SignOut
		mockSec.EXPECT().DeleteSession(gomock.Any(), tokenHash).Return(nil).Times(1)

		err = k.Sessions.SignOut(ctx, authResult.RawToken)
		if err != nil {
			t.Fatalf("SignOut failed: %v", err)
		}

		// Primary store must be empty
		_, err = memStores.Session.GetByTokenHash(ctx, tokenHash)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("complete SignUp -> SignIn -> SignOut lifecycle without secondary storage", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		fakeClk := clock.NewFake(fixedTime)
		memStores := memory.NewStores(memory.WithClock(fakeClk))

		cfg := kagi.Config{
			UserStore:         memStores.User,
			AccountStore:      memStores.Account,
			SessionStore:      memStores.Session,
			VerificationStore: memStores.Verification,
			RateLimitStore:    memStores.RateLimit,
			SecondaryStorage:  nil, // Optional secondary storage absent (ADR-0007)
			Secret:            validSecret,
			Password:          fastPasswordConfig(),
			Clock:             fakeClk,
		}

		k, err := kagi.New(cfg)
		if err != nil {
			t.Fatalf("kagi.New failed: %v", err)
		}

		user, err := k.Credentials.SignUp(ctx, kagi.SignUpInput{
			Email:    "david@example.com",
			Password: "DavidPassword123!",
			Name:     "David Miller",
		})
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}

		authResult, err := k.Credentials.SignIn(ctx, kagi.SignInInput{
			Email:    "david@example.com",
			Password: "DavidPassword123!",
		})
		if err != nil {
			t.Fatalf("SignIn failed: %v", err)
		}
		if authResult.User.ID != user.ID {
			t.Errorf("User mismatch: got %v, want %v", authResult.User.ID, user.ID)
		}

		tokenHash := crypto.HashToken(authResult.RawToken)
		storedSession, err := memStores.Session.GetByTokenHash(ctx, tokenHash)
		if err != nil {
			t.Fatalf("SessionStore.GetByTokenHash failed: %v", err)
		}
		if storedSession.ID != authResult.Session.ID {
			t.Errorf("Session ID mismatch: got %v, want %v", storedSession.ID, authResult.Session.ID)
		}

		err = k.Sessions.SignOut(ctx, authResult.RawToken)
		if err != nil {
			t.Fatalf("SignOut failed: %v", err)
		}

		_, err = memStores.Session.GetByTokenHash(ctx, tokenHash)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound after SignOut, got %v", err)
		}

		err = k.Sessions.SignOut(ctx, authResult.RawToken)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound on subsequent SignOut, got %v", err)
		}
	})
}

func TestKagi_SignInRateLimiting_Integration(t *testing.T) {
	validSecret := "a-very-long-master-secret-at-least-32-bytes-long"
	fixedTime := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

	t.Run("end-to-end rate limiting without Redis using RateLimitStore", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		fakeClk := clock.NewFake(fixedTime)
		memStores := memory.NewStores(memory.WithClock(fakeClk))

		cfg := kagi.Config{
			UserStore:         memStores.User,
			AccountStore:      memStores.Account,
			SessionStore:      memStores.Session,
			VerificationStore: memStores.Verification,
			RateLimitStore:    memStores.RateLimit,
			SecondaryStorage:  nil, // DB-backed rate limiting without Redis
			Secret:            validSecret,
			Password:          fastPasswordConfig(),
			Clock:             fakeClk,
			RateLimit: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{Limit: 2, Window: 15 * time.Minute},
				SignInIP:    kagi.LimitRule{Limit: 10, Window: 15 * time.Minute},
			},
		}

		k, err := kagi.New(cfg)
		if err != nil {
			t.Fatalf("kagi.New failed: %v", err)
		}

		// Register user
		_, err = k.Credentials.SignUp(ctx, kagi.SignUpInput{
			Email:    "rl-db@example.com",
			Password: "ValidPassword123!",
			Name:     "RL User",
		})
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}

		signInIn := kagi.SignInInput{
			Email:     "rl-db@example.com",
			Password:  "ValidPassword123!",
			IPAddress: "192.168.1.50",
		}

		// Attempt 1: Success
		res1, err := k.Credentials.SignIn(ctx, signInIn)
		if err != nil {
			t.Fatalf("attempt 1 failed: %v", err)
		}
		if res1 == nil || res1.Session == nil {
			t.Fatal("expected session on attempt 1")
		}

		// Attempt 2: Success
		res2, err := k.Credentials.SignIn(ctx, signInIn)
		if err != nil {
			t.Fatalf("attempt 2 failed: %v", err)
		}
		if res2 == nil || res2.Session == nil {
			t.Fatal("expected session on attempt 2")
		}

		// Attempt 3: Exceeds limit 2 -> ErrRateLimitExceeded
		_, err = k.Credentials.SignIn(ctx, signInIn)
		if !errors.Is(err, kagi.ErrRateLimitExceeded) {
			t.Fatalf("expected ErrRateLimitExceeded on attempt 3, got: %v", err)
		}
	})

	t.Run("end-to-end rate limiting with Redis using mocked SecondaryStorage", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		ctx := context.Background()
		fakeClk := clock.NewFake(fixedTime)
		memStores := memory.NewStores(memory.WithClock(fakeClk))

		cfg := kagi.Config{
			UserStore:         memStores.User,
			AccountStore:      memStores.Account,
			SessionStore:      memStores.Session,
			VerificationStore: memStores.Verification,
			RateLimitStore:    memStores.RateLimit,
			SecondaryStorage:  mockSec,
			Secret:            validSecret,
			Password:          fastPasswordConfig(),
			Clock:             fakeClk,
			RateLimit: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{Limit: 2, Window: 15 * time.Minute},
				SignInIP:    kagi.LimitRule{Limit: 10, Window: 15 * time.Minute},
			},
		}

		k, err := kagi.New(cfg)
		if err != nil {
			t.Fatalf("kagi.New failed: %v", err)
		}

		// Register user
		_, err = k.Credentials.SignUp(ctx, kagi.SignUpInput{
			Email:    "rl-redis@example.com",
			Password: "ValidPassword123!",
			Name:     "RL User Redis",
		})
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}

		signInIn := kagi.SignInInput{
			Email:     "rl-redis@example.com",
			Password:  "ValidPassword123!",
			IPAddress: "192.168.1.60",
		}

		// Attempt 1: IncrementRateLimit called on mockSec for IP then Email
		mockSec.EXPECT().IncrementRateLimit(gomock.Any(), "rl:ip:192.168.1.60", 15*time.Minute).Return(1, nil).Times(1)
		mockSec.EXPECT().IncrementRateLimit(gomock.Any(), "rl:auth:rl-redis@example.com", 15*time.Minute).Return(1, nil).Times(1)
		mockSec.EXPECT().SetSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)

		res1, err := k.Credentials.SignIn(ctx, signInIn)
		if err != nil {
			t.Fatalf("attempt 1 failed: %v", err)
		}
		if res1 == nil || res1.Session == nil {
			t.Fatal("expected session on attempt 1")
		}

		// Attempt 2: IncrementRateLimit returns 2 (at limit)
		mockSec.EXPECT().IncrementRateLimit(gomock.Any(), "rl:ip:192.168.1.60", 15*time.Minute).Return(2, nil).Times(1)
		mockSec.EXPECT().IncrementRateLimit(gomock.Any(), "rl:auth:rl-redis@example.com", 15*time.Minute).Return(2, nil).Times(1)
		mockSec.EXPECT().SetSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)

		res2, err := k.Credentials.SignIn(ctx, signInIn)
		if err != nil {
			t.Fatalf("attempt 2 failed: %v", err)
		}
		if res2 == nil || res2.Session == nil {
			t.Fatal("expected session on attempt 2")
		}

		// Attempt 3: IP returns 3 (count <= 10 allowed), Email returns 3 (count > 2 exceeded)
		mockSec.EXPECT().IncrementRateLimit(gomock.Any(), "rl:ip:192.168.1.60", 15*time.Minute).Return(3, nil).Times(1)
		mockSec.EXPECT().IncrementRateLimit(gomock.Any(), "rl:auth:rl-redis@example.com", 15*time.Minute).Return(3, nil).Times(1)

		_, err = k.Credentials.SignIn(ctx, signInIn)
		if !errors.Is(err, kagi.ErrRateLimitExceeded) {
			t.Fatalf("expected ErrRateLimitExceeded on attempt 3, got: %v", err)
		}
	})
}
