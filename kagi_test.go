package kagi_test

import (
	"context"
	"testing"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/internal/clock"
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

type cleanupTrackingSessionStore struct {
	mockSessionStore
	deletedCount int
}

func (s *cleanupTrackingSessionStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	s.deletedCount += 5
	return 5, nil
}

type cleanupTrackingVerificationStore struct {
	mockVerificationStore
	deletedCount int
}

func (v *cleanupTrackingVerificationStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	v.deletedCount += 3
	return 3, nil
}

type cleanupTrackingRateLimitStore struct {
	mockRateLimitStore
	deletedCount int
}

func (r *cleanupTrackingRateLimitStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	r.deletedCount += 10
	return 10, nil
}

func TestKagi_Cleanup(t *testing.T) {
	sessionStore := &cleanupTrackingSessionStore{}
	verificationStore := &cleanupTrackingVerificationStore{}
	rateLimitStore := &cleanupTrackingRateLimitStore{}

	instance, err := kagi.New(kagi.Config{
		UserStore:         &mockUserStore{},
		AccountStore:      &mockAccountStore{},
		SessionStore:      sessionStore,
		VerificationStore: verificationStore,
		RateLimitStore:    rateLimitStore,
		Secret:            "a-very-long-master-secret-at-least-32-bytes-long",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := instance.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if sessionStore.deletedCount != 5 {
		t.Errorf("expected 5 sessions deleted, got %d", sessionStore.deletedCount)
	}
	if verificationStore.deletedCount != 3 {
		t.Errorf("expected 3 verifications deleted, got %d", verificationStore.deletedCount)
	}
	if rateLimitStore.deletedCount != 10 {
		t.Errorf("expected 10 rate limits deleted, got %d", rateLimitStore.deletedCount)
	}
}
