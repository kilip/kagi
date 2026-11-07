package kagi_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/adapter/memory"
	"github.com/kilip/kagi/internal/clock"
	"github.com/kilip/kagi/internal/crypto"
	"github.com/kilip/kagi/mock"
	"go.uber.org/mock/gomock"
)

func TestNewSessionService(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	fakeClk := clock.NewFake(fixedTime)
	memStore := memory.NewSessionStore(memory.WithClock(fakeClk))

	tests := []struct {
		name              string
		store             kagi.SessionStore
		secondary         kagi.SecondaryStorage
		config            kagi.SessionConfig
		clk               clock.Clock
		wantIdleTimeout   time.Duration
		wantAbsTimeout    time.Duration
		want2FATimeout    time.Duration
		wantRealClockType bool
	}{
		{
			name:              "zero config and nil clock default safely",
			store:             memStore,
			secondary:         nil,
			config:            kagi.SessionConfig{},
			clk:               nil,
			wantIdleTimeout:   7 * 24 * time.Hour,
			wantAbsTimeout:    30 * 24 * time.Hour,
			want2FATimeout:    10 * time.Minute,
			wantRealClockType: true,
		},
		{
			name:      "custom config and custom clock preserved",
			store:     memStore,
			secondary: nil,
			config: kagi.SessionConfig{
				IdleTimeout:       2 * time.Hour,
				AbsoluteTimeout:   12 * time.Hour,
				RenewalThreshold:  0.2,
				Pending2FATimeout: 5 * time.Minute,
			},
			clk:               fakeClk,
			wantIdleTimeout:   2 * time.Hour,
			wantAbsTimeout:    12 * time.Hour,
			want2FATimeout:    5 * time.Minute,
			wantRealClockType: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc := kagi.NewSessionService(tc.store, tc.secondary, tc.config, tc.clk)
			if svc == nil {
				t.Fatalf("expected non-nil SessionService")
			}

			store, secondary, cfg, clk := kagi.SessionServiceDependenciesForTest(svc)
			if store != tc.store {
				t.Errorf("store mismatch: got %v, want %v", store, tc.store)
			}
			if secondary != tc.secondary {
				t.Errorf("secondary mismatch: got %v, want %v", secondary, tc.secondary)
			}
			if cfg.IdleTimeout != tc.wantIdleTimeout {
				t.Errorf("IdleTimeout mismatch: got %v, want %v", cfg.IdleTimeout, tc.wantIdleTimeout)
			}
			if cfg.AbsoluteTimeout != tc.wantAbsTimeout {
				t.Errorf("AbsoluteTimeout mismatch: got %v, want %v", cfg.AbsoluteTimeout, tc.wantAbsTimeout)
			}
			if cfg.Pending2FATimeout != tc.want2FATimeout {
				t.Errorf("Pending2FATimeout mismatch: got %v, want %v", cfg.Pending2FATimeout, tc.want2FATimeout)
			}
			if tc.wantRealClockType {
				if _, ok := clk.(clock.RealClock); !ok {
					t.Errorf("expected clock.RealClock, got %T", clk)
				}
			} else {
				if clk != tc.clk {
					t.Errorf("clock mismatch: got %v, want %v", clk, tc.clk)
				}
			}
		})
	}
}

func TestCreateSession(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

	t.Run("token format and hash properties", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		svc := kagi.NewSessionService(memStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		sess, rawToken, err := kagi.SessionServiceCreateSessionForTest(svc, context.Background(), "usr_123", false, "127.0.0.1", "test-agent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sess == nil {
			t.Fatalf("expected session not to be nil")
		}

		if len(rawToken) != 43 {
			t.Errorf("expected rawToken length 43, got %d", len(rawToken))
		}
		if err := crypto.ValidateSessionTokenFormat(rawToken); err != nil {
			t.Errorf("rawToken format validation failed: %v", err)
		}

		expectedHash := crypto.HashToken(rawToken)
		if sess.TokenHash != expectedHash {
			t.Errorf("tokenHash mismatch: got %s, want %s", sess.TokenHash, expectedHash)
		}
		if len(sess.TokenHash) != 64 {
			t.Errorf("expected tokenHash length 64, got %d", len(sess.TokenHash))
		}

		if sess.UserID != "usr_123" {
			t.Errorf("UserID mismatch: got %s, want usr_123", sess.UserID)
		}
		if sess.IPAddress != "127.0.0.1" {
			t.Errorf("IPAddress mismatch: got %s, want 127.0.0.1", sess.IPAddress)
		}
		if sess.UserAgent != "test-agent" {
			t.Errorf("UserAgent mismatch: got %s, want test-agent", sess.UserAgent)
		}
		if sess.Pending2FA {
			t.Errorf("expected Pending2FA false, got true")
		}
		if !sess.CreatedAt.Equal(fixedTime) {
			t.Errorf("CreatedAt mismatch: got %v, want %v", sess.CreatedAt, fixedTime)
		}
	})

	t.Run("pending 2FA session lifetime and secondary storage isolation", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockSec := mock.NewMockSecondaryStorage(ctrl)
		// mockSec must NEVER be called when pending2FA is true (Acceptance criteria)
		mockSec.EXPECT().SetSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		cfg := kagi.DefaultSessionConfig()
		svc := kagi.NewSessionService(memStore, mockSec, cfg, fakeClk)

		sess, rawToken, err := kagi.SessionServiceCreateSessionForTest(svc, context.Background(), "usr_2fa", true, "10.0.0.1", "mobile-app")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !sess.Pending2FA {
			t.Errorf("expected Pending2FA true")
		}

		expectedExpiresAt := fixedTime.Add(cfg.Pending2FATimeout)
		if !sess.ExpiresAt.Equal(expectedExpiresAt) {
			t.Errorf("ExpiresAt mismatch for pending 2FA: got %v, want %v", sess.ExpiresAt, expectedExpiresAt)
		}

		// Verify stored in primary SessionStore
		stored, err := memStore.GetByTokenHash(context.Background(), crypto.HashToken(rawToken))
		if err != nil {
			t.Fatalf("failed to retrieve stored session: %v", err)
		}
		if stored.UserID != "usr_2fa" || !stored.Pending2FA {
			t.Errorf("stored session does not match expectations: %+v", stored)
		}
	})

	t.Run("active session cached in secondary storage with exact TTL", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		cfg := kagi.DefaultSessionConfig()
		svc := kagi.NewSessionService(memStore, mockSec, cfg, fakeClk)

		expectedTTL := cfg.IdleTimeout
		mockSec.EXPECT().SetSession(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Session{}), expectedTTL).Return(nil).Times(1)

		sess, _, err := kagi.SessionServiceCreateSessionForTest(svc, context.Background(), "usr_active", false, "192.168.1.1", "desktop-browser")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sess.Pending2FA {
			t.Errorf("expected Pending2FA false")
		}
		if !sess.ExpiresAt.Equal(fixedTime.Add(expectedTTL)) {
			t.Errorf("ExpiresAt mismatch: got %v, want %v", sess.ExpiresAt, fixedTime.Add(expectedTTL))
		}
	})

	t.Run("active session absolute timeout clamping", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		cfg := kagi.SessionConfig{
			IdleTimeout:       10 * time.Hour,
			AbsoluteTimeout:   3 * time.Hour, // Absolute is shorter than Idle
			RenewalThreshold:  0.5,
			Pending2FATimeout: 10 * time.Minute,
		}
		svc := kagi.NewSessionService(memStore, nil, cfg, fakeClk)

		sess, _, err := kagi.SessionServiceCreateSessionForTest(svc, context.Background(), "usr_clamped", false, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedExpiresAt := fixedTime.Add(cfg.AbsoluteTimeout)
		if !sess.ExpiresAt.Equal(expectedExpiresAt) {
			t.Errorf("expected ExpiresAt clamped to %v, got %v", expectedExpiresAt, sess.ExpiresAt)
		}
	})

	t.Run("secondary storage failure propagates error", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		secErr := errors.New("redis connection refused")
		mockSec.EXPECT().SetSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(secErr).Times(1)

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		svc := kagi.NewSessionService(memStore, mockSec, kagi.DefaultSessionConfig(), fakeClk)

		_, _, err := kagi.SessionServiceCreateSessionForTest(svc, context.Background(), "usr_fail", false, "", "")
		if !errors.Is(err, secErr) {
			t.Fatalf("expected error %v, got %v", secErr, err)
		}
	})

	t.Run("context cancelled returns error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		svc := kagi.NewSessionService(memStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		_, _, err := kagi.SessionServiceCreateSessionForTest(svc, ctx, "usr_ctx", false, "", "")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})
}

func TestSignOut(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

	t.Run("invalid token format rejected without storage access", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		// Expect zero calls to storage on invalid formats
		mockStore.EXPECT().DeleteByTokenHash(gomock.Any(), gomock.Any()).Times(0)
		mockSec.EXPECT().DeleteSession(gomock.Any(), gomock.Any()).Times(0)

		fakeClk := clock.NewFake(fixedTime)
		svc := kagi.NewSessionService(mockStore, mockSec, kagi.DefaultSessionConfig(), fakeClk)

		invalidTokens := []struct {
			name  string
			token string
		}{
			{name: "empty token", token: ""},
			{name: "too short (42 chars)", token: strings.Repeat("a", 42)},
			{name: "too long (44 chars)", token: strings.Repeat("a", 44)},
			{name: "invalid chars (+ and / not raw URL-safe)", token: strings.Repeat("a", 41) + "+="},
			{name: "invalid chars space", token: strings.Repeat("a", 42) + " "},
			{name: "padded token", token: strings.Repeat("a", 40) + "=="},
		}

		for _, tc := range invalidTokens {
			t.Run(tc.name, func(t *testing.T) {
				err := svc.SignOut(context.Background(), tc.token)
				if !errors.Is(err, kagi.ErrInvalidSessionToken) {
					t.Errorf("token %q: expected ErrInvalidSessionToken, got %v", tc.token, err)
				}
			})
		}
	})

	t.Run("non-existent session returns ErrSessionNotFound", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		svc := kagi.NewSessionService(memStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		validRawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		err = svc.SignOut(context.Background(), validRawToken)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("expired session returns ErrSessionNotFound", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		svc := kagi.NewSessionService(memStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		sess, rawToken, err := kagi.SessionServiceCreateSessionForTest(svc, context.Background(), "usr_exp", false, "", "")
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		// Advance clock past expiration
		fakeClk.Advance(sess.ExpiresAt.Sub(fixedTime) + time.Second)

		err = svc.SignOut(context.Background(), rawToken)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound for expired session, got %v", err)
		}
	})

	t.Run("active session removed from primary and secondary storage", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))

		mockSec.EXPECT().SetSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)

		svc := kagi.NewSessionService(memStore, mockSec, kagi.DefaultSessionConfig(), fakeClk)

		sess, rawToken, err := kagi.SessionServiceCreateSessionForTest(svc, context.Background(), "usr_signout", false, "1.2.3.4", "agent")
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		tokenHash := crypto.HashToken(rawToken)

		// Expect DeleteSession called on secondary storage with the exact tokenHash
		mockSec.EXPECT().DeleteSession(gomock.Any(), tokenHash).Return(nil).Times(1)

		err = svc.SignOut(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("unexpected error on SignOut: %v", err)
		}

		// Verify session is removed from primary store
		_, err = memStore.GetByTokenHash(context.Background(), tokenHash)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound from store after sign out, got %v", err)
		}

		// Second SignOut should fail with ErrSessionNotFound
		err = svc.SignOut(context.Background(), rawToken)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound on second SignOut, got %v", err)
		}
		_ = sess
	})

	t.Run("pending-2FA session removed from primary store", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockSec := mock.NewMockSecondaryStorage(ctrl)
		// mockSec must never receive SetSession on 2FA session creation
		mockSec.EXPECT().SetSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		svc := kagi.NewSessionService(memStore, mockSec, kagi.DefaultSessionConfig(), fakeClk)

		_, rawToken, err := kagi.SessionServiceCreateSessionForTest(svc, context.Background(), "usr_2fa_signout", true, "", "")
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		tokenHash := crypto.HashToken(rawToken)

		// On SignOut, secondary DeleteSession is still called (safe cache eviction)
		mockSec.EXPECT().DeleteSession(gomock.Any(), tokenHash).Return(nil).Times(1)

		err = svc.SignOut(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("unexpected error on SignOut: %v", err)
		}

		_, err = memStore.GetByTokenHash(context.Background(), tokenHash)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("secondary storage failure propagates error", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))

		mockSec.EXPECT().SetSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
		svc := kagi.NewSessionService(memStore, mockSec, kagi.DefaultSessionConfig(), fakeClk)

		_, rawToken, err := kagi.SessionServiceCreateSessionForTest(svc, context.Background(), "usr_fail_sec", false, "", "")
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		secErr := errors.New("redis timeout")
		mockSec.EXPECT().DeleteSession(gomock.Any(), crypto.HashToken(rawToken)).Return(secErr).Times(1)

		err = svc.SignOut(context.Background(), rawToken)
		if !errors.Is(err, secErr) {
			t.Fatalf("expected %v, got %v", secErr, err)
		}
	})

	t.Run("context cancelled returns error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		svc := kagi.NewSessionService(memStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		validRawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		err = svc.SignOut(ctx, validRawToken)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})
}
