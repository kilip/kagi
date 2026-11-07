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

func TestValidate(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

	t.Run("context cancelled returns error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		svc := kagi.NewSessionService(mockStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		validRawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		sess, renewed, err := svc.Validate(ctx, validRawToken)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if sess != nil || renewed {
			t.Fatalf("expected nil session and false renewed, got sess=%v, renewed=%v", sess, renewed)
		}
	})

	t.Run("invalid token format rejects without database query", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		mockSec := mock.NewMockSecondaryStorage(ctrl)
		svc := kagi.NewSessionService(mockStore, mockSec, kagi.DefaultSessionConfig(), fakeClk)

		// Store and secondary must never be queried
		invalidTokens := []string{
			"",
			"too-short",
			strings.Repeat("a", 42),
			strings.Repeat("a", 44),
			strings.Repeat("a", 42) + "=",
			strings.Repeat("a", 42) + "@",
			strings.Repeat("a", 42) + "+",
			strings.Repeat("a", 42) + "/",
		}

		for _, tok := range invalidTokens {
			sess, renewed, err := svc.Validate(context.Background(), tok)
			if !errors.Is(err, kagi.ErrInvalidSessionToken) {
				t.Errorf("token %q: expected ErrInvalidSessionToken, got %v", tok, err)
			}
			if sess != nil || renewed {
				t.Errorf("token %q: expected nil session and false renewed, got sess=%v, renewed=%v", tok, sess, renewed)
			}
		}
	})

	t.Run("nonexistent token returns ErrSessionNotFound", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		svc := kagi.NewSessionService(memStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
		if sess != nil || renewed {
			t.Fatalf("expected nil session and false renewed, got sess=%v, renewed=%v", sess, renewed)
		}
	})

	t.Run("primary store ErrSessionExpired returns ErrSessionNotFound", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		svc := kagi.NewSessionService(mockStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		mockStore.EXPECT().GetByTokenHash(gomock.Any(), tokenHash).Return(nil, kagi.ErrSessionExpired).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
		if sess != nil || renewed {
			t.Fatalf("expected nil session and false renewed, got sess=%v, renewed=%v", sess, renewed)
		}
	})

	t.Run("expired token returns ErrSessionNotFound on read check", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		svc := kagi.NewSessionService(mockStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		// Store returns a session whose ExpiresAt is in the past
		expiredSession := &kagi.Session{
			ID:        "sess-expired",
			UserID:    "user-1",
			TokenHash: tokenHash,
			ExpiresAt: fixedTime.Add(-1 * time.Second),
			CreatedAt: fixedTime.Add(-10 * time.Minute),
			UpdatedAt: fixedTime.Add(-10 * time.Minute),
		}
		mockStore.EXPECT().GetByTokenHash(gomock.Any(), tokenHash).Return(expiredSession, nil).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
		if sess != nil || renewed {
			t.Fatalf("expected nil session and false renewed, got sess=%v, renewed=%v", sess, renewed)
		}
	})

	t.Run("pending 2FA session returns ErrSessionPending2FA", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		memStore := memory.NewSessionStore(memory.WithClock(fakeClk))
		svc := kagi.NewSessionService(memStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		created, rawToken, err := kagi.SessionServiceCreateSessionForTest(svc, context.Background(), "user-2fa", true, "127.0.0.1", "test-agent")
		if err != nil {
			t.Fatalf("failed to create pending 2FA session: %v", err)
		}
		if !created.Pending2FA {
			t.Fatalf("expected pending 2FA to be true")
		}

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if !errors.Is(err, kagi.ErrSessionPending2FA) {
			t.Fatalf("expected ErrSessionPending2FA, got %v", err)
		}
		if sess != nil || renewed {
			t.Fatalf("expected nil session and false renewed, got sess=%v, renewed=%v", sess, renewed)
		}
	})

	t.Run("constant time verification defends against token hash mismatch", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		svc := kagi.NewSessionService(mockStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		// Store returns a session with different token hash (e.g. collation collision)
		spoofedSession := &kagi.Session{
			ID:        "sess-spoofed",
			UserID:    "user-spoofed",
			TokenHash: strings.Repeat("0", 64),
			ExpiresAt: fixedTime.Add(7 * 24 * time.Hour),
			CreatedAt: fixedTime,
			UpdatedAt: fixedTime,
		}
		mockStore.EXPECT().GetByTokenHash(gomock.Any(), tokenHash).Return(spoofedSession, nil).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if !errors.Is(err, kagi.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound on hash mismatch, got %v", err)
		}
		if sess != nil || renewed {
			t.Fatalf("expected nil session and false renewed, got sess=%v, renewed=%v", sess, renewed)
		}
	})

	t.Run("sliding renewal triggers when remaining <= threshold and updates both tiers", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		cfg := kagi.DefaultSessionConfig()
		// IdleTimeout: 7 days, RenewalThreshold: 0.5 => thresholdDuration: 3.5 days.
		// If remaining <= 3.5 days, renewal triggers.
		svc := kagi.NewSessionService(mockStore, mockSec, cfg, fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		// Session has 3 days remaining (<= 3.5 days)
		existingSession := &kagi.Session{
			ID:        "sess-renew",
			UserID:    "user-renew",
			TokenHash: tokenHash,
			ExpiresAt: fixedTime.Add(3 * 24 * time.Hour),
			CreatedAt: fixedTime.Add(-4 * 24 * time.Hour),
			UpdatedAt: fixedTime.Add(-4 * 24 * time.Hour),
		}

		// Cache miss in secondary
		mockSec.EXPECT().GetSession(gomock.Any(), tokenHash).Return(nil, nil).Times(1)
		// Fallback to store
		mockStore.EXPECT().GetByTokenHash(gomock.Any(), tokenHash).Return(existingSession, nil).Times(1)

		expectedNewExpiresAt := fixedTime.Add(cfg.IdleTimeout) // now + 7 days
		mockStore.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Session{})).DoAndReturn(
			func(_ context.Context, s *kagi.Session) error {
				if !s.ExpiresAt.Equal(expectedNewExpiresAt) {
					t.Errorf("expected new ExpiresAt %v, got %v", expectedNewExpiresAt, s.ExpiresAt)
				}
				if !s.UpdatedAt.Equal(fixedTime) {
					t.Errorf("expected UpdatedAt %v, got %v", fixedTime, s.UpdatedAt)
				}
				return nil
			},
		).Times(1)

		expectedTTL := expectedNewExpiresAt.Sub(fixedTime)
		mockSec.EXPECT().SetSession(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Session{}), expectedTTL).Return(nil).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if !renewed {
			t.Fatalf("expected renewed == true")
		}
		if sess == nil || !sess.ExpiresAt.Equal(expectedNewExpiresAt) {
			t.Fatalf("expected returned session with ExpiresAt %v, got %v", expectedNewExpiresAt, sess)
		}
	})

	t.Run("sliding renewal does not trigger when remaining > threshold but backfills cache", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		cfg := kagi.DefaultSessionConfig()
		svc := kagi.NewSessionService(mockStore, mockSec, cfg, fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		// Session has 5 days remaining (> 3.5 days threshold)
		initialExpiresAt := fixedTime.Add(5 * 24 * time.Hour)
		existingSession := &kagi.Session{
			ID:        "sess-no-renew",
			UserID:    "user-no-renew",
			TokenHash: tokenHash,
			ExpiresAt: initialExpiresAt,
			CreatedAt: fixedTime.Add(-2 * 24 * time.Hour),
			UpdatedAt: fixedTime.Add(-2 * 24 * time.Hour),
		}

		// Cache miss in secondary
		mockSec.EXPECT().GetSession(gomock.Any(), tokenHash).Return(nil, nil).Times(1)
		// Query primary store
		mockStore.EXPECT().GetByTokenHash(gomock.Any(), tokenHash).Return(existingSession, nil).Times(1)
		// Store.Update must NOT be called
		// Cache backfill is performed
		mockSec.EXPECT().SetSession(gomock.Any(), existingSession, 5*24*time.Hour).Return(nil).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if renewed {
			t.Fatalf("expected renewed == false")
		}
		if !sess.ExpiresAt.Equal(initialExpiresAt) {
			t.Fatalf("expected ExpiresAt unchanged, got %v", sess.ExpiresAt)
		}
	})

	t.Run("renewal strictly clamps to CreatedAt + AbsoluteTimeout", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		cfg := kagi.DefaultSessionConfig()
		svc := kagi.NewSessionService(mockStore, mockSec, cfg, fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		// Created 28 days ago. AbsoluteTimeout = 30 days. Hard max = CreatedAt + 30 days = fixedTime + 2 days.
		// Session has 1 day remaining (<= 3.5 days threshold).
		// IdleTimeout would suggest now + 7 days, but absolute ceiling is now + 2 days!
		createdAt := fixedTime.Add(-28 * 24 * time.Hour)
		absMax := createdAt.Add(cfg.AbsoluteTimeout) // fixedTime + 2 days
		existingSession := &kagi.Session{
			ID:        "sess-clamped",
			UserID:    "user-clamped",
			TokenHash: tokenHash,
			ExpiresAt: fixedTime.Add(1 * 24 * time.Hour),
			CreatedAt: createdAt,
			UpdatedAt: fixedTime.Add(-6 * 24 * time.Hour),
		}

		mockSec.EXPECT().GetSession(gomock.Any(), tokenHash).Return(nil, nil).Times(1)
		mockStore.EXPECT().GetByTokenHash(gomock.Any(), tokenHash).Return(existingSession, nil).Times(1)

		mockStore.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Session{})).DoAndReturn(
			func(_ context.Context, s *kagi.Session) error {
				if !s.ExpiresAt.Equal(absMax) {
					t.Errorf("expected clamped ExpiresAt %v, got %v", absMax, s.ExpiresAt)
				}
				return nil
			},
		).Times(1)

		expectedTTL := absMax.Sub(fixedTime)
		mockSec.EXPECT().SetSession(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Session{}), expectedTTL).Return(nil).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if !renewed {
			t.Fatalf("expected renewed == true")
		}
		if !sess.ExpiresAt.Equal(absMax) {
			t.Fatalf("expected sess.ExpiresAt == absMax (%v), got %v", absMax, sess.ExpiresAt)
		}
	})

	t.Run("prevents redundant writes when session has reached absolute ceiling", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		cfg := kagi.DefaultSessionConfig()
		svc := kagi.NewSessionService(mockStore, mockSec, cfg, fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		// Session was created 29 days ago.
		// ExpiresAt is ALREADY at the absolute ceiling (CreatedAt + 30 days = fixedTime + 1 day).
		// Remaining is 1 day (<= 3.5 days threshold).
		// But newExpiresAt = min(now + 7d, absMax) = absMax = existingSession.ExpiresAt.
		// Since newExpiresAt is NOT strictly after ExpiresAt, NO UPDATE should occur!
		createdAt := fixedTime.Add(-29 * 24 * time.Hour)
		absMax := createdAt.Add(cfg.AbsoluteTimeout)
		existingSession := &kagi.Session{
			ID:        "sess-capped",
			UserID:    "user-capped",
			TokenHash: tokenHash,
			ExpiresAt: absMax, // already capped
			CreatedAt: createdAt,
			UpdatedAt: fixedTime.Add(-1 * 24 * time.Hour),
		}

		mockSec.EXPECT().GetSession(gomock.Any(), tokenHash).Return(nil, nil).Times(1)
		mockStore.EXPECT().GetByTokenHash(gomock.Any(), tokenHash).Return(existingSession, nil).Times(1)
		// Store.Update MUST NOT be called!
		// Opportunistic cache backfill
		mockSec.EXPECT().SetSession(gomock.Any(), existingSession, absMax.Sub(fixedTime)).Return(nil).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if renewed {
			t.Fatalf("expected renewed == false when already at absolute ceiling")
		}
		if !sess.ExpiresAt.Equal(absMax) {
			t.Fatalf("expected ExpiresAt unchanged, got %v", sess.ExpiresAt)
		}
	})

	t.Run("secondary cache hit avoids querying primary store", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		cfg := kagi.DefaultSessionConfig()
		svc := kagi.NewSessionService(mockStore, mockSec, cfg, fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		cachedSession := &kagi.Session{
			ID:        "sess-cached",
			UserID:    "user-cached",
			TokenHash: tokenHash,
			ExpiresAt: fixedTime.Add(6 * 24 * time.Hour), // remaining > 3.5 days -> no renewal
			CreatedAt: fixedTime.Add(-1 * 24 * time.Hour),
			UpdatedAt: fixedTime.Add(-1 * 24 * time.Hour),
		}

		// Returns cached session
		mockSec.EXPECT().GetSession(gomock.Any(), tokenHash).Return(cachedSession, nil).Times(1)
		// mockStore must NOT be called at all!

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if renewed {
			t.Fatalf("expected renewed == false")
		}
		if sess.ID != "sess-cached" {
			t.Fatalf("expected cached session, got %v", sess)
		}
	})

	t.Run("secondary storage error gracefully falls back to primary store", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		mockSec := mock.NewMockSecondaryStorage(ctrl)

		cfg := kagi.DefaultSessionConfig()
		svc := kagi.NewSessionService(mockStore, mockSec, cfg, fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		storedSession := &kagi.Session{
			ID:        "sess-fallback",
			UserID:    "user-fallback",
			TokenHash: tokenHash,
			ExpiresAt: fixedTime.Add(6 * 24 * time.Hour),
			CreatedAt: fixedTime.Add(-1 * 24 * time.Hour),
			UpdatedAt: fixedTime.Add(-1 * 24 * time.Hour),
		}

		// Secondary returns error
		mockSec.EXPECT().GetSession(gomock.Any(), tokenHash).Return(nil, errors.New("redis timeout")).Times(1)
		// Fallback to store succeeds
		mockStore.EXPECT().GetByTokenHash(gomock.Any(), tokenHash).Return(storedSession, nil).Times(1)
		// Backfill attempt
		mockSec.EXPECT().SetSession(gomock.Any(), storedSession, gomock.Any()).Return(nil).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if renewed {
			t.Fatalf("expected renewed == false")
		}
		if sess.ID != "sess-fallback" {
			t.Fatalf("expected fallback session, got %v", sess)
		}
	})

	t.Run("primary store error propagates", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		svc := kagi.NewSessionService(mockStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		dbErr := errors.New("db connection failure")
		mockStore.EXPECT().GetByTokenHash(gomock.Any(), tokenHash).Return(nil, dbErr).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if !errors.Is(err, dbErr) {
			t.Fatalf("expected dbErr, got %v", err)
		}
		if sess != nil || renewed {
			t.Fatalf("expected nil session and false renewed")
		}
	})

	t.Run("primary store Update error on renewal propagates", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		svc := kagi.NewSessionService(mockStore, nil, kagi.DefaultSessionConfig(), fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		existingSession := &kagi.Session{
			ID:        "sess-renew-err",
			UserID:    "user-renew-err",
			TokenHash: tokenHash,
			ExpiresAt: fixedTime.Add(2 * 24 * time.Hour), // <= 3.5 days -> renew
			CreatedAt: fixedTime.Add(-5 * 24 * time.Hour),
			UpdatedAt: fixedTime.Add(-5 * 24 * time.Hour),
		}

		updateErr := errors.New("store update failed")
		mockStore.EXPECT().GetByTokenHash(gomock.Any(), tokenHash).Return(existingSession, nil).Times(1)
		mockStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(updateErr).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if !errors.Is(err, updateErr) {
			t.Fatalf("expected updateErr, got %v", err)
		}
		if sess != nil || renewed {
			t.Fatalf("expected nil session and false renewed")
		}
	})

	t.Run("secondary storage SetSession error on renewal propagates", func(t *testing.T) {
		t.Parallel()

		fakeClk := clock.NewFake(fixedTime)
		ctrl := gomock.NewController(t)
		mockStore := mock.NewMockSessionStore(ctrl)
		mockSec := mock.NewMockSecondaryStorage(ctrl)
		svc := kagi.NewSessionService(mockStore, mockSec, kagi.DefaultSessionConfig(), fakeClk)

		rawToken, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		tokenHash := crypto.HashToken(rawToken)

		existingSession := &kagi.Session{
			ID:        "sess-sec-renew-err",
			UserID:    "user-sec-renew-err",
			TokenHash: tokenHash,
			ExpiresAt: fixedTime.Add(2 * 24 * time.Hour), // <= 3.5 days -> renew
			CreatedAt: fixedTime.Add(-5 * 24 * time.Hour),
			UpdatedAt: fixedTime.Add(-5 * 24 * time.Hour),
		}

		secErr := errors.New("redis write failed")
		mockSec.EXPECT().GetSession(gomock.Any(), tokenHash).Return(existingSession, nil).Times(1)
		mockStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil).Times(1)
		mockSec.EXPECT().SetSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(secErr).Times(1)

		sess, renewed, err := svc.Validate(context.Background(), rawToken)
		if !errors.Is(err, secErr) {
			t.Fatalf("expected secErr, got %v", err)
		}
		if sess != nil || renewed {
			t.Fatalf("expected nil session and false renewed")
		}
	})
}
