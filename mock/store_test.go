package mock_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/mock"
	"go.uber.org/mock/gomock"
)

// Compile-time interface assertions to verify that each mock implements its target interface.
var (
	_ kagi.UserStore         = (*mock.MockUserStore)(nil)
	_ kagi.AccountStore      = (*mock.MockAccountStore)(nil)
	_ kagi.SessionStore      = (*mock.MockSessionStore)(nil)
	_ kagi.VerificationStore = (*mock.MockVerificationStore)(nil)
	_ kagi.RateLimitStore    = (*mock.MockRateLimitStore)(nil)
	_ kagi.SecondaryStorage  = (*mock.MockSecondaryStorage)(nil)
)

func TestMockStores_LifecycleAndExpectations(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()

	tests := []struct {
		name string
		test func(t *testing.T, ctrl *gomock.Controller)
	}{
		{
			name: "MockUserStore - GetByID success and not found",
			test: func(t *testing.T, ctrl *gomock.Controller) {
				m := mock.NewMockUserStore(ctrl)
				expectedUser := &kagi.User{
					ID:            "usr_123",
					Email:         "user@example.com",
					EmailVerified: true,
					CreatedAt:     now,
					UpdatedAt:     now,
				}

				m.EXPECT().
					GetByID(ctx, "usr_123").
					Return(expectedUser, nil).
					Times(1)

				m.EXPECT().
					GetByID(ctx, "usr_missing").
					Return(nil, kagi.ErrUserNotFound).
					Times(1)

				u, err := m.GetByID(ctx, "usr_123")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if u.ID != expectedUser.ID || u.Email != expectedUser.Email {
					t.Errorf("unexpected user returned: %+v", u)
				}

				_, err = m.GetByID(ctx, "usr_missing")
				if !errors.Is(err, kagi.ErrUserNotFound) {
					t.Fatalf("expected ErrUserNotFound, got %v", err)
				}
			},
		},
		{
			name: "MockAccountStore - GetByProvider success and not found",
			test: func(t *testing.T, ctrl *gomock.Controller) {
				m := mock.NewMockAccountStore(ctrl)
				expectedAccount := &kagi.Account{
					ID:                "acc_123",
					UserID:            "usr_123",
					Provider:          "credential",
					ProviderAccountID: "user@example.com",
					PasswordHash:      "hashed_pw",
					CreatedAt:         now,
					UpdatedAt:         now,
				}

				m.EXPECT().
					GetByProvider(ctx, "credential", "user@example.com").
					Return(expectedAccount, nil).
					Times(1)

				m.EXPECT().
					GetByProvider(ctx, "credential", "unknown@example.com").
					Return(nil, kagi.ErrAccountNotFound).
					Times(1)

				acc, err := m.GetByProvider(ctx, "credential", "user@example.com")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if acc.ID != expectedAccount.ID || acc.Provider != "credential" {
					t.Errorf("unexpected account returned: %+v", acc)
				}

				_, err = m.GetByProvider(ctx, "credential", "unknown@example.com")
				if !errors.Is(err, kagi.ErrAccountNotFound) {
					t.Fatalf("expected ErrAccountNotFound, got %v", err)
				}
			},
		},
		{
			name: "MockSessionStore - GetByTokenHash success and expired error",
			test: func(t *testing.T, ctrl *gomock.Controller) {
				m := mock.NewMockSessionStore(ctrl)
				expectedSession := &kagi.Session{
					ID:        "sess_123",
					UserID:    "usr_123",
					TokenHash: "hash_abc",
					ExpiresAt: now.Add(24 * time.Hour),
					CreatedAt: now,
					UpdatedAt: now,
				}

				m.EXPECT().
					GetByTokenHash(ctx, "hash_abc").
					Return(expectedSession, nil).
					Times(1)

				m.EXPECT().
					GetByTokenHash(ctx, "hash_expired").
					Return(nil, kagi.ErrSessionExpired).
					Times(1)

				sess, err := m.GetByTokenHash(ctx, "hash_abc")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if sess.ID != expectedSession.ID || sess.UserID != "usr_123" {
					t.Errorf("unexpected session returned: %+v", sess)
				}

				_, err = m.GetByTokenHash(ctx, "hash_expired")
				if !errors.Is(err, kagi.ErrSessionExpired) {
					t.Fatalf("expected ErrSessionExpired, got %v", err)
				}
			},
		},
		{
			name: "MockVerificationStore - Get success and not found",
			test: func(t *testing.T, ctrl *gomock.Controller) {
				m := mock.NewMockVerificationStore(ctrl)
				expectedVerification := &kagi.Verification{
					ID:        "ver_123",
					Target:    "user@example.com",
					Type:      kagi.VerificationTypeEmailVerify,
					CodeHash:  "hash_code",
					ExpiresAt: now.Add(15 * time.Minute),
					CreatedAt: now,
				}

				m.EXPECT().
					Get(ctx, "user@example.com", kagi.VerificationTypeEmailVerify).
					Return(expectedVerification, nil).
					Times(1)

				m.EXPECT().
					Get(ctx, "user@example.com", kagi.VerificationTypePasswordReset).
					Return(nil, kagi.ErrVerificationNotFound).
					Times(1)

				v, err := m.Get(ctx, "user@example.com", kagi.VerificationTypeEmailVerify)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if v.ID != expectedVerification.ID || v.Target != "user@example.com" {
					t.Errorf("unexpected verification returned: %+v", v)
				}

				_, err = m.Get(ctx, "user@example.com", kagi.VerificationTypePasswordReset)
				if !errors.Is(err, kagi.ErrVerificationNotFound) {
					t.Fatalf("expected ErrVerificationNotFound, got %v", err)
				}
			},
		},
		{
			name: "MockRateLimitStore - Increment and allowed checks",
			test: func(t *testing.T, ctrl *gomock.Controller) {
				m := mock.NewMockRateLimitStore(ctrl)

				window := time.Minute
				m.EXPECT().
					Increment(ctx, "rl:ip:127.0.0.1", window).
					Return(1, nil).
					Times(1)

				m.EXPECT().
					Increment(ctx, "rl:ip:127.0.0.1", window).
					Return(2, nil).
					Times(1)

				cnt1, err := m.Increment(ctx, "rl:ip:127.0.0.1", window)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cnt1 != 1 {
					t.Errorf("expected count 1, got %d", cnt1)
				}

				cnt2, err := m.Increment(ctx, "rl:ip:127.0.0.1", window)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cnt2 != 2 {
					t.Errorf("expected count 2, got %d", cnt2)
				}
			},
		},
		{
			name: "MockSecondaryStorage - GetSession cache hit, miss, and SetSession",
			test: func(t *testing.T, ctrl *gomock.Controller) {
				m := mock.NewMockSecondaryStorage(ctrl)
				cachedSession := &kagi.Session{
					ID:        "sess_fast",
					UserID:    "usr_fast",
					TokenHash: "hash_fast",
					ExpiresAt: now.Add(time.Hour),
					CreatedAt: now,
					UpdatedAt: now,
				}

				m.EXPECT().
					GetSession(ctx, "hash_fast").
					Return(cachedSession, nil).
					Times(1)

				m.EXPECT().
					GetSession(ctx, "hash_miss").
					Return(nil, nil).
					Times(1)

				m.EXPECT().
					SetSession(ctx, cachedSession, time.Hour).
					Return(nil).
					Times(1)

				s, err := m.GetSession(ctx, "hash_fast")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if s == nil || s.ID != "sess_fast" {
					t.Errorf("unexpected session returned: %+v", s)
				}

				miss, err := m.GetSession(ctx, "hash_miss")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if miss != nil {
					t.Errorf("expected nil for cache miss, got %+v", miss)
				}

				if err := m.SetSession(ctx, cachedSession, time.Hour); err != nil {
					t.Fatalf("unexpected error setting session: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			tc.test(t, ctrl)
		})
	}
}
