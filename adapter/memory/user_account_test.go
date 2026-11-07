package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/adapter/memory"
	"github.com/kilip/kagi/adaptertest"
)

type mockClock struct {
	now time.Time
}

func (m *mockClock) Now() time.Time {
	return m.now
}

func (m *mockClock) Since(t time.Time) time.Duration {
	return m.now.Sub(t)
}

func (m *mockClock) Until(t time.Time) time.Duration {
	return t.Sub(m.now)
}

func TestConformance(t *testing.T) {
	t.Run("UserStore", func(t *testing.T) {
		userStore := memory.NewUserStore()
		adaptertest.RunUserStoreTests(t, userStore)
	})

	t.Run("AccountStore", func(t *testing.T) {
		userStore := memory.NewUserStore()
		accountStore := memory.NewAccountStore()
		adaptertest.RunAccountStoreTests(t, accountStore, userStore)
	})
}

func TestDefensiveCloning_UserStore(t *testing.T) {
	ctx := context.Background()
	store := memory.NewUserStore()

	original := &kagi.User{
		Email: "test@example.com",
		Name:  "Original Name",
	}

	if err := store.Create(ctx, original); err != nil {
		t.Fatalf("unexpected error creating user: %v", err)
	}

	// Mutating original after creation should not mutate stored state
	original.Name = "Mutated Name"
	fetched, err := store.GetByID(ctx, original.ID)
	if err != nil {
		t.Fatalf("unexpected error fetching user: %v", err)
	}
	if fetched.Name != "Original Name" {
		t.Errorf("expected stored name 'Original Name', got %q", fetched.Name)
	}

	// Mutating fetched user should not mutate stored state
	fetched.Name = "Mutated Fetched Name"
	fetchedAgain, err := store.GetByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error fetching user by email: %v", err)
	}
	if fetchedAgain.Name != "Original Name" {
		t.Errorf("expected stored name 'Original Name', got %q", fetchedAgain.Name)
	}
}

func TestDefensiveCloning_AccountStore(t *testing.T) {
	ctx := context.Background()
	store := memory.NewAccountStore()

	initialExpiry := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	expiry := initialExpiry
	original := &kagi.Account{
		UserID:            "1",
		Provider:          "google",
		ProviderAccountID: "google-123",
		AccessToken:       "original_token",
		TokenExpiresAt:    &expiry,
	}

	if err := store.Create(ctx, original); err != nil {
		t.Fatalf("unexpected error creating account: %v", err)
	}

	// Mutate caller's original struct and nested pointer
	original.AccessToken = "mutated_token"
	mutatedExpiry := expiry.Add(24 * time.Hour)
	*original.TokenExpiresAt = mutatedExpiry

	fetched, err := store.GetByProvider(ctx, "google", "google-123")
	if err != nil {
		t.Fatalf("unexpected error fetching account: %v", err)
	}
	if fetched.AccessToken != "original_token" {
		t.Errorf("expected 'original_token', got %q", fetched.AccessToken)
	}
	if !fetched.TokenExpiresAt.Equal(initialExpiry) {
		t.Errorf("expected expiry %v, got %v", initialExpiry, *fetched.TokenExpiresAt)
	}

	// Mutate fetched account
	fetched.AccessToken = "mutated_fetched_token"
	mutatedExpiry2 := expiry.Add(48 * time.Hour)
	*fetched.TokenExpiresAt = mutatedExpiry2

	list, err := store.ListByUserID(ctx, "1")
	if err != nil {
		t.Fatalf("unexpected error listing accounts: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 account, got %d", len(list))
	}
	if list[0].AccessToken != "original_token" {
		t.Errorf("expected 'original_token', got %q", list[0].AccessToken)
	}
	if !list[0].TokenExpiresAt.Equal(initialExpiry) {
		t.Errorf("expected expiry %v, got %v", initialExpiry, *list[0].TokenExpiresAt)
	}
}

func TestWithClock(t *testing.T) {
	ctx := context.Background()
	frozenTime := time.Date(2026, 6, 15, 10, 30, 0, 0, time.UTC)
	mock := &mockClock{now: frozenTime}

	t.Run("UserStore respects WithClock", func(t *testing.T) {
		store := memory.NewUserStore(memory.WithClock(mock))
		u := &kagi.User{
			Email: "clock@example.com",
			Name:  "Clock User",
		}

		if err := store.Create(ctx, u); err != nil {
			t.Fatalf("unexpected error creating user: %v", err)
		}
		if !u.CreatedAt.Equal(frozenTime) {
			t.Errorf("expected CreatedAt %v, got %v", frozenTime, u.CreatedAt)
		}
		if !u.UpdatedAt.Equal(frozenTime) {
			t.Errorf("expected UpdatedAt %v, got %v", frozenTime, u.UpdatedAt)
		}

		// Update with time advancement
		nextTime := frozenTime.Add(2 * time.Hour)
		mock.now = nextTime
		u.Name = "Clock User Updated"
		if err := store.Update(ctx, u); err != nil {
			t.Fatalf("unexpected error updating user: %v", err)
		}
		if !u.UpdatedAt.Equal(nextTime) {
			t.Errorf("expected UpdatedAt %v, got %v", nextTime, u.UpdatedAt)
		}
	})

	t.Run("AccountStore respects WithClock", func(t *testing.T) {
		mock.now = frozenTime
		store := memory.NewAccountStore(memory.WithClock(mock))
		a := &kagi.Account{
			UserID:            "1",
			Provider:          "credential",
			ProviderAccountID: "clock@example.com",
		}

		if err := store.Create(ctx, a); err != nil {
			t.Fatalf("unexpected error creating account: %v", err)
		}
		if !a.CreatedAt.Equal(frozenTime) {
			t.Errorf("expected CreatedAt %v, got %v", frozenTime, a.CreatedAt)
		}
		if !a.UpdatedAt.Equal(frozenTime) {
			t.Errorf("expected UpdatedAt %v, got %v", frozenTime, a.UpdatedAt)
		}

		// Update with time advancement
		nextTime := frozenTime.Add(2 * time.Hour)
		mock.now = nextTime
		a.PasswordHash = "new_hash"
		if err := store.Update(ctx, a); err != nil {
			t.Fatalf("unexpected error updating account: %v", err)
		}
		if !a.UpdatedAt.Equal(nextTime) {
			t.Errorf("expected UpdatedAt %v, got %v", nextTime, a.UpdatedAt)
		}
	})
}
