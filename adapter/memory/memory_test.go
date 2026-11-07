package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/adapter/memory"
	"github.com/kilip/kagi/adaptertest"
	"github.com/kilip/kagi/internal/clock"
)

func TestSessionStoreConformance(t *testing.T) {
	sessionStore := memory.NewSessionStore()
	userStore := memory.NewUserStore()
	adaptertest.RunSessionStoreTests(t, sessionStore, userStore)
}

func TestVerificationStoreConformance(t *testing.T) {
	verificationStore := memory.NewVerificationStore()
	adaptertest.RunVerificationStoreTests(t, verificationStore)
}

func TestRateLimitStoreConformance(t *testing.T) {
	rateLimitStore := memory.NewRateLimitStore()
	adaptertest.RunRateLimitStoreTests(t, rateLimitStore)
}

func TestAllConformance(t *testing.T) {
	stores := memory.New()
	adaptertest.RunAll(t, stores.AsAdaptertestStores())
}

func TestNewStoresAlias(t *testing.T) {
	stores := memory.NewStores()
	adaptertest.RunAll(t, stores.AsAdaptertestStores())
}

func TestSessionStore_CASTokenRotationAnd2FAReset(t *testing.T) {
	ctx := context.Background()
	store := memory.NewSessionStore()

	origExpiresAt := time.Now().UTC().Add(1 * time.Hour)
	sess := &kagi.Session{
		UserID:     "user_test_cas",
		TokenHash:  "initial_token_hash_64_chars_hex_0000000000000000000000000000000000",
		ExpiresAt:  origExpiresAt,
		Pending2FA: true,
	}

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	initialCreatedAt := sess.CreatedAt
	newExpiresAt := time.Now().UTC().Add(2 * time.Hour)
	newTokenHash := "rotated_token_hash_64_chars_hex_1111111111111111111111111111111111"

	// Old token hash mismatch must fail CAS
	err := store.UpdateTokenHash(ctx, sess.ID, "wrong_old_token_hash", newTokenHash, newExpiresAt)
	if err == nil {
		t.Fatal("expected error on oldTokenHash mismatch, got nil")
	}

	// Correct old token hash must succeed and graduate 2FA (Pending2FA = false)
	err = store.UpdateTokenHash(ctx, sess.ID, sess.TokenHash, newTokenHash, newExpiresAt)
	if err != nil {
		t.Fatalf("UpdateTokenHash failed: %v", err)
	}

	// Verify old token hash is gone
	oldLookup, err := store.GetByTokenHash(ctx, "initial_token_hash_64_chars_hex_0000000000000000000000000000000000")
	if err == nil || oldLookup != nil {
		t.Fatalf("expected old token hash to be removed, got sess: %+v", oldLookup)
	}

	// Verify new token hash is active, Pending2FA is false, and CreatedAt is unchanged
	updated, err := store.GetByTokenHash(ctx, newTokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash with newTokenHash failed: %v", err)
	}
	if updated.Pending2FA {
		t.Errorf("expected Pending2FA to be false after 2FA graduation, got true")
	}
	if !updated.CreatedAt.Equal(initialCreatedAt) {
		t.Errorf("expected CreatedAt preserved (absolute ceiling guard), orig=%v, got=%v", initialCreatedAt, updated.CreatedAt)
	}
	if !updated.ExpiresAt.Equal(newExpiresAt) {
		t.Errorf("expected ExpiresAt updated to %v, got %v", newExpiresAt, updated.ExpiresAt)
	}
}

func TestSessionStore_DefensiveCloning(t *testing.T) {
	ctx := context.Background()
	store := memory.NewSessionStore()

	sess := &kagi.Session{
		UserID:    "user_def_clone",
		TokenHash: "th_def_clone_000000000000000000000000000000000000000000000000000000",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		IPAddress: "127.0.0.1",
	}

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Mutating caller object should not affect stored session
	sess.IPAddress = "192.168.1.1"

	stored, err := store.GetByTokenHash(ctx, sess.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash failed: %v", err)
	}
	if stored.IPAddress != "127.0.0.1" {
		t.Errorf("expected stored IPAddress '127.0.0.1', got %q", stored.IPAddress)
	}

	// Mutating returned object should not affect stored session
	stored.IPAddress = "10.0.0.1"

	storedAgain, err := store.GetByTokenHash(ctx, sess.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash failed: %v", err)
	}
	if storedAgain.IPAddress != "127.0.0.1" {
		t.Errorf("expected stored IPAddress '127.0.0.1', got %q", storedAgain.IPAddress)
	}
}

func TestVerificationStore_DefensiveCloning(t *testing.T) {
	ctx := context.Background()
	store := memory.NewVerificationStore()

	v := &kagi.Verification{
		Target:    "test@example.com",
		Type:      kagi.VerificationTypeLogin,
		CodeHash:  "code_hash_123456",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Attempts:  1,
	}

	if err := store.Create(ctx, v); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Mutate caller object
	v.Attempts = 99
	stored, err := store.Get(ctx, "test@example.com", kagi.VerificationTypeLogin)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if stored.Attempts != 1 {
		t.Errorf("expected stored Attempts 1, got %d", stored.Attempts)
	}

	// Mutate returned object
	stored.Attempts = 50
	storedAgain, err := store.Get(ctx, "test@example.com", kagi.VerificationTypeLogin)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if storedAgain.Attempts != 1 {
		t.Errorf("expected stored Attempts 1, got %d", storedAgain.Attempts)
	}
}

func TestRateLimitStore_WindowReset(t *testing.T) {
	fake := clock.NewFake(time.Now())
	store := memory.NewRateLimitStore(memory.WithClock(fake))
	ctx := context.Background()

	key := "rl:window_test"
	window := 10 * time.Second

	// 1st increment -> count 1
	c1, err := store.Increment(ctx, key, window)
	if err != nil || c1 != 1 {
		t.Fatalf("1st increment expected (1, nil), got (%d, %v)", c1, err)
	}

	// Advance time within window -> count 2
	fake.Advance(5 * time.Second)
	c2, err := store.Increment(ctx, key, window)
	if err != nil || c2 != 2 {
		t.Fatalf("2nd increment expected (2, nil), got (%d, %v)", c2, err)
	}

	// Advance time past window -> reset to count 1
	fake.Advance(6 * time.Second)
	c3, err := store.Increment(ctx, key, window)
	if err != nil || c3 != 1 {
		t.Fatalf("3rd increment expected reset to (1, nil), got (%d, %v)", c3, err)
	}
}
