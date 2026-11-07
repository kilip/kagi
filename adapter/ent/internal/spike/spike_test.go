package spike_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"

	"github.com/kilip/kagi"
	kagientc "github.com/kilip/kagi/adapter/ent/entc"
	"github.com/kilip/kagi/adapter/ent/internal/spike/ent"
	"github.com/kilip/kagi/adaptertest"
)

func setupTestClient(t *testing.T) *ent.Client {
	t.Helper()

	client, err := ent.Open("sqlite3", "file:spiketest?mode=memory&cache=shared&_fk=1")
	if err != nil {
		t.Fatalf("failed opening connection to sqlite: %v", err)
	}

	ctx := context.Background()
	if err := client.Schema.Create(ctx); err != nil {
		client.Close()
		t.Fatalf("failed creating schema resources: %v", err)
	}

	t.Cleanup(func() {
		client.Close()
	})

	return client
}

func TestEntcGeneration(t *testing.T) {
	tempTarget := t.TempDir()
	cfg := &gen.Config{
		Package: "spike/temp/ent",
		Target:  tempTarget,
	}

	err := entc.Generate("./schema", cfg, entc.Extensions(kagientc.NewExtension()))
	if err != nil {
		t.Fatalf("failed running entc.Generate with Kagi extension: %v", err)
	}

	for _, name := range []string{"kagi_user_store.go", "kagi_account_store.go", "kagi_session_store.go", "kagi_verification_store.go", "kagi_rate_limit_store.go"} {
		generatedFile := filepath.Join(tempTarget, name)
		info, err := os.Stat(generatedFile)
		if err != nil {
			t.Fatalf("expected %s to be generated, got error: %v", generatedFile, err)
		}
		if info.Size() == 0 {
			t.Fatalf("expected %s to be non-empty", generatedFile)
		}
	}
}

func TestKagiAccountStore_Conformance(t *testing.T) {
	var _ kagi.AccountStore = (*ent.KagiAccountStore)(nil)

	client := setupTestClient(t)
	accountStore := ent.NewKagiAccountStore(client)
	userStore := ent.NewKagiUserStore(client)
	adaptertest.RunAccountStoreTests(t, accountStore, userStore)
}

func TestKagiSessionStore_Conformance(t *testing.T) {
	var _ kagi.SessionStore = (*ent.KagiSessionStore)(nil)

	client := setupTestClient(t)
	sessionStore := ent.NewKagiSessionStore(client)
	userStore := ent.NewKagiUserStore(client)
	adaptertest.RunSessionStoreTests(t, sessionStore, userStore)
}

func TestKagiVerificationStore_Conformance(t *testing.T) {
	var _ kagi.VerificationStore = (*ent.KagiVerificationStore)(nil)

	client := setupTestClient(t)
	verificationStore := ent.NewKagiVerificationStore(client)
	adaptertest.RunVerificationStoreTests(t, verificationStore)
}

func TestKagiRateLimitStore_Conformance(t *testing.T) {
	var _ kagi.RateLimitStore = (*ent.KagiRateLimitStore)(nil)

	client := setupTestClient(t)
	rateLimitStore := ent.NewKagiRateLimitStore(client)
	adaptertest.RunRateLimitStoreTests(t, rateLimitStore)
}

func TestKagiUserStore_Conformance(t *testing.T) {
	var _ kagi.UserStore = (*ent.KagiUserStore)(nil)

	client := setupTestClient(t)
	store := ent.NewKagiUserStore(client)
	adaptertest.RunUserStoreTests(t, store)
}

func TestKagiUserStore_Lifecycle(t *testing.T) {
	client := setupTestClient(t)
	store := ent.NewKagiUserStore(client)
	ctx := context.Background()

	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

	t.Run("Create user successfully", func(t *testing.T) {
		user := &kagi.User{
			Email:            "alice@example.com",
			Name:             "Alice Smith",
			EmailVerified:    true,
			TwoFactorEnabled: false,
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		err := store.Create(ctx, user)
		if err != nil {
			t.Fatalf("expected no error on Create, got %v", err)
		}
		if user.ID == "" {
			t.Fatal("expected non-empty user ID after Create")
		}

		fetched, err := store.GetByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("expected no error on GetByID, got %v", err)
		}
		if fetched.Email != "alice@example.com" {
			t.Errorf("expected email alice@example.com, got %s", fetched.Email)
		}
		if fetched.Name != "Alice Smith" {
			t.Errorf("expected name Alice Smith, got %s", fetched.Name)
		}
		if !fetched.EmailVerified {
			t.Errorf("expected email verified to be true")
		}
	})

	t.Run("Create with zero timestamps assigns defaults", func(t *testing.T) {
		user := &kagi.User{
			Email: "bob@example.com",
			Name:  "Bob Jones",
		}

		err := store.Create(ctx, user)
		if err != nil {
			t.Fatalf("expected no error on Create, got %v", err)
		}
		if user.CreatedAt.IsZero() {
			t.Error("expected non-zero CreatedAt assigned from Ent default")
		}
		if user.UpdatedAt.IsZero() {
			t.Error("expected non-zero UpdatedAt assigned from Ent default")
		}
	})

	t.Run("GetByEmail success and not found", func(t *testing.T) {
		user, err := store.GetByEmail(ctx, "alice@example.com")
		if err != nil {
			t.Fatalf("expected to find alice@example.com, got %v", err)
		}
		if user.Email != "alice@example.com" {
			t.Errorf("expected email alice@example.com, got %s", user.Email)
		}

		_, err = store.GetByEmail(ctx, "nonexistent@example.com")
		if !errors.Is(err, kagi.ErrUserNotFound) {
			t.Errorf("expected ErrUserNotFound for missing email, got %v", err)
		}
	})

	t.Run("Create duplicate email returns ErrEmailAlreadyExists", func(t *testing.T) {
		dupUser := &kagi.User{
			Email:     "alice@example.com",
			Name:      "Alice Imposter",
			CreatedAt: now,
			UpdatedAt: now,
		}

		err := store.Create(ctx, dupUser)
		if !errors.Is(err, kagi.ErrEmailAlreadyExists) {
			t.Errorf("expected ErrEmailAlreadyExists, got %v", err)
		}
	})

	t.Run("GetByID with non-existent and invalid ID", func(t *testing.T) {
		_, err := store.GetByID(ctx, "999999")
		if !errors.Is(err, kagi.ErrUserNotFound) {
			t.Errorf("expected ErrUserNotFound for missing ID, got %v", err)
		}

		_, err = store.GetByID(ctx, "not-a-valid-int-id")
		if !errors.Is(err, kagi.ErrUserNotFound) {
			t.Errorf("expected ErrUserNotFound for unparseable ID, got %v", err)
		}
	})

	t.Run("Update user", func(t *testing.T) {
		user, err := store.GetByEmail(ctx, "alice@example.com")
		if err != nil {
			t.Fatalf("failed fetching user for update: %v", err)
		}

		user.Name = "Alice Cooper"
		user.TwoFactorEnabled = true
		user.UpdatedAt = now.Add(time.Hour)

		if err := store.Update(ctx, user); err != nil {
			t.Fatalf("expected no error on Update, got %v", err)
		}

		updated, err := store.GetByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("failed fetching user after update: %v", err)
		}
		if updated.Name != "Alice Cooper" {
			t.Errorf("expected updated name Alice Cooper, got %s", updated.Name)
		}
		if !updated.TwoFactorEnabled {
			t.Errorf("expected TwoFactorEnabled to be true")
		}
	})

	t.Run("Delete user", func(t *testing.T) {
		user, err := store.GetByEmail(ctx, "alice@example.com")
		if err != nil {
			t.Fatalf("failed fetching user for delete: %v", err)
		}

		if err := store.Delete(ctx, user.ID); err != nil {
			t.Fatalf("expected no error on Delete, got %v", err)
		}

		// Verify user is gone
		_, err = store.GetByID(ctx, user.ID)
		if !errors.Is(err, kagi.ErrUserNotFound) {
			t.Errorf("expected ErrUserNotFound after deletion, got %v", err)
		}

		// Deleting again should return ErrUserNotFound
		err = store.Delete(ctx, user.ID)
		if !errors.Is(err, kagi.ErrUserNotFound) {
			t.Errorf("expected ErrUserNotFound when deleting already-deleted user, got %v", err)
		}
	})
}
