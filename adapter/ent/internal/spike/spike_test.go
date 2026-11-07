package spike_test

import (
	"context"
	"errors"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"

	"github.com/kilip/kagi"
	kagientc "github.com/kilip/kagi/adapter/ent/entc"
	"github.com/kilip/kagi/adapter/ent/internal/spike/ent"
	"github.com/kilip/kagi/adapter/ent/internal/spike/ent/hook"
	"github.com/kilip/kagi/adapter/ent/internal/spike/ent/user"
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

	for _, name := range []string{"kagi_user_store.go", "kagi_account_store.go", "kagi_session_store.go", "kagi_verification_store.go", "kagi_rate_limit_store.go", "kagi_adapter.go"} {
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
func TestKagiAdapter_FullConformance(t *testing.T) {
	client := setupTestClient(t)
	adapter := ent.NewKagiAdapter(client)
	adaptertest.RunAll(t, adapter.AsAdaptertestStores())
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

func TestKagiUserStore_ExtraFieldsHooks(t *testing.T) {
	ctx := context.Background()

	t.Run("Create and Update with hooks", func(t *testing.T) {
		client := setupTestClient(t)
		store := ent.NewKagiUserStore(client,
			ent.WithUserCreateHook(func(ctx context.Context, b *ent.UserCreate, u *kagi.User) error {
				b.SetTenantID("tenant-123")
				b.SetAvatarURL("https://example.com/custom.png")
				return nil
			}),
			ent.WithUserUpdateHook(func(ctx context.Context, b *ent.UserUpdateOne, u *kagi.User) error {
				b.SetAvatarURL("https://example.com/updated.png")
				return nil
			}),
		)

		userToCreate := &kagi.User{
			Email: "hook-user@example.com",
			Name:  "Hook User",
		}

		if err := store.Create(ctx, userToCreate); err != nil {
			t.Fatalf("failed to create user with hook: %v", err)
		}

		id, err := strconv.Atoi(userToCreate.ID)
		if err != nil {
			t.Fatalf("failed to parse user ID %q: %v", userToCreate.ID, err)
		}

		entUser, err := client.User.Get(ctx, id)
		if err != nil {
			t.Fatalf("failed to fetch user directly via ent client: %v", err)
		}
		if entUser.TenantID != "tenant-123" {
			t.Errorf("expected tenant_id 'tenant-123', got %q", entUser.TenantID)
		}
		if entUser.AvatarURL != "https://example.com/custom.png" {
			t.Errorf("expected avatar_url 'https://example.com/custom.png', got %q", entUser.AvatarURL)
		}

		// Update via store
		userToCreate.Name = "Hook User Updated"
		if err := store.Update(ctx, userToCreate); err != nil {
			t.Fatalf("failed to update user with hook: %v", err)
		}

		updatedEntUser, err := client.User.Get(ctx, id)
		if err != nil {
			t.Fatalf("failed to fetch updated user directly: %v", err)
		}
		if updatedEntUser.AvatarURL != "https://example.com/updated.png" {
			t.Errorf("expected avatar_url 'https://example.com/updated.png', got %q", updatedEntUser.AvatarURL)
		}
		if updatedEntUser.TenantID != "tenant-123" {
			t.Errorf("expected tenant_id to remain 'tenant-123', got %q", updatedEntUser.TenantID)
		}
	})

	t.Run("Create hook error propagation", func(t *testing.T) {
		client := setupTestClient(t)
		errHook := errors.New("abort user creation")
		store := ent.NewKagiUserStore(client,
			ent.WithUserCreateHook(func(ctx context.Context, b *ent.UserCreate, u *kagi.User) error {
				return errHook
			}),
		)

		userToCreate := &kagi.User{
			Email: "fail-create@example.com",
			Name:  "Fail Create",
		}

		err := store.Create(ctx, userToCreate)
		if !errors.Is(err, errHook) {
			t.Fatalf("expected error %v, got %v", errHook, err)
		}

		exists, err := client.User.Query().Where(user.EmailEQ("fail-create@example.com")).Exist(ctx)
		if err != nil {
			t.Fatalf("failed checking user existence: %v", err)
		}
		if exists {
			t.Errorf("expected user not to be created in database")
		}
	})

	t.Run("Update hook error propagation", func(t *testing.T) {
		client := setupTestClient(t)
		errHook := errors.New("abort user update")

		store := ent.NewKagiUserStore(client,
			ent.WithUserUpdateHook(func(ctx context.Context, b *ent.UserUpdateOne, u *kagi.User) error {
				return errHook
			}),
		)

		userToCreate := &kagi.User{
			Email: "fail-update@example.com",
			Name:  "Original Name",
		}
		if err := store.Create(ctx, userToCreate); err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		id, err := strconv.Atoi(userToCreate.ID)
		if err != nil {
			t.Fatalf("failed to parse user ID: %v", err)
		}

		userToCreate.Name = "New Name"
		err = store.Update(ctx, userToCreate)
		if !errors.Is(err, errHook) {
			t.Fatalf("expected error %v, got %v", errHook, err)
		}

		entUser, err := client.User.Get(ctx, id)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if entUser.Name != "Original Name" {
			t.Errorf("expected name to remain 'Original Name', got %q", entUser.Name)
		}
	})
}

func TestKagiUserStore_NativeEntHooks(t *testing.T) {
	ctx := context.Background()
	client := setupTestClient(t)

	type contextKey string
	const tenantKey contextKey = "tenant_id"

	client.User.Use(func(next ent.Mutator) ent.Mutator {
		return hook.UserFunc(func(ctx context.Context, m *ent.UserMutation) (ent.Value, error) {
			if m.Op().Is(ent.OpCreate) {
				if tenant, ok := ctx.Value(tenantKey).(string); ok {
					m.SetTenantID(tenant)
				}
			}
			return next.Mutate(ctx, m)
		})
	})

	store := ent.NewKagiUserStore(client)

	tenantCtx := context.WithValue(ctx, tenantKey, "tenant-native-999")
	userToCreate := &kagi.User{
		Email: "native-hook@example.com",
		Name:  "Native Hook User",
	}

	if err := store.Create(tenantCtx, userToCreate); err != nil {
		t.Fatalf("failed to create user with native hook: %v", err)
	}

	id, err := strconv.Atoi(userToCreate.ID)
	if err != nil {
		t.Fatalf("failed to parse user ID %q: %v", userToCreate.ID, err)
	}

	entUser, err := client.User.Get(ctx, id)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if entUser.TenantID != "tenant-native-999" {
		t.Errorf("expected tenant_id 'tenant-native-999', got %q", entUser.TenantID)
	}
	if entUser.AvatarURL != "https://example.com/default.png" {
		t.Errorf("expected default avatar_url, got %q", entUser.AvatarURL)
	}
}

func TestKagiAdapter_WithForwardedOptions(t *testing.T) {
	ctx := context.Background()
	client := setupTestClient(t)

	adapter := ent.NewKagiAdapter(client,
		ent.WithUserStoreOptions(
			ent.WithUserCreateHook(func(ctx context.Context, b *ent.UserCreate, u *kagi.User) error {
				b.SetTenantID("tenant-forwarded-888")
				return nil
			}),
		),
	)

	userToCreate := &kagi.User{
		Email: "forwarded-opt@example.com",
		Name:  "Forwarded Option User",
	}

	if err := adapter.User.Create(ctx, userToCreate); err != nil {
		t.Fatalf("failed to create user via adapter: %v", err)
	}

	id, err := strconv.Atoi(userToCreate.ID)
	if err != nil {
		t.Fatalf("failed to parse user ID %q: %v", userToCreate.ID, err)
	}

	entUser, err := client.User.Get(ctx, id)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if entUser.TenantID != "tenant-forwarded-888" {
		t.Errorf("expected tenant_id 'tenant-forwarded-888', got %q", entUser.TenantID)
	}
}
