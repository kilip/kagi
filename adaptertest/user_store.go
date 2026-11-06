package adaptertest

import (
	"context"
	"errors"
	"time"

	"github.com/kilip/kagi"
)

func runUserStoreTests(tb TB, store kagi.UserStore) {
	tb.Helper()

	runSubtest(tb, "UserStore_Create", func(tb TB) {
		testUserStore_Create(tb, store)
	})
	runSubtest(tb, "UserStore_GetByID", func(tb TB) {
		testUserStore_GetByID(tb, store)
	})
	runSubtest(tb, "UserStore_GetByEmail", func(tb TB) {
		testUserStore_GetByEmail(tb, store)
	})
	runSubtest(tb, "UserStore_Update", func(tb TB) {
		testUserStore_Update(tb, store)
	})
	runSubtest(tb, "UserStore_Delete", func(tb TB) {
		testUserStore_Delete(tb, store)
	})
}

func testUserStore_Create(tb TB, store kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful creation with explicit fields",
			run: func(tb TB) {
				email := uniqueEmail("create_user")
				now := time.Now().UTC().Truncate(time.Second)
				user := &kagi.User{
					Email:            email,
					Name:             "Alice Smith",
					EmailVerified:    true,
					TwoFactorEnabled: false,
					CreatedAt:        now,
					UpdatedAt:        now,
				}

				err := store.Create(ctx, user)
				if err != nil {
					tb.Fatalf("expected no error on Create, got: %v", err)
					return
				}
				if user.ID == "" {
					tb.Fatal("expected non-empty string ID assigned to user.ID (ADR-0011)")
					return
				}
				if user.CreatedAt.IsZero() {
					tb.Fatal("expected non-zero CreatedAt assigned")
					return
				}
				if user.UpdatedAt.IsZero() {
					tb.Fatal("expected non-zero UpdatedAt assigned")
					return
				}

				// Verify by fetching via GetByID
				fetched, err := store.GetByID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("expected no error on GetByID, got: %v", err)
					return
				}
				if fetched == nil {
					tb.Fatal("expected fetched user to be non-nil")
					return
				}
				if fetched.ID != user.ID {
					tb.Errorf("expected ID %q, got %q", user.ID, fetched.ID)
				}
				if fetched.Email != email {
					tb.Errorf("expected Email %q, got %q", email, fetched.Email)
				}
				if fetched.Name != "Alice Smith" {
					tb.Errorf("expected Name %q, got %q", "Alice Smith", fetched.Name)
				}
				if !fetched.EmailVerified {
					tb.Errorf("expected EmailVerified true, got false")
				}
				if fetched.TwoFactorEnabled {
					tb.Errorf("expected TwoFactorEnabled false, got true")
				}
				if fetched.CreatedAt.IsZero() {
					tb.Error("expected fetched CreatedAt to be non-zero")
				}
				if fetched.UpdatedAt.IsZero() {
					tb.Error("expected fetched UpdatedAt to be non-zero")
				}
			},
		},
		{
			name: "successful creation with zero timestamps assigns persistence defaults",
			run: func(tb TB) {
				email := uniqueEmail("zero_ts")
				user := &kagi.User{
					Email: email,
					Name:  "Bob Jones",
				}

				err := store.Create(ctx, user)
				if err != nil {
					tb.Fatalf("expected no error on Create, got: %v", err)
					return
				}
				if user.ID == "" {
					tb.Fatal("expected non-empty string ID assigned to user.ID (ADR-0011)")
					return
				}
				if user.CreatedAt.IsZero() {
					tb.Fatal("expected non-zero CreatedAt assigned by adapter")
					return
				}
				if user.UpdatedAt.IsZero() {
					tb.Fatal("expected non-zero UpdatedAt assigned by adapter")
					return
				}
			},
		},
		{
			name: "duplicate email conflict returns ErrEmailAlreadyExists",
			run: func(tb TB) {
				email := uniqueEmail("dup_user")
				u1 := &kagi.User{
					Email: email,
					Name:  "User One",
				}
				if err := store.Create(ctx, u1); err != nil {
					tb.Fatalf("failed to create first user: %v", err)
					return
				}

				u2 := &kagi.User{
					Email: email,
					Name:  "User Two",
				}
				err := store.Create(ctx, u2)
				if err == nil {
					tb.Fatal("expected error on duplicate email, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrEmailAlreadyExists) {
					tb.Fatalf("expected ErrEmailAlreadyExists, got %v", err)
					return
				}
			},
		},
	}

	for _, tc := range tests {
		runSubtest(tb, tc.name, func(tb TB) {
			tc.run(tb)
		})
	}
}

func testUserStore_GetByID(tb TB, store kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	// Provision an existing user
	existingEmail := uniqueEmail("getbyid")
	existingUser := &kagi.User{
		Email:            existingEmail,
		Name:             "Existing User",
		EmailVerified:    true,
		TwoFactorEnabled: false,
	}
	if err := store.Create(ctx, existingUser); err != nil {
		tb.Fatalf("failed to provision existing user: %v", err)
		return
	}

	tests := []struct {
		name       string
		id         string
		wantErr    error
		assertUser func(tb TB, u *kagi.User)
	}{
		{
			name:    "existing user",
			id:      existingUser.ID,
			wantErr: nil,
			assertUser: func(tb TB, u *kagi.User) {
				if u == nil {
					tb.Fatal("expected non-nil user")
					return
				}
				if u.ID != existingUser.ID {
					tb.Errorf("expected ID %q, got %q", existingUser.ID, u.ID)
				}
				if u.Email != existingEmail {
					tb.Errorf("expected Email %q, got %q", existingEmail, u.Email)
				}
				if u.Name != "Existing User" {
					tb.Errorf("expected Name %q, got %q", "Existing User", u.Name)
				}
			},
		},
		{
			name:    "missing ID returns ErrUserNotFound",
			id:      uniqueID("missing_user_id"),
			wantErr: kagi.ErrUserNotFound,
			assertUser: func(tb TB, u *kagi.User) {
				if u != nil {
					tb.Errorf("expected nil user for missing ID, got %+v", u)
				}
			},
		},
		{
			name:    "unparseable invalid ID returns ErrUserNotFound",
			id:      "invalid/unparseable/id/!@#$%",
			wantErr: kagi.ErrUserNotFound,
			assertUser: func(tb TB, u *kagi.User) {
				if u != nil {
					tb.Errorf("expected nil user for unparseable ID, got %+v", u)
				}
			},
		},
		{
			name:    "empty string ID returns ErrUserNotFound",
			id:      "",
			wantErr: kagi.ErrUserNotFound,
			assertUser: func(tb TB, u *kagi.User) {
				if u != nil {
					tb.Errorf("expected nil user for empty ID, got %+v", u)
				}
			},
		},
	}

	for _, tc := range tests {
		runSubtest(tb, tc.name, func(tb TB) {
			u, err := store.GetByID(ctx, tc.id)
			if tc.wantErr != nil {
				if err == nil {
					tb.Fatalf("expected error %v, got nil", tc.wantErr)
					return
				}
				if !errors.Is(err, tc.wantErr) {
					tb.Fatalf("expected error wrapping %v, got: %v", tc.wantErr, err)
					return
				}
			} else {
				if err != nil {
					tb.Fatalf("expected no error, got: %v", err)
					return
				}
			}
			if tc.assertUser != nil {
				tc.assertUser(tb, u)
			}
		})
	}
}

func testUserStore_GetByEmail(tb TB, store kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	existingEmail := uniqueEmail("getbyemail")
	existingUser := &kagi.User{
		Email: existingEmail,
		Name:  "Email User",
	}
	if err := store.Create(ctx, existingUser); err != nil {
		tb.Fatalf("failed to provision user: %v", err)
		return
	}

	tests := []struct {
		name       string
		email      string
		wantErr    error
		assertUser func(tb TB, u *kagi.User)
	}{
		{
			name:    "existing email",
			email:   existingEmail,
			wantErr: nil,
			assertUser: func(tb TB, u *kagi.User) {
				if u == nil {
					tb.Fatal("expected non-nil user")
					return
				}
				if u.ID != existingUser.ID {
					tb.Errorf("expected ID %q, got %q", existingUser.ID, u.ID)
				}
				if u.Email != existingEmail {
					tb.Errorf("expected Email %q, got %q", existingEmail, u.Email)
				}
			},
		},
		{
			name:    "missing email returns ErrUserNotFound",
			email:   uniqueEmail("nonexistent_email"),
			wantErr: kagi.ErrUserNotFound,
			assertUser: func(tb TB, u *kagi.User) {
				if u != nil {
					tb.Errorf("expected nil user for missing email, got %+v", u)
				}
			},
		},
		{
			name:    "empty email returns ErrUserNotFound",
			email:   "",
			wantErr: kagi.ErrUserNotFound,
			assertUser: func(tb TB, u *kagi.User) {
				if u != nil {
					tb.Errorf("expected nil user for empty email, got %+v", u)
				}
			},
		},
	}

	for _, tc := range tests {
		runSubtest(tb, tc.name, func(tb TB) {
			u, err := store.GetByEmail(ctx, tc.email)
			if tc.wantErr != nil {
				if err == nil {
					tb.Fatalf("expected error %v, got nil", tc.wantErr)
					return
				}
				if !errors.Is(err, tc.wantErr) {
					tb.Fatalf("expected error wrapping %v, got: %v", tc.wantErr, err)
					return
				}
			} else {
				if err != nil {
					tb.Fatalf("expected no error, got: %v", err)
					return
				}
			}
			if tc.assertUser != nil {
				tc.assertUser(tb, u)
			}
		})
	}
}

func testUserStore_Update(tb TB, store kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful field updates",
			run: func(tb TB) {
				user := &kagi.User{
					Email:            uniqueEmail("update_fields"),
					Name:             "Initial Name",
					EmailVerified:    false,
					TwoFactorEnabled: false,
				}
				if err := store.Create(ctx, user); err != nil {
					tb.Fatalf("failed to create user: %v", err)
					return
				}

				newUpdate := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
				user.Name = "Updated Name"
				user.EmailVerified = true
				user.TwoFactorEnabled = true
				user.UpdatedAt = newUpdate

				if err := store.Update(ctx, user); err != nil {
					tb.Fatalf("expected no error on Update, got: %v", err)
					return
				}

				fetched, err := store.GetByID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("expected no error on GetByID, got: %v", err)
					return
				}
				if fetched == nil {
					tb.Fatal("expected non-nil fetched user")
					return
				}
				if fetched.Name != "Updated Name" {
					tb.Errorf("expected Name %q, got %q", "Updated Name", fetched.Name)
				}
				if !fetched.EmailVerified {
					tb.Errorf("expected EmailVerified true, got false")
				}
				if !fetched.TwoFactorEnabled {
					tb.Errorf("expected TwoFactorEnabled true, got false")
				}
			},
		},
		{
			name: "successful email update",
			run: func(tb TB) {
				oldEmail := uniqueEmail("email_old")
				newEmail := uniqueEmail("email_new")
				user := &kagi.User{
					Email: oldEmail,
					Name:  "Email Changer",
				}
				if err := store.Create(ctx, user); err != nil {
					tb.Fatalf("failed to create user: %v", err)
					return
				}

				user.Email = newEmail
				if err := store.Update(ctx, user); err != nil {
					tb.Fatalf("expected no error updating email, got: %v", err)
					return
				}

				// Find by new email
				fetched, err := store.GetByEmail(ctx, newEmail)
				if err != nil {
					tb.Fatalf("expected to find user by new email, got: %v", err)
					return
				}
				if fetched == nil {
					tb.Fatal("expected non-nil fetched user")
					return
				}
				if fetched.ID != user.ID {
					tb.Errorf("expected ID %q, got %q", user.ID, fetched.ID)
				}

				// Old email should not be found
				_, err = store.GetByEmail(ctx, oldEmail)
				if !errors.Is(err, kagi.ErrUserNotFound) {
					tb.Fatalf("expected ErrUserNotFound for old email, got: %v", err)
					return
				}
			},
		},
		{
			name: "missing user returns ErrUserNotFound",
			run: func(tb TB) {
				missingUser := &kagi.User{
					ID:    uniqueID("nonexistent_user"),
					Email: uniqueEmail("missing_update"),
					Name:  "Nobody",
				}
				err := store.Update(ctx, missingUser)
				if err == nil {
					tb.Fatal("expected error updating missing user, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrUserNotFound) {
					tb.Fatalf("expected ErrUserNotFound, got: %v", err)
					return
				}
			},
		},
		{
			name: "unparseable ID returns ErrUserNotFound",
			run: func(tb TB) {
				invalidUser := &kagi.User{
					ID:    "unparseable-id-!@#$%",
					Email: uniqueEmail("unparseable"),
					Name:  "Invalid ID",
				}
				err := store.Update(ctx, invalidUser)
				if err == nil {
					tb.Fatal("expected error on unparseable ID, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrUserNotFound) {
					tb.Fatalf("expected ErrUserNotFound, got: %v", err)
					return
				}
			},
		},
		{
			name: "duplicate email conflict on update returns ErrEmailAlreadyExists",
			run: func(tb TB) {
				emailA := uniqueEmail("user_a")
				emailB := uniqueEmail("user_b")

				userA := &kagi.User{Email: emailA, Name: "User A"}
				if err := store.Create(ctx, userA); err != nil {
					tb.Fatalf("failed to create user A: %v", err)
					return
				}

				userB := &kagi.User{Email: emailB, Name: "User B"}
				if err := store.Create(ctx, userB); err != nil {
					tb.Fatalf("failed to create user B: %v", err)
					return
				}

				// Try to update userB's email to userA's email
				userB.Email = emailA
				err := store.Update(ctx, userB)
				if err == nil {
					tb.Fatal("expected error when updating to conflicting email, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrEmailAlreadyExists) {
					tb.Fatalf("expected ErrEmailAlreadyExists, got: %v", err)
					return
				}
			},
		},
	}

	for _, tc := range tests {
		runSubtest(tb, tc.name, func(tb TB) {
			tc.run(tb)
		})
	}
}

func testUserStore_Delete(tb TB, store kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful deletion",
			run: func(tb TB) {
				email := uniqueEmail("delete_user")
				user := &kagi.User{
					Email: email,
					Name:  "To Delete",
				}
				if err := store.Create(ctx, user); err != nil {
					tb.Fatalf("failed to create user: %v", err)
					return
				}

				if err := store.Delete(ctx, user.ID); err != nil {
					tb.Fatalf("expected no error on Delete, got: %v", err)
					return
				}

				// User should not be found by ID
				_, err := store.GetByID(ctx, user.ID)
				if !errors.Is(err, kagi.ErrUserNotFound) {
					tb.Fatalf("expected ErrUserNotFound after deletion by ID, got: %v", err)
					return
				}

				// User should not be found by Email
				_, err = store.GetByEmail(ctx, email)
				if !errors.Is(err, kagi.ErrUserNotFound) {
					tb.Fatalf("expected ErrUserNotFound after deletion by Email, got: %v", err)
					return
				}
			},
		},
		{
			name: "deleting already deleted user returns ErrUserNotFound",
			run: func(tb TB) {
				user := &kagi.User{
					Email: uniqueEmail("delete_twice"),
					Name:  "Delete Twice",
				}
				if err := store.Create(ctx, user); err != nil {
					tb.Fatalf("failed to create user: %v", err)
					return
				}
				if err := store.Delete(ctx, user.ID); err != nil {
					tb.Fatalf("failed first deletion: %v", err)
					return
				}

				err := store.Delete(ctx, user.ID)
				if err == nil {
					tb.Fatal("expected error when deleting already deleted user, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrUserNotFound) {
					tb.Fatalf("expected ErrUserNotFound, got: %v", err)
					return
				}
			},
		},
		{
			name: "deleting non-existent ID returns ErrUserNotFound",
			run: func(tb TB) {
				err := store.Delete(ctx, uniqueID("nonexistent_id"))
				if err == nil {
					tb.Fatal("expected error on non-existent ID, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrUserNotFound) {
					tb.Fatalf("expected ErrUserNotFound, got: %v", err)
					return
				}
			},
		},
		{
			name: "deleting unparseable ID returns ErrUserNotFound",
			run: func(tb TB) {
				err := store.Delete(ctx, "invalid-id-!@#$%")
				if err == nil {
					tb.Fatal("expected error on unparseable ID, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrUserNotFound) {
					tb.Fatalf("expected ErrUserNotFound, got: %v", err)
					return
				}
			},
		},
	}

	for _, tc := range tests {
		runSubtest(tb, tc.name, func(tb TB) {
			tc.run(tb)
		})
	}
}
