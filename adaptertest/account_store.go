package adaptertest

import (
	"context"
	"errors"
	"time"

	"github.com/kilip/kagi"
)

func runAccountStoreTests(tb TB, store kagi.AccountStore, userStore kagi.UserStore) {
	tb.Helper()

	runSubtest(tb, "AccountStore_Create", func(tb TB) {
		testAccountStore_Create(tb, store, userStore)
	})
	runSubtest(tb, "AccountStore_GetByProvider", func(tb TB) {
		testAccountStore_GetByProvider(tb, store, userStore)
	})
	runSubtest(tb, "AccountStore_ListByUserID", func(tb TB) {
		testAccountStore_ListByUserID(tb, store, userStore)
	})
	runSubtest(tb, "AccountStore_CountByUserID", func(tb TB) {
		testAccountStore_CountByUserID(tb, store, userStore)
	})
	runSubtest(tb, "AccountStore_Update", func(tb TB) {
		testAccountStore_Update(tb, store, userStore)
	})
	runSubtest(tb, "AccountStore_Delete", func(tb TB) {
		testAccountStore_Delete(tb, store, userStore)
	})
}

// provisionUser creates a valid parent User via userStore to satisfy foreign key constraints.
func provisionUser(tb TB, userStore kagi.UserStore) *kagi.User {
	tb.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	u := &kagi.User{
		Email:            uniqueEmail("parent_user"),
		Name:             "Parent User",
		EmailVerified:    true,
		TwoFactorEnabled: false,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := userStore.Create(ctx, u); err != nil {
		tb.Fatalf("provisionUser: failed to create parent user: %v", err)
		return nil
	}
	if u.ID == "" {
		tb.Fatal("provisionUser: parent user ID was not assigned")
		return nil
	}
	return u
}

func testAccountStore_Create(tb TB, store kagi.AccountStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful creation of credential account",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}
				providerAccountID := uniqueEmail("cred_acct")
				now := time.Now().UTC().Truncate(time.Second)

				account := &kagi.Account{
					UserID:            user.ID,
					Provider:          "credential",
					ProviderAccountID: providerAccountID,
					PasswordHash:      "$argon2id$v=19$m=65536,t=3,p=2$mockhash",
					CreatedAt:         now,
					UpdatedAt:         now,
				}

				err := store.Create(ctx, account)
				if err != nil {
					tb.Fatalf("expected no error on Create, got: %v", err)
					return
				}
				if account.ID == "" {
					tb.Fatal("expected non-empty string ID assigned to account.ID (ADR-0011)")
					return
				}
				if account.CreatedAt.IsZero() {
					tb.Fatal("expected non-zero CreatedAt assigned")
					return
				}
				if account.UpdatedAt.IsZero() {
					tb.Fatal("expected non-zero UpdatedAt assigned")
					return
				}

				// Verify by GetByProvider
				fetched, err := store.GetByProvider(ctx, "credential", providerAccountID)
				if err != nil {
					tb.Fatalf("expected no error on GetByProvider, got: %v", err)
					return
				}
				if fetched == nil {
					tb.Fatal("expected fetched account to be non-nil")
					return
				}
				if fetched.ID != account.ID {
					tb.Errorf("expected ID %q, got %q", account.ID, fetched.ID)
				}
				if fetched.UserID != user.ID {
					tb.Errorf("expected UserID %q, got %q", user.ID, fetched.UserID)
				}
				if fetched.Provider != "credential" {
					tb.Errorf("expected Provider %q, got %q", "credential", fetched.Provider)
				}
				if fetched.ProviderAccountID != providerAccountID {
					tb.Errorf("expected ProviderAccountID %q, got %q", providerAccountID, fetched.ProviderAccountID)
				}
				if fetched.PasswordHash != account.PasswordHash {
					tb.Errorf("expected PasswordHash %q, got %q", account.PasswordHash, fetched.PasswordHash)
				}
			},
		},
		{
			name: "successful creation of oauth account with tokens and expiry",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}
				providerAccountID := uniqueID("google_sub")
				expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)

				account := &kagi.Account{
					UserID:            user.ID,
					Provider:          "google",
					ProviderAccountID: providerAccountID,
					AccessToken:       "ya29.sample_access_token",
					RefreshToken:      "1//sample_refresh_token",
					TokenExpiresAt:    &expiry,
				}

				err := store.Create(ctx, account)
				if err != nil {
					tb.Fatalf("expected no error on Create, got: %v", err)
					return
				}
				if account.ID == "" {
					tb.Fatal("expected non-empty string ID assigned to account.ID")
					return
				}
				if account.CreatedAt.IsZero() {
					tb.Fatal("expected non-zero CreatedAt assigned")
					return
				}
				if account.UpdatedAt.IsZero() {
					tb.Fatal("expected non-zero UpdatedAt assigned")
					return
				}

				fetched, err := store.GetByProvider(ctx, "google", providerAccountID)
				if err != nil {
					tb.Fatalf("expected no error on GetByProvider, got: %v", err)
					return
				}
				if fetched == nil {
					tb.Fatal("expected non-nil fetched account")
					return
				}
				if fetched.AccessToken != "ya29.sample_access_token" {
					tb.Errorf("expected AccessToken %q, got %q", "ya29.sample_access_token", fetched.AccessToken)
				}
				if fetched.RefreshToken != "1//sample_refresh_token" {
					tb.Errorf("expected RefreshToken %q, got %q", "1//sample_refresh_token", fetched.RefreshToken)
				}
				if fetched.TokenExpiresAt == nil {
					tb.Fatal("expected non-nil TokenExpiresAt")
					return
				} else if !fetched.TokenExpiresAt.Equal(expiry) {
					tb.Errorf("expected TokenExpiresAt %v, got %v", expiry, *fetched.TokenExpiresAt)
				}
			},
		},
		{
			name: "successful creation with zero timestamps assigns defaults",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}
				account := &kagi.Account{
					UserID:            user.ID,
					Provider:          "github",
					ProviderAccountID: uniqueID("gh_user"),
				}

				err := store.Create(ctx, account)
				if err != nil {
					tb.Fatalf("expected no error on Create, got: %v", err)
					return
				}
				if account.ID == "" {
					tb.Fatal("expected non-empty string ID assigned")
					return
				}
				if account.CreatedAt.IsZero() {
					tb.Fatal("expected non-zero CreatedAt assigned")
					return
				}
				if account.UpdatedAt.IsZero() {
					tb.Fatal("expected non-zero UpdatedAt assigned")
					return
				}
			},
		},
		{
			name: "duplicate provider and providerAccountID conflict returns ErrAccountAlreadyExists",
			run: func(tb TB) {
				user1 := provisionUser(tb, userStore)
				user2 := provisionUser(tb, userStore)
				if user1 == nil || user2 == nil {
					return
				}
				provider := "github"
				providerAccountID := uniqueID("gh_dup")

				acct1 := &kagi.Account{
					UserID:            user1.ID,
					Provider:          provider,
					ProviderAccountID: providerAccountID,
				}
				if err := store.Create(ctx, acct1); err != nil {
					tb.Fatalf("failed to create initial account: %v", err)
					return
				}

				acct2 := &kagi.Account{
					UserID:            user2.ID,
					Provider:          provider,
					ProviderAccountID: providerAccountID,
				}
				err := store.Create(ctx, acct2)
				if err == nil {
					tb.Fatal("expected error on duplicate (provider, providerAccountID), got nil")
					return
				}
				if !errors.Is(err, kagi.ErrAccountAlreadyExists) {
					tb.Fatalf("expected ErrAccountAlreadyExists, got: %v", err)
					return
				}
			},
		},
		{
			name: "distinct providers with same providerAccountID succeed",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}
				commonAccountID := uniqueID("common_sub")

				acctGoogle := &kagi.Account{
					UserID:            user.ID,
					Provider:          "google",
					ProviderAccountID: commonAccountID,
				}
				if err := store.Create(ctx, acctGoogle); err != nil {
					tb.Fatalf("failed creating google account: %v", err)
					return
				}

				acctGitHub := &kagi.Account{
					UserID:            user.ID,
					Provider:          "github",
					ProviderAccountID: commonAccountID,
				}
				if err := store.Create(ctx, acctGitHub); err != nil {
					tb.Fatalf("expected distinct provider to succeed, got: %v", err)
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

func testAccountStore_GetByProvider(tb TB, store kagi.AccountStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	user := provisionUser(tb, userStore)
	if user == nil {
		return
	}
	provider := "credential"
	providerAccountID := uniqueEmail("getbyprovider")
	account := &kagi.Account{
		UserID:            user.ID,
		Provider:          provider,
		ProviderAccountID: providerAccountID,
		PasswordHash:      "hashed_credential_password",
	}
	if err := store.Create(ctx, account); err != nil {
		tb.Fatalf("failed to create test account: %v", err)
		return
	}

	tests := []struct {
		name              string
		provider          string
		providerAccountID string
		wantErr           error
		assertAccount     func(tb TB, a *kagi.Account)
	}{
		{
			name:              "existing account",
			provider:          provider,
			providerAccountID: providerAccountID,
			wantErr:           nil,
			assertAccount: func(tb TB, a *kagi.Account) {
				if a == nil {
					tb.Fatal("expected non-nil account")
					return
				}
				if a.ID != account.ID {
					tb.Errorf("expected ID %q, got %q", account.ID, a.ID)
				}
				if a.UserID != user.ID {
					tb.Errorf("expected UserID %q, got %q", user.ID, a.UserID)
				}
				if a.Provider != provider {
					tb.Errorf("expected Provider %q, got %q", provider, a.Provider)
				}
				if a.ProviderAccountID != providerAccountID {
					tb.Errorf("expected ProviderAccountID %q, got %q", providerAccountID, a.ProviderAccountID)
				}
				if a.PasswordHash != "hashed_credential_password" {
					tb.Errorf("expected PasswordHash match, got %q", a.PasswordHash)
				}
			},
		},
		{
			name:              "missing providerAccountID returns ErrAccountNotFound",
			provider:          provider,
			providerAccountID: uniqueID("missing_account_id"),
			wantErr:           kagi.ErrAccountNotFound,
			assertAccount: func(tb TB, a *kagi.Account) {
				if a != nil {
					tb.Errorf("expected nil account for missing ID, got %+v", a)
				}
			},
		},
		{
			name:              "missing provider returns ErrAccountNotFound",
			provider:          uniqueID("nonexistent_provider"),
			providerAccountID: providerAccountID,
			wantErr:           kagi.ErrAccountNotFound,
			assertAccount: func(tb TB, a *kagi.Account) {
				if a != nil {
					tb.Errorf("expected nil account for missing provider, got %+v", a)
				}
			},
		},
		{
			name:              "empty provider and account ID returns ErrAccountNotFound",
			provider:          "",
			providerAccountID: "",
			wantErr:           kagi.ErrAccountNotFound,
			assertAccount: func(tb TB, a *kagi.Account) {
				if a != nil {
					tb.Errorf("expected nil account for empty keys, got %+v", a)
				}
			},
		},
	}

	for _, tc := range tests {
		runSubtest(tb, tc.name, func(tb TB) {
			a, err := store.GetByProvider(ctx, tc.provider, tc.providerAccountID)
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
			if tc.assertAccount != nil {
				tc.assertAccount(tb, a)
			}
		})
	}
}

func testAccountStore_ListByUserID(tb TB, store kagi.AccountStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "user with no accounts returns non-nil empty slice",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}

				accounts, err := store.ListByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("expected no error on ListByUserID, got: %v", err)
					return
				}
				if accounts == nil {
					tb.Fatal("expected non-nil empty slice []*Account{}, got nil")
					return
				}
				if len(accounts) != 0 {
					tb.Fatalf("expected 0 accounts for new user, got %d", len(accounts))
					return
				}
			},
		},
		{
			name: "nonexistent user returns non-nil empty slice",
			run: func(tb TB) {
				accounts, err := store.ListByUserID(ctx, uniqueID("nonexistent_user"))
				if err != nil {
					tb.Fatalf("expected no error on nonexistent user, got: %v", err)
					return
				}
				if accounts == nil {
					tb.Fatal("expected non-nil empty slice []*Account{}, got nil")
					return
				}
				if len(accounts) != 0 {
					tb.Fatalf("expected 0 accounts, got %d", len(accounts))
					return
				}
			},
		},
		{
			name: "single linked account",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}
				account := &kagi.Account{
					UserID:            user.ID,
					Provider:          "credential",
					ProviderAccountID: uniqueEmail("single_acct"),
				}
				if err := store.Create(ctx, account); err != nil {
					tb.Fatalf("failed to create account: %v", err)
					return
				}

				accounts, err := store.ListByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("expected no error, got: %v", err)
					return
				}
				if accounts == nil {
					tb.Fatal("expected non-nil accounts slice")
					return
				}
				if len(accounts) != 1 {
					tb.Fatalf("expected 1 account, got %d", len(accounts))
					return
				}
				if accounts[0].ID != account.ID {
					tb.Errorf("expected account ID %q, got %q", account.ID, accounts[0].ID)
				}
				if accounts[0].UserID != user.ID {
					tb.Errorf("expected UserID %q, got %q", user.ID, accounts[0].UserID)
				}
			},
		},
		{
			name: "multiple linked accounts",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}

				providers := []string{"credential", "google", "github"}
				createdIDs := make(map[string]bool)

				for _, p := range providers {
					acct := &kagi.Account{
						UserID:            user.ID,
						Provider:          p,
						ProviderAccountID: uniqueID(p),
					}
					if err := store.Create(ctx, acct); err != nil {
						tb.Fatalf("failed creating account for %s: %v", p, err)
						return
					}
					createdIDs[acct.ID] = true
				}

				accounts, err := store.ListByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("expected no error, got: %v", err)
					return
				}
				if len(accounts) != 3 {
					tb.Fatalf("expected 3 accounts, got %d", len(accounts))
					return
				}

				for _, a := range accounts {
					if !createdIDs[a.ID] {
						tb.Errorf("unexpected account ID %q in list", a.ID)
					}
					if a.UserID != user.ID {
						tb.Errorf("account %q has UserID %q, expected %q", a.ID, a.UserID, user.ID)
					}
				}
			},
		},
		{
			name: "isolation between users",
			run: func(tb TB) {
				userA := provisionUser(tb, userStore)
				userB := provisionUser(tb, userStore)
				if userA == nil || userB == nil {
					return
				}

				acctA1 := &kagi.Account{UserID: userA.ID, Provider: "google", ProviderAccountID: uniqueID("ga1")}
				acctA2 := &kagi.Account{UserID: userA.ID, Provider: "github", ProviderAccountID: uniqueID("ga2")}
				acctB1 := &kagi.Account{UserID: userB.ID, Provider: "google", ProviderAccountID: uniqueID("gb1")}

				if err := store.Create(ctx, acctA1); err != nil {
					tb.Fatalf("failed creating acctA1: %v", err)
					return
				}
				if err := store.Create(ctx, acctA2); err != nil {
					tb.Fatalf("failed creating acctA2: %v", err)
					return
				}
				if err := store.Create(ctx, acctB1); err != nil {
					tb.Fatalf("failed creating acctB1: %v", err)
					return
				}

				listA, err := store.ListByUserID(ctx, userA.ID)
				if err != nil {
					tb.Fatalf("failed listing accounts for user A: %v", err)
					return
				}
				if len(listA) != 2 {
					tb.Fatalf("expected 2 accounts for user A, got %d", len(listA))
					return
				}

				listB, err := store.ListByUserID(ctx, userB.ID)
				if err != nil {
					tb.Fatalf("failed listing accounts for user B: %v", err)
					return
				}
				if len(listB) != 1 {
					tb.Fatalf("expected 1 account for user B, got %d", len(listB))
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

func testAccountStore_CountByUserID(tb TB, store kagi.AccountStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "zero for user with no accounts",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}

				count, err := store.CountByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("expected no error on CountByUserID, got: %v", err)
					return
				}
				if count != 0 {
					tb.Fatalf("expected count 0, got %d", count)
					return
				}
			},
		},
		{
			name: "zero for non-existent user",
			run: func(tb TB) {
				count, err := store.CountByUserID(ctx, uniqueID("nonexistent_user"))
				if err != nil {
					tb.Fatalf("expected no error on CountByUserID for missing user, got: %v", err)
					return
				}
				if count != 0 {
					tb.Fatalf("expected count 0, got %d", count)
					return
				}
			},
		},
		{
			name: "increments and decrements on creation and deletion",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}

				acct1 := &kagi.Account{UserID: user.ID, Provider: "credential", ProviderAccountID: uniqueEmail("cnt1")}
				if err := store.Create(ctx, acct1); err != nil {
					tb.Fatalf("failed creating acct1: %v", err)
					return
				}

				count, err := store.CountByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("CountByUserID failed: %v", err)
					return
				}
				if count != 1 {
					tb.Fatalf("expected count 1, got %d", count)
					return
				}

				acct2 := &kagi.Account{UserID: user.ID, Provider: "google", ProviderAccountID: uniqueID("cnt2")}
				if err := store.Create(ctx, acct2); err != nil {
					tb.Fatalf("failed creating acct2: %v", err)
					return
				}

				count, err = store.CountByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("CountByUserID failed: %v", err)
					return
				}
				if count != 2 {
					tb.Fatalf("expected count 2, got %d", count)
					return
				}

				// Delete one account
				if err := store.Delete(ctx, acct1.ID); err != nil {
					tb.Fatalf("failed deleting acct1: %v", err)
					return
				}

				count, err = store.CountByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("CountByUserID failed: %v", err)
					return
				}
				if count != 1 {
					tb.Fatalf("expected count 1 after deleting one account, got %d", count)
					return
				}

				// Delete second account
				if err := store.Delete(ctx, acct2.ID); err != nil {
					tb.Fatalf("failed deleting acct2: %v", err)
					return
				}

				count, err = store.CountByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("CountByUserID failed: %v", err)
					return
				}
				if count != 0 {
					tb.Fatalf("expected count 0 after deleting all accounts, got %d", count)
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

func testAccountStore_Update(tb TB, store kagi.AccountStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful credential update",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}
				account := &kagi.Account{
					UserID:            user.ID,
					Provider:          "credential",
					ProviderAccountID: uniqueEmail("upd_cred"),
					PasswordHash:      "old_password_hash",
				}
				if err := store.Create(ctx, account); err != nil {
					tb.Fatalf("failed creating account: %v", err)
					return
				}

				account.PasswordHash = "new_argon2id_password_hash"
				newUpdate := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
				account.UpdatedAt = newUpdate

				if err := store.Update(ctx, account); err != nil {
					tb.Fatalf("expected no error on Update, got: %v", err)
					return
				}

				fetched, err := store.GetByProvider(ctx, account.Provider, account.ProviderAccountID)
				if err != nil {
					tb.Fatalf("failed fetching updated account: %v", err)
					return
				}
				if fetched == nil {
					tb.Fatal("expected non-nil fetched account")
					return
				}
				if fetched.PasswordHash != "new_argon2id_password_hash" {
					tb.Errorf("expected updated PasswordHash, got %q", fetched.PasswordHash)
				}
			},
		},
		{
			name: "successful oauth tokens and expiry update",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}
				account := &kagi.Account{
					UserID:            user.ID,
					Provider:          "google",
					ProviderAccountID: uniqueID("upd_oauth"),
					AccessToken:       "initial_token",
					RefreshToken:      "initial_refresh",
				}
				if err := store.Create(ctx, account); err != nil {
					tb.Fatalf("failed creating account: %v", err)
					return
				}

				newExpiry := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
				account.AccessToken = "updated_access_token"
				account.RefreshToken = "updated_refresh_token"
				account.TokenExpiresAt = &newExpiry

				if err := store.Update(ctx, account); err != nil {
					tb.Fatalf("expected no error updating oauth fields: %v", err)
					return
				}

				fetched, err := store.GetByProvider(ctx, account.Provider, account.ProviderAccountID)
				if err != nil {
					tb.Fatalf("failed fetching updated oauth account: %v", err)
					return
				}
				if fetched == nil {
					tb.Fatal("expected non-nil fetched account")
					return
				}
				if fetched.AccessToken != "updated_access_token" {
					tb.Errorf("expected AccessToken %q, got %q", "updated_access_token", fetched.AccessToken)
				}
				if fetched.RefreshToken != "updated_refresh_token" {
					tb.Errorf("expected RefreshToken %q, got %q", "updated_refresh_token", fetched.RefreshToken)
				}
				if fetched.TokenExpiresAt == nil || !fetched.TokenExpiresAt.Equal(newExpiry) {
					tb.Errorf("expected TokenExpiresAt %v, got %v", newExpiry, fetched.TokenExpiresAt)
				}
			},
		},
		{
			name: "missing account returns ErrAccountNotFound",
			run: func(tb TB) {
				missingAcct := &kagi.Account{
					ID:                uniqueID("nonexistent_account"),
					UserID:            uniqueID("some_user"),
					Provider:          "google",
					ProviderAccountID: uniqueID("missing_sub"),
				}
				err := store.Update(ctx, missingAcct)
				if err == nil {
					tb.Fatal("expected error updating missing account, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrAccountNotFound) {
					tb.Fatalf("expected ErrAccountNotFound, got: %v", err)
					return
				}
			},
		},
		{
			name: "unparseable ID returns ErrAccountNotFound",
			run: func(tb TB) {
				invalidAcct := &kagi.Account{
					ID:                "unparseable-id-!@#$%",
					UserID:            uniqueID("some_user"),
					Provider:          "google",
					ProviderAccountID: uniqueID("invalid_sub"),
				}
				err := store.Update(ctx, invalidAcct)
				if err == nil {
					tb.Fatal("expected error on unparseable ID, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrAccountNotFound) {
					tb.Fatalf("expected ErrAccountNotFound, got: %v", err)
					return
				}
			},
		},
		{
			name: "duplicate conflict on provider and providerAccountID update returns ErrAccountAlreadyExists",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}
				provider := "google"
				sub1 := uniqueID("sub1")
				sub2 := uniqueID("sub2")

				acct1 := &kagi.Account{UserID: user.ID, Provider: provider, ProviderAccountID: sub1}
				if err := store.Create(ctx, acct1); err != nil {
					tb.Fatalf("failed creating acct1: %v", err)
					return
				}

				acct2 := &kagi.Account{UserID: user.ID, Provider: provider, ProviderAccountID: sub2}
				if err := store.Create(ctx, acct2); err != nil {
					tb.Fatalf("failed creating acct2: %v", err)
					return
				}

				// Try updating acct2's ProviderAccountID to sub1
				acct2.ProviderAccountID = sub1
				err := store.Update(ctx, acct2)
				if err == nil {
					tb.Fatal("expected error on conflicting provider and providerAccountID, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrAccountAlreadyExists) {
					tb.Fatalf("expected ErrAccountAlreadyExists, got: %v", err)
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

func testAccountStore_Delete(tb TB, store kagi.AccountStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful deletion",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}
				provider := "credential"
				providerAccountID := uniqueEmail("del_acct")

				account := &kagi.Account{
					UserID:            user.ID,
					Provider:          provider,
					ProviderAccountID: providerAccountID,
				}
				if err := store.Create(ctx, account); err != nil {
					tb.Fatalf("failed creating account: %v", err)
					return
				}

				if err := store.Delete(ctx, account.ID); err != nil {
					tb.Fatalf("expected no error on Delete, got: %v", err)
					return
				}

				// GetByProvider should return ErrAccountNotFound
				_, err := store.GetByProvider(ctx, provider, providerAccountID)
				if !errors.Is(err, kagi.ErrAccountNotFound) {
					tb.Fatalf("expected ErrAccountNotFound after deletion, got: %v", err)
					return
				}

				// ListByUserID should be empty
				list, err := store.ListByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("ListByUserID failed: %v", err)
					return
				}
				if len(list) != 0 {
					tb.Fatalf("expected 0 accounts in list after deletion, got %d", len(list))
					return
				}

				// Count should be 0
				count, err := store.CountByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("CountByUserID failed: %v", err)
					return
				}
				if count != 0 {
					tb.Fatalf("expected count 0 after deletion, got %d", count)
					return
				}
			},
		},
		{
			name: "deleting already deleted account returns ErrAccountNotFound",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				if user == nil {
					return
				}
				account := &kagi.Account{
					UserID:            user.ID,
					Provider:          "github",
					ProviderAccountID: uniqueID("del_twice"),
				}
				if err := store.Create(ctx, account); err != nil {
					tb.Fatalf("failed creating account: %v", err)
					return
				}
				if err := store.Delete(ctx, account.ID); err != nil {
					tb.Fatalf("failed first delete: %v", err)
					return
				}

				err := store.Delete(ctx, account.ID)
				if err == nil {
					tb.Fatal("expected error on second Delete, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrAccountNotFound) {
					tb.Fatalf("expected ErrAccountNotFound, got: %v", err)
					return
				}
			},
		},
		{
			name: "deleting non-existent ID returns ErrAccountNotFound",
			run: func(tb TB) {
				err := store.Delete(ctx, uniqueID("nonexistent_account"))
				if err == nil {
					tb.Fatal("expected error deleting non-existent ID, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrAccountNotFound) {
					tb.Fatalf("expected ErrAccountNotFound, got: %v", err)
					return
				}
			},
		},
		{
			name: "deleting unparseable ID returns ErrAccountNotFound",
			run: func(tb TB) {
				err := store.Delete(ctx, "unparseable-id-!@#$%")
				if err == nil {
					tb.Fatal("expected error on unparseable ID, got nil")
					return
				}
				if !errors.Is(err, kagi.ErrAccountNotFound) {
					tb.Fatalf("expected ErrAccountNotFound, got: %v", err)
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
