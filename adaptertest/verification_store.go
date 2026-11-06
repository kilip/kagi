package adaptertest

import (
	"context"
	"errors"
	"time"

	"github.com/kilip/kagi"
)

func runVerificationStoreTests(tb TB, store kagi.VerificationStore) {
	tb.Helper()

	runSubtest(tb, "VerificationStore_Create", func(tb TB) {
		testVerificationStore_Create(tb, store)
	})
	runSubtest(tb, "VerificationStore_Get", func(tb TB) {
		testVerificationStore_Get(tb, store)
	})
	runSubtest(tb, "VerificationStore_Update", func(tb TB) {
		testVerificationStore_Update(tb, store)
	})
	runSubtest(tb, "VerificationStore_Delete", func(tb TB) {
		testVerificationStore_Delete(tb, store)
	})
	runSubtest(tb, "VerificationStore_DeleteExpired", func(tb TB) {
		testVerificationStore_DeleteExpired(tb, store)
	})
}

func testVerificationStore_Create(tb TB, store kagi.VerificationStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful creation assigns string ID and timestamps",
			run: func(tb TB) {
				target := uniqueEmail("verify_create")
				codeHash := uniqueTokenHash("otp_code")
				now := time.Now().UTC().Truncate(time.Second)
				expiresAt := now.Add(15 * time.Minute)

				v := &kagi.Verification{
					Target:    target,
					Type:      kagi.VerificationTypeLogin,
					CodeHash:  codeHash,
					ExpiresAt: expiresAt,
					Attempts:  0,
					CreatedAt: now,
					UpdatedAt: now,
				}

				err := store.Create(ctx, v)
				if err != nil {
					tb.Fatalf("expected no error on Create, got: %v", err)
				}
				if v.ID == "" {
					tb.Fatal("expected non-empty string ID assigned to v.ID (ADR-0011)")
				}
				if v.CreatedAt.IsZero() {
					tb.Fatal("expected non-zero CreatedAt assigned")
				}
				if v.UpdatedAt.IsZero() {
					tb.Fatal("expected non-zero UpdatedAt assigned")
				}

				// Verify retrieval
				got, err := store.Get(ctx, target, kagi.VerificationTypeLogin)
				if err != nil {
					tb.Fatalf("expected Get to find newly created verification, got: %v", err)
				}
				if got.ID != v.ID {
					tb.Fatalf("expected ID %q, got %q", v.ID, got.ID)
				}
				if got.Target != target {
					tb.Fatalf("expected Target %q, got %q", target, got.Target)
				}
				if got.Type != kagi.VerificationTypeLogin {
					tb.Fatalf("expected Type %v, got %v", kagi.VerificationTypeLogin, got.Type)
				}
				if got.CodeHash != codeHash {
					tb.Fatalf("expected CodeHash %q, got %q", codeHash, got.CodeHash)
				}
				if got.Attempts != 0 {
					tb.Fatalf("expected Attempts 0, got %d", got.Attempts)
				}
			},
		},
		{
			name: "create distinct verification records for different types on same target",
			run: func(tb TB) {
				target := uniqueEmail("verify_types")
				vLogin := &kagi.Verification{
					Target:    target,
					Type:      kagi.VerificationTypeLogin,
					CodeHash:  uniqueTokenHash("login_hash"),
					ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
				}
				vTwoFactor := &kagi.Verification{
					Target:    target,
					Type:      kagi.VerificationTypeTwoFactor,
					CodeHash:  uniqueTokenHash("2fa_hash"),
					ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
				}

				if err := store.Create(ctx, vLogin); err != nil {
					tb.Fatalf("failed to create login verification: %v", err)
				}
				if err := store.Create(ctx, vTwoFactor); err != nil {
					tb.Fatalf("failed to create 2fa verification: %v", err)
				}

				gotLogin, err := store.Get(ctx, target, kagi.VerificationTypeLogin)
				if err != nil {
					tb.Fatalf("failed to get login verification: %v", err)
				}
				if gotLogin.ID != vLogin.ID {
					tb.Fatalf("expected login ID %q, got %q", vLogin.ID, gotLogin.ID)
				}

				gotTwoFactor, err := store.Get(ctx, target, kagi.VerificationTypeTwoFactor)
				if err != nil {
					tb.Fatalf("failed to get 2fa verification: %v", err)
				}
				if gotTwoFactor.ID != vTwoFactor.ID {
					tb.Fatalf("expected 2fa ID %q, got %q", vTwoFactor.ID, gotTwoFactor.ID)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testVerificationStore_Get(tb TB, store kagi.VerificationStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "active verification retrieval returns unexpired record",
			run: func(tb TB) {
				target := uniqueEmail("get_active")
				v := &kagi.Verification{
					Target:    target,
					Type:      kagi.VerificationTypeEmailVerify,
					CodeHash:  uniqueTokenHash("email_verify_hash"),
					ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
				}
				if err := store.Create(ctx, v); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				got, err := store.Get(ctx, target, kagi.VerificationTypeEmailVerify)
				if err != nil {
					tb.Fatalf("expected active verification retrieval, got: %v", err)
				}
				if got.ID != v.ID {
					tb.Fatalf("expected ID %q, got %q", v.ID, got.ID)
				}
			},
		},
		{
			name: "non-existent target or type returns ErrVerificationNotFound",
			run: func(tb TB) {
				got, err := store.Get(ctx, "non_existent_target@example.com", kagi.VerificationTypeLogin)
				if !errors.Is(err, kagi.ErrVerificationNotFound) {
					tb.Fatalf("expected ErrVerificationNotFound for non-existent target, got: %v", err)
				}
				if got != nil {
					tb.Fatalf("expected nil result, got: %+v", got)
				}
			},
		},
		{
			name: "strict expiry-on-read: expired record returns ErrVerificationNotFound",
			run: func(tb TB) {
				target := uniqueEmail("get_expired")
				v := &kagi.Verification{
					Target:    target,
					Type:      kagi.VerificationTypePasswordReset,
					CodeHash:  uniqueTokenHash("reset_hash"),
					ExpiresAt: time.Now().UTC().Add(-5 * time.Minute), // expired
				}
				if err := store.Create(ctx, v); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				got, err := store.Get(ctx, target, kagi.VerificationTypePasswordReset)
				if !errors.Is(err, kagi.ErrVerificationNotFound) {
					tb.Fatalf("expected ErrVerificationNotFound for expired verification record (ADR-0010), got: %v", err)
				}
				if got != nil {
					tb.Fatalf("expected nil result for expired verification, got: %+v", got)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testVerificationStore_Update(tb TB, store kagi.VerificationStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "update attempt count and updated_at on existing active record",
			run: func(tb TB) {
				target := uniqueEmail("update_attempts")
				v := &kagi.Verification{
					Target:    target,
					Type:      kagi.VerificationTypeLogin,
					CodeHash:  uniqueTokenHash("update_hash"),
					ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
					Attempts:  0,
				}
				if err := store.Create(ctx, v); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				v.Attempts = 2
				v.UpdatedAt = time.Now().UTC()
				if err := store.Update(ctx, v); err != nil {
					tb.Fatalf("expected successful update, got: %v", err)
				}

				got, err := store.Get(ctx, target, kagi.VerificationTypeLogin)
				if err != nil {
					tb.Fatalf("expected Get to succeed after update, got: %v", err)
				}
				if got.Attempts != 2 {
					tb.Fatalf("expected Attempts 2, got %d", got.Attempts)
				}
			},
		},
		{
			name: "update non-existent verification record returns ErrVerificationNotFound",
			run: func(tb TB) {
				fake := &kagi.Verification{
					ID:        "non_existent_verification_id_9999",
					Target:    "fake@example.com",
					Type:      kagi.VerificationTypeLogin,
					CodeHash:  uniqueTokenHash("fake"),
					ExpiresAt: time.Now().UTC().Add(time.Hour),
					Attempts:  1,
				}
				err := store.Update(ctx, fake)
				if !errors.Is(err, kagi.ErrVerificationNotFound) {
					tb.Fatalf("expected ErrVerificationNotFound updating non-existent record, got: %v", err)
				}
			},
		},
		{
			name: "update expired verification record returns ErrVerificationNotFound",
			run: func(tb TB) {
				target := uniqueEmail("update_expired")
				v := &kagi.Verification{
					Target:    target,
					Type:      kagi.VerificationTypeLogin,
					CodeHash:  uniqueTokenHash("update_exp_hash"),
					ExpiresAt: time.Now().UTC().Add(-10 * time.Minute),
					Attempts:  0,
				}
				if err := store.Create(ctx, v); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				v.Attempts = 1
				err := store.Update(ctx, v)
				if !errors.Is(err, kagi.ErrVerificationNotFound) {
					tb.Fatalf("expected ErrVerificationNotFound updating expired record, got: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testVerificationStore_Delete(tb TB, store kagi.VerificationStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful delete removes verification record by ID",
			run: func(tb TB) {
				target := uniqueEmail("delete_target")
				v := &kagi.Verification{
					Target:    target,
					Type:      kagi.VerificationTypeLogin,
					CodeHash:  uniqueTokenHash("del_hash"),
					ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
				}
				if err := store.Create(ctx, v); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				if err := store.Delete(ctx, v.ID); err != nil {
					tb.Fatalf("expected successful Delete, got: %v", err)
				}

				got, err := store.Get(ctx, target, kagi.VerificationTypeLogin)
				if !errors.Is(err, kagi.ErrVerificationNotFound) {
					tb.Fatalf("expected ErrVerificationNotFound after Delete, got: %v (record: %+v)", err, got)
				}
			},
		},
		{
			name: "delete non-existent verification ID returns ErrVerificationNotFound",
			run: func(tb TB) {
				err := store.Delete(ctx, "non_existent_verification_id_9999")
				if !errors.Is(err, kagi.ErrVerificationNotFound) {
					tb.Fatalf("expected ErrVerificationNotFound deleting non-existent ID, got: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testVerificationStore_DeleteExpired(tb TB, store kagi.VerificationStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "batched cleanup removes only expired records up to batchSize without removing active records",
			run: func(tb TB) {
				// Clean any leftover expired records from prior subtests
				for {
					cleaned, err := store.DeleteExpired(ctx, 100)
					if err != nil {
						tb.Fatalf("DeleteExpired cleanup failed: %v", err)
					}
					if cleaned == 0 {
						break
					}
				}

				past := time.Now().UTC().Add(-1 * time.Hour)
				future := time.Now().UTC().Add(1 * time.Hour)

				// Create 4 expired verification records
				for range 4 {
					v := &kagi.Verification{
						Target:    uniqueEmail("exp_verif"),
						Type:      kagi.VerificationTypeLogin,
						CodeHash:  uniqueTokenHash("exp_v_hash"),
						ExpiresAt: past,
					}
					if err := store.Create(ctx, v); err != nil {
						tb.Fatalf("setup expired verification failed: %v", err)
					}
				}

				// Create 1 active verification record
				activeTarget := uniqueEmail("act_verif")
				activeV := &kagi.Verification{
					Target:    activeTarget,
					Type:      kagi.VerificationTypeLogin,
					CodeHash:  uniqueTokenHash("act_v_hash"),
					ExpiresAt: future,
				}
				if err := store.Create(ctx, activeV); err != nil {
					tb.Fatalf("setup active verification failed: %v", err)
				}

				// Run DeleteExpired with batchSize = 2
				count1, err := store.DeleteExpired(ctx, 2)
				if err != nil {
					tb.Fatalf("expected successful DeleteExpired batch 1, got: %v", err)
				}
				if count1 != 2 {
					tb.Fatalf("expected batch 1 to delete exactly 2 rows, got %d", count1)
				}

				// Run DeleteExpired with batchSize = 5 (should delete remaining 2 expired rows)
				count2, err := store.DeleteExpired(ctx, 5)
				if err != nil {
					tb.Fatalf("expected successful DeleteExpired batch 2, got: %v", err)
				}
				if count2 != 2 {
					tb.Fatalf("expected batch 2 to delete remaining 2 rows, got %d", count2)
				}

				// Run DeleteExpired again (should delete 0 rows)
				count3, err := store.DeleteExpired(ctx, 10)
				if err != nil {
					tb.Fatalf("expected successful DeleteExpired batch 3, got: %v", err)
				}
				if count3 != 0 {
					tb.Fatalf("expected batch 3 to delete 0 rows, got %d", count3)
				}

				// Active verification record must still exist and be retrievable
				gotActive, err := store.Get(ctx, activeTarget, kagi.VerificationTypeLogin)
				if err != nil {
					tb.Fatalf("expected active verification record still retrievable, got: %v", err)
				}
				if gotActive.ID != activeV.ID {
					tb.Fatalf("expected active verification ID %q, got %q", activeV.ID, gotActive.ID)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}
