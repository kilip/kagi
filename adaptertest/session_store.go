package adaptertest

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/kilip/kagi"
)

func runSessionStoreTests(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()

	runSubtest(tb, "SessionStore_Create", func(tb TB) {
		testSessionStore_Create(tb, store, userStore)
	})
	runSubtest(tb, "SessionStore_GetByTokenHash", func(tb TB) {
		testSessionStore_GetByTokenHash(tb, store, userStore)
	})
	runSubtest(tb, "SessionStore_Update", func(tb TB) {
		testSessionStore_Update(tb, store, userStore)
	})
	runSubtest(tb, "SessionStore_UpdateTokenHash", func(tb TB) {
		testSessionStore_UpdateTokenHash(tb, store, userStore)
	})
	runSubtest(tb, "SessionStore_DeleteByID", func(tb TB) {
		testSessionStore_DeleteByID(tb, store, userStore)
	})
	runSubtest(tb, "SessionStore_DeleteByTokenHash", func(tb TB) {
		testSessionStore_DeleteByTokenHash(tb, store, userStore)
	})
	runSubtest(tb, "SessionStore_DeleteByUserID", func(tb TB) {
		testSessionStore_DeleteByUserID(tb, store, userStore)
	})
	runSubtest(tb, "SessionStore_DeleteOthersByUserID", func(tb TB) {
		testSessionStore_DeleteOthersByUserID(tb, store, userStore)
	})
	runSubtest(tb, "SessionStore_ListByUserID", func(tb TB) {
		testSessionStore_ListByUserID(tb, store, userStore)
	})
	runSubtest(tb, "SessionStore_DeleteExpired", func(tb TB) {
		testSessionStore_DeleteExpired(tb, store, userStore)
	})
}

// equalStringSets checks if two string slices contain the same elements regardless of order.
func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sortedA := make([]string, len(a))
	copy(sortedA, a)
	sort.Strings(sortedA)

	sortedB := make([]string, len(b))
	copy(sortedB, b)
	sort.Strings(sortedB)

	return reflect.DeepEqual(sortedA, sortedB)
}

func testSessionStore_Create(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful creation assigns string ID and timestamps",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("create_sess")
				now := time.Now().UTC().Truncate(time.Second)
				expiresAt := now.Add(24 * time.Hour)

				sess := &kagi.Session{
					UserID:     user.ID,
					TokenHash:  tokenHash,
					ExpiresAt:  expiresAt,
					IPAddress:  "192.168.1.1",
					UserAgent:  "Mozilla/5.0 TestBrowser",
					Pending2FA: false,
					CreatedAt:  now,
					UpdatedAt:  now,
				}

				err := store.Create(ctx, sess)
				if err != nil {
					tb.Fatalf("expected no error on Create, got: %v", err)
				}
				if sess.ID == "" {
					tb.Fatal("expected non-empty string ID assigned to session.ID (ADR-0011)")
				}
				if sess.CreatedAt.IsZero() {
					tb.Fatal("expected non-zero CreatedAt assigned")
				}
				if sess.UpdatedAt.IsZero() {
					tb.Fatal("expected non-zero UpdatedAt assigned")
				}
				if sess.TokenHash != tokenHash {
					tb.Fatalf("expected TokenHash %q preserved, got %q", tokenHash, sess.TokenHash)
				}

				// Verify retrieval
				got, err := store.GetByTokenHash(ctx, tokenHash)
				if err != nil {
					tb.Fatalf("expected GetByTokenHash to succeed, got: %v", err)
				}
				if got.ID != sess.ID {
					tb.Fatalf("expected ID %q, got %q", sess.ID, got.ID)
				}
				if got.UserID != user.ID {
					tb.Fatalf("expected UserID %q, got %q", user.ID, got.UserID)
				}
				if got.IPAddress != "192.168.1.1" {
					tb.Fatalf("expected IPAddress 192.168.1.1, got %q", got.IPAddress)
				}
				if got.UserAgent != "Mozilla/5.0 TestBrowser" {
					tb.Fatalf("expected UserAgent Mozilla/5.0 TestBrowser, got %q", got.UserAgent)
				}
				if got.Pending2FA != false {
					tb.Fatalf("expected Pending2FA false, got %v", got.Pending2FA)
				}
			},
		},
		{
			name: "create session with pending_2fa flag set to true",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("pending_2fa")
				expiresAt := time.Now().UTC().Add(10 * time.Minute)

				sess := &kagi.Session{
					UserID:     user.ID,
					TokenHash:  tokenHash,
					ExpiresAt:  expiresAt,
					Pending2FA: true,
				}

				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("expected no error creating pending 2FA session, got: %v", err)
				}

				got, err := store.GetByTokenHash(ctx, tokenHash)
				if err != nil {
					tb.Fatalf("expected GetByTokenHash to succeed, got: %v", err)
				}
				if !got.Pending2FA {
					tb.Fatal("expected Pending2FA to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testSessionStore_GetByTokenHash(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "active session retrieval returns unexpired session",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("get_active")
				expiresAt := time.Now().UTC().Add(2 * time.Hour)

				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: tokenHash,
					ExpiresAt: expiresAt,
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				got, err := store.GetByTokenHash(ctx, tokenHash)
				if err != nil {
					tb.Fatalf("expected active session retrieval, got: %v", err)
				}
				if got.ID != sess.ID {
					tb.Fatalf("expected ID %q, got %q", sess.ID, got.ID)
				}
			},
		},
		{
			name: "non-existent token hash returns ErrSessionNotFound",
			run: func(tb TB) {
				nonExistent := uniqueTokenHash("non_existent")
				got, err := store.GetByTokenHash(ctx, nonExistent)
				if !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected ErrSessionNotFound for non-existent token hash, got: %v", err)
				}
				if got != nil {
					tb.Fatalf("expected nil session, got: %+v", got)
				}
			},
		},
		{
			name: "strict expiry-on-read: expired session returns ErrSessionNotFound or ErrSessionExpired",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("expired_sess")
				pastExpiry := time.Now().UTC().Add(-1 * time.Hour)

				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: tokenHash,
					ExpiresAt: pastExpiry,
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				got, err := store.GetByTokenHash(ctx, tokenHash)
				if !errors.Is(err, kagi.ErrSessionNotFound) && !errors.Is(err, kagi.ErrSessionExpired) {
					tb.Fatalf("expected ErrSessionNotFound or ErrSessionExpired for expired session (ADR-0010), got: %v", err)
				}
				if got != nil {
					tb.Fatalf("expected nil session for expired session, got: %+v", got)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testSessionStore_Update(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "update sliding renewal preserves created_at ceiling and updates mutable fields",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("update_sliding")
				createdTime := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
				origExpiresAt := createdTime.Add(24 * time.Hour)

				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: tokenHash,
					ExpiresAt: origExpiresAt,
					IPAddress: "10.0.0.1",
					UserAgent: "OldAgent",
					CreatedAt: createdTime,
					UpdatedAt: createdTime,
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				newExpiresAt := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
				sess.ExpiresAt = newExpiresAt
				sess.IPAddress = "10.0.0.2"
				sess.UserAgent = "NewAgent"
				sess.UpdatedAt = time.Now().UTC()

				if err := store.Update(ctx, sess); err != nil {
					tb.Fatalf("expected successful update, got: %v", err)
				}

				got, err := store.GetByTokenHash(ctx, tokenHash)
				if err != nil {
					tb.Fatalf("failed to retrieve updated session: %v", err)
				}
				if got.IPAddress != "10.0.0.2" {
					tb.Fatalf("expected IPAddress 10.0.0.2, got %q", got.IPAddress)
				}
				if got.UserAgent != "NewAgent" {
					tb.Fatalf("expected UserAgent NewAgent, got %q", got.UserAgent)
				}
				// Verify CreatedAt preserved (ADR-0014 absolute ceiling)
				if !got.CreatedAt.Truncate(time.Second).Equal(createdTime) {
					tb.Fatalf("expected CreatedAt preserved as %v, got %v", createdTime, got.CreatedAt)
				}
				// Verify ExpiresAt extended
				if got.ExpiresAt.Before(newExpiresAt.Add(-time.Second)) {
					tb.Fatalf("expected ExpiresAt updated to >= %v, got %v", newExpiresAt, got.ExpiresAt)
				}
			},
		},
		{
			name: "update non-existent session returns ErrSessionNotFound",
			run: func(tb TB) {
				fakeSess := &kagi.Session{
					ID:        "non_existent_session_id_99999",
					UserID:    "user_99999",
					TokenHash: uniqueTokenHash("fake_sess"),
					ExpiresAt: time.Now().UTC().Add(time.Hour),
				}
				err := store.Update(ctx, fakeSess)
				if !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected ErrSessionNotFound for non-existent session update, got: %v", err)
				}
			},
		},
		{
			name: "update expired session fails with ErrSessionNotFound or ErrSessionExpired",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("update_expired")
				pastExpiry := time.Now().UTC().Add(-10 * time.Minute)

				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: tokenHash,
					ExpiresAt: pastExpiry,
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				sess.IPAddress = "1.2.3.4"
				err := store.Update(ctx, sess)
				if !errors.Is(err, kagi.ErrSessionNotFound) && !errors.Is(err, kagi.ErrSessionExpired) {
					tb.Fatalf("expected ErrSessionNotFound or ErrSessionExpired updating expired session, got: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testSessionStore_UpdateTokenHash(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful CAS rotates token hash, extends expires_at, resets pending_2fa to false, preserves created_at",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				oldHash := uniqueTokenHash("cas_old")
				newHash := uniqueTokenHash("cas_new")
				createdTime := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
				origExpiresAt := time.Now().UTC().Add(10 * time.Minute)

				sess := &kagi.Session{
					UserID:     user.ID,
					TokenHash:  oldHash,
					ExpiresAt:  origExpiresAt,
					Pending2FA: true, // will be graduated
					CreatedAt:  createdTime,
					UpdatedAt:  createdTime,
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				newExpiresAt := time.Now().UTC().Add(7 * 24 * time.Hour).Truncate(time.Second)
				err := store.UpdateTokenHash(ctx, sess.ID, oldHash, newHash, newExpiresAt)
				if err != nil {
					tb.Fatalf("expected successful CAS UpdateTokenHash, got: %v", err)
				}

				// Old token hash should no longer resolve
				oldGet, err := store.GetByTokenHash(ctx, oldHash)
				if !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected old token hash to return ErrSessionNotFound, got %v (sess: %+v)", err, oldGet)
				}

				// New token hash resolves
				updated, err := store.GetByTokenHash(ctx, newHash)
				if err != nil {
					tb.Fatalf("expected new token hash to resolve, got: %v", err)
				}
				if updated.ID != sess.ID {
					tb.Fatalf("expected session ID %q, got %q", sess.ID, updated.ID)
				}
				// 2FA graduation: pending_2fa reset to false (ADR-0014)
				if updated.Pending2FA {
					tb.Fatal("expected pending_2fa reset to false after CAS token rotation (ADR-0014)")
				}
				// created_at preservation
				if !updated.CreatedAt.Truncate(time.Second).Equal(createdTime) {
					tb.Fatalf("expected CreatedAt preserved as %v, got %v", createdTime, updated.CreatedAt)
				}
				// expires_at updated
				if updated.ExpiresAt.Before(newExpiresAt.Add(-time.Second)) {
					tb.Fatalf("expected ExpiresAt updated to >= %v, got %v", newExpiresAt, updated.ExpiresAt)
				}
			},
		},
		{
			name: "CAS fails with ErrSessionNotFound on mismatched oldTokenHash",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				actualHash := uniqueTokenHash("cas_actual")
				wrongHash := uniqueTokenHash("cas_wrong")
				newHash := uniqueTokenHash("cas_target")

				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: actualHash,
					ExpiresAt: time.Now().UTC().Add(time.Hour),
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				newExpiresAt := time.Now().UTC().Add(24 * time.Hour)
				err := store.UpdateTokenHash(ctx, sess.ID, wrongHash, newHash, newExpiresAt)
				if !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected ErrSessionNotFound on mismatched oldTokenHash, got: %v", err)
				}

				// Original session remains unchanged
				current, err := store.GetByTokenHash(ctx, actualHash)
				if err != nil {
					tb.Fatalf("expected original session intact, got: %v", err)
				}
				if current.ID != sess.ID {
					tb.Fatalf("expected ID %q, got %q", sess.ID, current.ID)
				}
			},
		},
		{
			name: "CAS fails with ErrSessionNotFound on non-existent session ID",
			run: func(tb TB) {
				oldHash := uniqueTokenHash("cas_nonexist_old")
				newHash := uniqueTokenHash("cas_nonexist_new")
				err := store.UpdateTokenHash(ctx, "non_existent_sess_9999", oldHash, newHash, time.Now().UTC().Add(time.Hour))
				if !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected ErrSessionNotFound on non-existent session ID, got: %v", err)
				}
			},
		},
		{
			name: "CAS fails with ErrSessionNotFound on expired session",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("cas_expired")
				newHash := uniqueTokenHash("cas_new_hash")
				pastExpiry := time.Now().UTC().Add(-5 * time.Minute)

				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: tokenHash,
					ExpiresAt: pastExpiry,
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				err := store.UpdateTokenHash(ctx, sess.ID, tokenHash, newHash, time.Now().UTC().Add(time.Hour))
				if !errors.Is(err, kagi.ErrSessionNotFound) && !errors.Is(err, kagi.ErrSessionExpired) {
					tb.Fatalf("expected ErrSessionNotFound or ErrSessionExpired when updating expired session hash, got: %v", err)
				}
			},
		},
		{
			name: "concurrent CAS rotations with same oldTokenHash resolve with exactly one winner",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				oldHash := uniqueTokenHash("cas_race_old")
				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: oldHash,
					ExpiresAt: time.Now().UTC().Add(time.Hour),
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				const concurrency = 2
				newHashes := make([]string, concurrency)
				for i := range newHashes {
					newHashes[i] = uniqueTokenHash("cas_race_new")
				}

				var startWg sync.WaitGroup
				startWg.Add(1)
				var doneWg sync.WaitGroup
				results := make([]error, concurrency)

				for i := range concurrency {
					doneWg.Add(1)
					go func(idx int) {
						defer doneWg.Done()
						startWg.Wait()
						results[idx] = store.UpdateTokenHash(ctx, sess.ID, oldHash, newHashes[idx], time.Now().UTC().Add(24*time.Hour))
					}(i)
				}

				startWg.Done() // release concurrent goroutines
				doneWg.Wait()

				successCount := 0
				failureCount := 0
				for _, err := range results {
					if err == nil {
						successCount++
					} else if errors.Is(err, kagi.ErrSessionNotFound) {
						failureCount++
					} else {
						tb.Fatalf("unexpected CAS error in race: %v", err)
					}
				}

				if successCount != 1 {
					tb.Fatalf("expected exactly 1 successful CAS winner, got %d (results: %v)", successCount, results)
				}
				if failureCount != concurrency-1 {
					tb.Fatalf("expected %d CAS failures with ErrSessionNotFound, got %d (results: %v)", concurrency-1, failureCount, results)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testSessionStore_DeleteByID(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "delete by ID returns deleted token hash for cache invalidation",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("del_id_token")
				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: tokenHash,
					ExpiresAt: time.Now().UTC().Add(time.Hour),
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				deletedHash, err := store.DeleteByID(ctx, sess.ID)
				if err != nil {
					tb.Fatalf("expected successful DeleteByID, got: %v", err)
				}
				if deletedHash != tokenHash {
					tb.Fatalf("expected returned deleted token hash %q, got %q", tokenHash, deletedHash)
				}

				// Verify session is deleted
				got, err := store.GetByTokenHash(ctx, tokenHash)
				if !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected ErrSessionNotFound after deletion, got: %v (sess: %+v)", err, got)
				}
			},
		},
		{
			name: "delete by non-existent ID returns ErrSessionNotFound and empty string",
			run: func(tb TB) {
				deletedHash, err := store.DeleteByID(ctx, "non_existent_sess_id_9999")
				if !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected ErrSessionNotFound deleting non-existent ID, got: %v", err)
				}
				if deletedHash != "" {
					tb.Fatalf("expected empty token hash on error, got %q", deletedHash)
				}
			},
		},
		{
			name: "delete by ID for expired session returns ErrSessionNotFound or ErrSessionExpired",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("del_id_expired")
				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: tokenHash,
					ExpiresAt: time.Now().UTC().Add(-10 * time.Minute),
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				deletedHash, err := store.DeleteByID(ctx, sess.ID)
				if !errors.Is(err, kagi.ErrSessionNotFound) && !errors.Is(err, kagi.ErrSessionExpired) {
					tb.Fatalf("expected ErrSessionNotFound or ErrSessionExpired deleting expired session by ID, got: %v", err)
				}
				if deletedHash != "" {
					tb.Fatalf("expected empty token hash on expired session delete failure, got %q", deletedHash)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testSessionStore_DeleteByTokenHash(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "successful delete by token hash removes session",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("del_by_hash")
				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: tokenHash,
					ExpiresAt: time.Now().UTC().Add(time.Hour),
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				if err := store.DeleteByTokenHash(ctx, tokenHash); err != nil {
					tb.Fatalf("expected successful DeleteByTokenHash, got: %v", err)
				}

				got, err := store.GetByTokenHash(ctx, tokenHash)
				if !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected ErrSessionNotFound after DeleteByTokenHash, got: %v (sess: %+v)", err, got)
				}
			},
		},
		{
			name: "delete by non-existent token hash returns ErrSessionNotFound",
			run: func(tb TB) {
				fakeHash := uniqueTokenHash("del_fake_hash")
				err := store.DeleteByTokenHash(ctx, fakeHash)
				if !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected ErrSessionNotFound on non-existent token hash deletion, got: %v", err)
				}
			},
		},
		{
			name: "delete by token hash for expired session returns ErrSessionNotFound or ErrSessionExpired",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				tokenHash := uniqueTokenHash("del_hash_expired")
				sess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: tokenHash,
					ExpiresAt: time.Now().UTC().Add(-10 * time.Minute),
				}
				if err := store.Create(ctx, sess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				err := store.DeleteByTokenHash(ctx, tokenHash)
				if !errors.Is(err, kagi.ErrSessionNotFound) && !errors.Is(err, kagi.ErrSessionExpired) {
					tb.Fatalf("expected ErrSessionNotFound or ErrSessionExpired deleting expired token hash, got: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testSessionStore_DeleteByUserID(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "delete by user ID revokes all user sessions and returns deleted token hashes as set",
			run: func(tb TB) {
				user1 := provisionUser(tb, userStore)
				user2 := provisionUser(tb, userStore)

				hash1 := uniqueTokenHash("u1_sess1")
				hash2 := uniqueTokenHash("u1_sess2")
				hash3 := uniqueTokenHash("u2_sess1")

				s1 := &kagi.Session{UserID: user1.ID, TokenHash: hash1, ExpiresAt: time.Now().UTC().Add(time.Hour)}
				s2 := &kagi.Session{UserID: user1.ID, TokenHash: hash2, ExpiresAt: time.Now().UTC().Add(time.Hour)}
				s3 := &kagi.Session{UserID: user2.ID, TokenHash: hash3, ExpiresAt: time.Now().UTC().Add(time.Hour)}

				if err := store.Create(ctx, s1); err != nil {
					tb.Fatalf("setup s1 failed: %v", err)
				}
				if err := store.Create(ctx, s2); err != nil {
					tb.Fatalf("setup s2 failed: %v", err)
				}
				if err := store.Create(ctx, s3); err != nil {
					tb.Fatalf("setup s3 failed: %v", err)
				}

				deletedHashes, err := store.DeleteByUserID(ctx, user1.ID)
				if err != nil {
					tb.Fatalf("expected successful DeleteByUserID, got: %v", err)
				}

				expectedHashes := []string{hash1, hash2}
				if !equalStringSets(deletedHashes, expectedHashes) {
					tb.Fatalf("expected deleted token hashes set %v, got %v", expectedHashes, deletedHashes)
				}

				// user1 sessions are gone
				if _, err := store.GetByTokenHash(ctx, hash1); !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected s1 deleted, got err: %v", err)
				}
				if _, err := store.GetByTokenHash(ctx, hash2); !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected s2 deleted, got err: %v", err)
				}

				// user2 session remains intact
				activeS3, err := store.GetByTokenHash(ctx, hash3)
				if err != nil {
					tb.Fatalf("expected user2 session s3 intact, got: %v", err)
				}
				if activeS3.ID != s3.ID {
					tb.Fatalf("expected s3 ID %q, got %q", s3.ID, activeS3.ID)
				}
			},
		},
		{
			name: "delete by user ID with no sessions returns nil, nil (bulk no-op)",
			run: func(tb TB) {
				deletedHashes, err := store.DeleteByUserID(ctx, "user_without_sessions_99999")
				if err != nil {
					tb.Fatalf("expected nil error on bulk delete no-op, got: %v", err)
				}
				if deletedHashes != nil {
					tb.Fatalf("expected (nil, nil) on bulk no-op per ADR-0014 contract, got: %v", deletedHashes)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testSessionStore_DeleteOthersByUserID(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "revokes other sessions belonging to user while preserving currentSessionID",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				currentHash := uniqueTokenHash("current_sess")
				otherHash1 := uniqueTokenHash("other_sess1")
				otherHash2 := uniqueTokenHash("other_sess2")

				currentSess := &kagi.Session{UserID: user.ID, TokenHash: currentHash, ExpiresAt: time.Now().UTC().Add(time.Hour)}
				other1 := &kagi.Session{UserID: user.ID, TokenHash: otherHash1, ExpiresAt: time.Now().UTC().Add(time.Hour)}
				other2 := &kagi.Session{UserID: user.ID, TokenHash: otherHash2, ExpiresAt: time.Now().UTC().Add(time.Hour)}

				if err := store.Create(ctx, currentSess); err != nil {
					tb.Fatalf("setup current failed: %v", err)
				}
				if err := store.Create(ctx, other1); err != nil {
					tb.Fatalf("setup other1 failed: %v", err)
				}
				if err := store.Create(ctx, other2); err != nil {
					tb.Fatalf("setup other2 failed: %v", err)
				}

				deletedHashes, err := store.DeleteOthersByUserID(ctx, user.ID, currentSess.ID)
				if err != nil {
					tb.Fatalf("expected successful DeleteOthersByUserID, got: %v", err)
				}

				expectedDeleted := []string{otherHash1, otherHash2}
				if !equalStringSets(deletedHashes, expectedDeleted) {
					tb.Fatalf("expected deleted token hashes %v, got %v", expectedDeleted, deletedHashes)
				}

				// other sessions are gone
				if _, err := store.GetByTokenHash(ctx, otherHash1); !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected other1 deleted, got: %v", err)
				}
				if _, err := store.GetByTokenHash(ctx, otherHash2); !errors.Is(err, kagi.ErrSessionNotFound) {
					tb.Fatalf("expected other2 deleted, got: %v", err)
				}

				// current session remains intact
				activeCurrent, err := store.GetByTokenHash(ctx, currentHash)
				if err != nil {
					tb.Fatalf("expected current session intact, got: %v", err)
				}
				if activeCurrent.ID != currentSess.ID {
					tb.Fatalf("expected current session ID %q, got %q", currentSess.ID, activeCurrent.ID)
				}
			},
		},
		{
			name: "delete others returns nil, nil when no other sessions exist (bulk no-op)",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				soleHash := uniqueTokenHash("sole_sess")
				soleSess := &kagi.Session{UserID: user.ID, TokenHash: soleHash, ExpiresAt: time.Now().UTC().Add(time.Hour)}
				if err := store.Create(ctx, soleSess); err != nil {
					tb.Fatalf("setup failed: %v", err)
				}

				deletedHashes, err := store.DeleteOthersByUserID(ctx, user.ID, soleSess.ID)
				if err != nil {
					tb.Fatalf("expected nil error on DeleteOthersByUserID with no others, got: %v", err)
				}
				if deletedHashes != nil {
					tb.Fatalf("expected (nil, nil) on bulk no-op, got: %v", deletedHashes)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testSessionStore_ListByUserID(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "lists only active non-pending sessions, filtering expired and pending_2fa sessions",
			run: func(tb TB) {
				user := provisionUser(tb, userStore)
				otherUser := provisionUser(tb, userStore)

				// Active, non-pending session (should be listed)
				activeHash1 := uniqueTokenHash("list_active1")
				activeSess1 := &kagi.Session{
					UserID:     user.ID,
					TokenHash:  activeHash1,
					ExpiresAt:  time.Now().UTC().Add(2 * time.Hour),
					Pending2FA: false,
				}
				// Another active, non-pending session (should be listed)
				activeHash2 := uniqueTokenHash("list_active2")
				activeSess2 := &kagi.Session{
					UserID:     user.ID,
					TokenHash:  activeHash2,
					ExpiresAt:  time.Now().UTC().Add(3 * time.Hour),
					Pending2FA: false,
				}
				// Pending 2FA session (MUST be filtered out per ADR-0014)
				pendingHash := uniqueTokenHash("list_pending")
				pendingSess := &kagi.Session{
					UserID:     user.ID,
					TokenHash:  pendingHash,
					ExpiresAt:  time.Now().UTC().Add(time.Hour),
					Pending2FA: true,
				}
				// Expired session (MUST be filtered out per ADR-0010)
				expiredHash := uniqueTokenHash("list_expired")
				expiredSess := &kagi.Session{
					UserID:     user.ID,
					TokenHash:  expiredHash,
					ExpiresAt:  time.Now().UTC().Add(-1 * time.Hour),
					Pending2FA: false,
				}
				// Other user session (MUST not be included)
				otherHash := uniqueTokenHash("list_other_user")
				otherSess := &kagi.Session{
					UserID:     otherUser.ID,
					TokenHash:  otherHash,
					ExpiresAt:  time.Now().UTC().Add(time.Hour),
					Pending2FA: false,
				}

				for _, s := range []*kagi.Session{activeSess1, activeSess2, pendingSess, expiredSess, otherSess} {
					if err := store.Create(ctx, s); err != nil {
						tb.Fatalf("setup session %q failed: %v", s.TokenHash, err)
					}
				}

				list, err := store.ListByUserID(ctx, user.ID)
				if err != nil {
					tb.Fatalf("expected successful ListByUserID, got: %v", err)
				}
				if len(list) != 2 {
					tb.Fatalf("expected exactly 2 active non-pending sessions, got %d", len(list))
				}

				ids := map[string]bool{}
				for _, s := range list {
					ids[s.ID] = true
					if s.Pending2FA {
						tb.Fatalf("pending_2fa session found in ListByUserID: %+v", s)
					}
					if s.ExpiresAt.Before(time.Now().UTC()) {
						tb.Fatalf("expired session found in ListByUserID: %+v", s)
					}
				}
				if !ids[activeSess1.ID] || !ids[activeSess2.ID] {
					tb.Fatalf("expected sessions [%s, %s], got %v", activeSess1.ID, activeSess2.ID, ids)
				}
			},
		},
		{
			name: "returns empty non-nil slice []*Session{} when no matching sessions exist",
			run: func(tb TB) {
				list, err := store.ListByUserID(ctx, "user_without_sessions_empty_slice")
				if err != nil {
					tb.Fatalf("expected successful ListByUserID, got: %v", err)
				}
				if list == nil {
					tb.Fatal("expected non-nil empty slice []*Session{}, got nil")
				}
				if len(list) != 0 {
					tb.Fatalf("expected 0 sessions, got %d", len(list))
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testSessionStore_DeleteExpired(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "batched cleanup removes only expired sessions up to batchSize without removing active sessions",
			run: func(tb TB) {
				// Clean any leftover expired sessions from prior subtests
				for {
					cleaned, err := store.DeleteExpired(ctx, 100)
					if err != nil {
						tb.Fatalf("DeleteExpired cleanup failed: %v", err)
					}
					if cleaned == 0 {
						break
					}
				}

				user := provisionUser(tb, userStore)
				past := time.Now().UTC().Add(-2 * time.Hour)
				future := time.Now().UTC().Add(2 * time.Hour)

				// Create 4 expired sessions
				expiredHashes := make([]string, 4)
				for i := range 4 {
					expiredHashes[i] = uniqueTokenHash("exp_batch")
					s := &kagi.Session{
						UserID:    user.ID,
						TokenHash: expiredHashes[i],
						ExpiresAt: past,
					}
					if err := store.Create(ctx, s); err != nil {
						tb.Fatalf("setup expired session %d failed: %v", i, err)
					}
				}

				// Create 1 active session
				activeHash := uniqueTokenHash("act_batch")
				activeSess := &kagi.Session{
					UserID:    user.ID,
					TokenHash: activeHash,
					ExpiresAt: future,
				}
				if err := store.Create(ctx, activeSess); err != nil {
					tb.Fatalf("setup active session failed: %v", err)
				}

				// Run DeleteExpired with batchSize = 2
				count1, err := store.DeleteExpired(ctx, 2)
				if err != nil {
					tb.Fatalf("expected successful DeleteExpired batch 1, got: %v", err)
				}
				if count1 != 2 {
					tb.Fatalf("expected batch 1 to delete exactly 2 rows, got %d", count1)
				}

				// Run DeleteExpired with batchSize = 5 (should delete remaining 2 expired sessions)
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

				// Active session must remain intact and retrievable
				gotActive, err := store.GetByTokenHash(ctx, activeHash)
				if err != nil {
					tb.Fatalf("expected active session still retrievable, got: %v", err)
				}
				if gotActive.ID != activeSess.ID {
					tb.Fatalf("expected active session ID %q, got %q", activeSess.ID, gotActive.ID)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}
