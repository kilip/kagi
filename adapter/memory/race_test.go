package memory_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/adapter/memory"
)

// TestRace_SessionStore_CASTokenRotation tests CAS UpdateTokenHash with 50+ concurrent goroutines
// attempting to rotate the exact same token hash simultaneously.
// Invariant: Exactly 1 goroutine wins (returns nil), and all other goroutines fail with ErrSessionNotFound.
func TestRace_SessionStore_CASTokenRotation(t *testing.T) {
	ctx := context.Background()
	store := memory.NewSessionStore()

	initialHash := "initial_token_hash_for_concurrent_cas_rotation_00000000000000000000"
	sess := &kagi.Session{
		UserID:     "user_cas_race_1",
		TokenHash:  initialHash,
		ExpiresAt:  time.Now().UTC().Add(1 * time.Hour),
		Pending2FA: true,
	}

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create session failed: %v", err)
	}

	const goroutines = 64
	var (
		startWg   sync.WaitGroup
		doneWg    sync.WaitGroup
		successes atomic.Int64
		notFound  atomic.Int64
		otherErr  atomic.Int64
	)

	startWg.Add(1)
	doneWg.Add(goroutines)

	for i := range goroutines {
		newHash := fmt.Sprintf("rotated_hash_goroutine_%03d_0000000000000000000000000000000000", i)
		newExpiry := time.Now().UTC().Add(time.Duration(i+2) * time.Hour)

		go func() {
			defer doneWg.Done()
			startWg.Wait() // maximize concurrent collision

			err := store.UpdateTokenHash(ctx, sess.ID, initialHash, newHash, newExpiry)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, kagi.ErrSessionNotFound):
				notFound.Add(1)
			default:
				otherErr.Add(1)
			}
		}()
	}

	// Release all goroutines at once
	startWg.Done()
	doneWg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("expected exactly 1 successful CAS rotation, got %d", got)
	}
	if got := notFound.Load(); got != goroutines-1 {
		t.Fatalf("expected exactly %d ErrSessionNotFound errors, got %d", goroutines-1, got)
	}
	if got := otherErr.Load(); got != 0 {
		t.Fatalf("expected 0 unexpected errors, got %d", got)
	}

	// Verify old hash no longer resolves
	if old, err := store.GetByTokenHash(ctx, initialHash); err == nil || old != nil {
		t.Fatalf("expected old token hash to be gone, got %+v", old)
	}
}

// TestRace_RateLimitStore_ConcurrentIncrement tests 100+ concurrent Increment calls
// on the same rate limit key, verifying the final count equals the total number of increments.
func TestRace_RateLimitStore_ConcurrentIncrement(t *testing.T) {
	ctx := context.Background()
	store := memory.NewRateLimitStore()

	const goroutines = 128
	key := "rate_limit:user:race:100"
	window := 10 * time.Minute

	var startWg sync.WaitGroup
	var doneWg sync.WaitGroup
	startWg.Add(1)
	doneWg.Add(goroutines)

	counts := make([]int, goroutines)

	for i := range goroutines {
		idx := i
		go func() {
			defer doneWg.Done()
			startWg.Wait()

			c, err := store.Increment(ctx, key, window)
			if err != nil {
				t.Errorf("Increment failed: %v", err)
				return
			}
			counts[idx] = c
		}()
	}

	startWg.Done()
	doneWg.Wait()

	// Verify that each increment returned a unique count between 1 and goroutines
	seen := make(map[int]bool, goroutines)
	for i, c := range counts {
		if c < 1 || c > goroutines {
			t.Errorf("goroutine %d got out-of-range count: %d", i, c)
		}
		if seen[c] {
			t.Errorf("duplicate count observed: %d", c)
		}
		seen[c] = true
	}

	if len(seen) != goroutines {
		t.Fatalf("expected %d distinct count values, got %d", goroutines, len(seen))
	}

	// Final increment should return goroutines + 1
	finalCount, err := store.Increment(ctx, key, window)
	if err != nil {
		t.Fatalf("final Increment failed: %v", err)
	}
	if finalCount != goroutines+1 {
		t.Fatalf("expected final count %d, got %d", goroutines+1, finalCount)
	}
}

// TestRace_UserStore_CRUD tests concurrent UserStore Create, GetByID, GetByEmail, Update, and Delete.
func TestRace_UserStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := memory.NewUserStore()

	const usersCount = 50
	userIDs := make([]string, usersCount)

	// Pre-populate some users
	for i := range usersCount {
		u := &kagi.User{
			Email: fmt.Sprintf("race_user_%03d@example.com", i),
		}
		if err := store.Create(ctx, u); err != nil {
			t.Fatalf("pre-population Create failed: %v", err)
		}
		userIDs[i] = u.ID
	}

	const workers = 30
	var startWg sync.WaitGroup
	var doneWg sync.WaitGroup
	startWg.Add(1)
	doneWg.Add(workers)

	for w := range workers {
		workerID := w
		go func() {
			defer doneWg.Done()
			startWg.Wait()

			for iter := range 20 {
				id := userIDs[(workerID+iter)%usersCount]
				email := fmt.Sprintf("race_user_%03d@example.com", (workerID+iter)%usersCount)

				// Concurrent reads
				_, _ = store.GetByID(ctx, id)
				_, _ = store.GetByEmail(ctx, email)

				// Concurrent updates
				_ = store.Update(ctx, &kagi.User{
					ID:    id,
					Email: email,
				})

				// Concurrent new creates
				newEmail := fmt.Sprintf("worker_%d_iter_%d@dynamic.example.com", workerID, iter)
				newU := &kagi.User{Email: newEmail}
				if err := store.Create(ctx, newU); err == nil {
					// Delete newly created user concurrently
					_ = store.Delete(ctx, newU.ID)
				}
			}
		}()
	}

	startWg.Done()
	doneWg.Wait()
}

// TestRace_AccountStore_CRUD tests concurrent AccountStore Create, GetByProvider, ListByUserID,
// CountByUserID, Update, and Delete.
func TestRace_AccountStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := memory.NewAccountStore()

	const accountsCount = 40
	accountIDs := make([]string, accountsCount)

	// Pre-populate accounts
	for i := range accountsCount {
		a := &kagi.Account{
			UserID:            fmt.Sprintf("user_%d", i%10),
			Provider:          fmt.Sprintf("provider_%d", i%4),
			ProviderAccountID: fmt.Sprintf("prov_acc_%03d", i),
		}
		if err := store.Create(ctx, a); err != nil {
			t.Fatalf("pre-population Create failed: %v", err)
		}
		accountIDs[i] = a.ID
	}

	const workers = 30
	var startWg sync.WaitGroup
	var doneWg sync.WaitGroup
	startWg.Add(1)
	doneWg.Add(workers)

	for w := range workers {
		workerID := w
		go func() {
			defer doneWg.Done()
			startWg.Wait()

			for iter := range 20 {
				accIdx := (workerID + iter) % accountsCount
				accID := accountIDs[accIdx]
				userID := fmt.Sprintf("user_%d", accIdx%10)
				provider := fmt.Sprintf("provider_%d", accIdx%4)
				provAccID := fmt.Sprintf("prov_acc_%03d", accIdx)

				// Concurrent reads
				_, _ = store.GetByProvider(ctx, provider, provAccID)
				_, _ = store.ListByUserID(ctx, userID)
				_, _ = store.CountByUserID(ctx, userID)

				// Concurrent update
				_ = store.Update(ctx, &kagi.Account{
					ID:                accID,
					UserID:            userID,
					Provider:          provider,
					ProviderAccountID: provAccID,
				})

				// Concurrent dynamic creates & deletes
				dynAcc := &kagi.Account{
					UserID:            userID,
					Provider:          fmt.Sprintf("dyn_p_%d_%d", workerID, iter),
					ProviderAccountID: fmt.Sprintf("dyn_pa_%d_%d", workerID, iter),
				}
				if err := store.Create(ctx, dynAcc); err == nil {
					_ = store.Delete(ctx, dynAcc.ID)
				}
			}
		}()
	}

	startWg.Done()
	doneWg.Wait()
}

// TestRace_SessionStore_CRUDAndActiveListing tests concurrent SessionStore Create, GetByTokenHash,
// Update, ListByUserID, DeleteByID, DeleteByUserID, and DeleteExpired.
func TestRace_SessionStore_CRUDAndActiveListing(t *testing.T) {
	ctx := context.Background()
	store := memory.NewSessionStore()

	const usersCount = 5
	const sessionsCount = 30
	sessionIDs := make([]string, sessionsCount)
	hashes := make([]string, sessionsCount)

	for i := range sessionsCount {
		th := fmt.Sprintf("sess_race_init_hash_%04d_000000000000000000000000000000000000", i)
		s := &kagi.Session{
			UserID:    fmt.Sprintf("user_sess_%d", i%usersCount),
			TokenHash: th,
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		}
		if err := store.Create(ctx, s); err != nil {
			t.Fatalf("setup session failed: %v", err)
		}
		sessionIDs[i] = s.ID
		hashes[i] = th
	}

	const workers = 30
	var startWg sync.WaitGroup
	var doneWg sync.WaitGroup
	startWg.Add(1)
	doneWg.Add(workers)

	for w := range workers {
		workerID := w
		go func() {
			defer doneWg.Done()
			startWg.Wait()

			for iter := range 20 {
				idx := (workerID + iter) % sessionsCount
				th := hashes[idx]
				userID := fmt.Sprintf("user_sess_%d", idx%usersCount)

				// Read
				_, _ = store.GetByTokenHash(ctx, th)
				_, _ = store.ListByUserID(ctx, userID)

				// Create dynamic session
				dynTH := fmt.Sprintf("dyn_th_%d_%d_000000000000000000000000000000000000000000", workerID, iter)
				dynSess := &kagi.Session{
					UserID:    userID,
					TokenHash: dynTH,
					ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
				}
				if err := store.Create(ctx, dynSess); err == nil {
					// Update sliding
					dynSess.ExpiresAt = time.Now().UTC().Add(45 * time.Minute)
					_ = store.Update(ctx, dynSess)

					// Delete
					_, _ = store.DeleteByID(ctx, dynSess.ID)
				}

				// Periodic maintenance call
				if iter%5 == 0 {
					_, _ = store.DeleteExpired(ctx, 10)
				}
			}
		}()
	}

	startWg.Done()
	doneWg.Wait()
}

// TestRace_VerificationStore_CRUD tests concurrent VerificationStore Create, Get,
// Update, Delete, and DeleteExpired.
func TestRace_VerificationStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := memory.NewVerificationStore()

	const verificationsCount = 30
	targets := make([]string, verificationsCount)

	for i := range verificationsCount {
		target := fmt.Sprintf("verify_race_%03d@example.com", i)
		v := &kagi.Verification{
			Target:    target,
			Type:      kagi.VerificationTypeLogin,
			CodeHash:  fmt.Sprintf("code_hash_%03d_0000000000000000000000000000000000000000", i),
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			Attempts:  0,
		}
		if err := store.Create(ctx, v); err != nil {
			t.Fatalf("setup verification failed: %v", err)
		}
		targets[i] = target
	}

	const workers = 30
	var startWg sync.WaitGroup
	var doneWg sync.WaitGroup
	startWg.Add(1)
	doneWg.Add(workers)

	for w := range workers {
		workerID := w
		go func() {
			defer doneWg.Done()
			startWg.Wait()

			for iter := range 20 {
				idx := (workerID + iter) % verificationsCount
				target := targets[idx]

				// Concurrent Get
				v, err := store.Get(ctx, target, kagi.VerificationTypeLogin)
				if err == nil && v != nil {
					// Concurrent attempt update
					v.Attempts++
					_ = store.Update(ctx, v)
				}

				// Concurrent dynamic create, get, and delete
				dynTarget := fmt.Sprintf("dyn_v_%d_%d@example.com", workerID, iter)
				dynV := &kagi.Verification{
					Target:    dynTarget,
					Type:      kagi.VerificationTypePasswordReset,
					CodeHash:  fmt.Sprintf("dyn_code_%d_%d", workerID, iter),
					ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
				}
				if err := store.Create(ctx, dynV); err == nil {
					_, _ = store.Get(ctx, dynTarget, kagi.VerificationTypePasswordReset)
					_ = store.Delete(ctx, dynV.ID)
				}

				// Periodic maintenance call
				if iter%5 == 0 {
					_, _ = store.DeleteExpired(ctx, 10)
				}
			}
		}()
	}

	startWg.Done()
	doneWg.Wait()
}
