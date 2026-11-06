package adaptertest

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kilip/kagi"
)

func runRateLimitStoreTests(tb TB, store kagi.RateLimitStore) {
	tb.Helper()

	runSubtest(tb, "RateLimitStore_Increment", func(tb TB) {
		testRateLimitStore_Increment(tb, store)
	})
	runSubtest(tb, "RateLimitStore_Concurrency", func(tb TB) {
		testRateLimitStore_Concurrency(tb, store)
	})
	runSubtest(tb, "RateLimitStore_DeleteExpired", func(tb TB) {
		testRateLimitStore_DeleteExpired(tb, store)
	})
}

func testRateLimitStore_Increment(tb TB, store kagi.RateLimitStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "first increment initializes count to 1",
			run: func(tb TB) {
				key := uniqueID("rl:first")
				window := 1 * time.Minute

				count, err := store.Increment(ctx, key, window)
				if err != nil {
					tb.Fatalf("expected no error on first increment, got: %v", err)
				}
				if count != 1 {
					tb.Fatalf("expected count 1 on first increment, got: %d", count)
				}
			},
		},
		{
			name: "subsequent increments within active window return count+1 preserving window",
			run: func(tb TB) {
				key := uniqueID("rl:active")
				window := 2 * time.Second

				count1, err := store.Increment(ctx, key, window)
				if err != nil {
					tb.Fatalf("increment 1 failed: %v", err)
				}
				if count1 != 1 {
					tb.Fatalf("expected count 1, got %d", count1)
				}

				count2, err := store.Increment(ctx, key, window)
				if err != nil {
					tb.Fatalf("increment 2 failed: %v", err)
				}
				if count2 != 2 {
					tb.Fatalf("expected count 2, got %d", count2)
				}

				count3, err := store.Increment(ctx, key, window)
				if err != nil {
					tb.Fatalf("increment 3 failed: %v", err)
				}
				if count3 != 3 {
					tb.Fatalf("expected count 3, got %d", count3)
				}
			},
		},
		{
			name: "increment after bounded window expiration resets count to 1 and refreshes window",
			run: func(tb TB) {
				key := uniqueID("rl:expired")
				// Bounded window: 50ms window with 100ms wait
				window := 50 * time.Millisecond

				count1, err := store.Increment(ctx, key, window)
				if err != nil {
					tb.Fatalf("initial increment failed: %v", err)
				}
				if count1 != 1 {
					tb.Fatalf("expected count 1, got %d", count1)
				}

				// Wait for window expiration
				time.Sleep(100 * time.Millisecond)

				// Next increment should reset count to 1 and establish a new window
				count2, err := store.Increment(ctx, key, window)
				if err != nil {
					tb.Fatalf("increment after expiration failed: %v", err)
				}
				if count2 != 1 {
					tb.Fatalf("expected count reset to 1 after expiry, got: %d", count2)
				}

				// Increment immediately within new window to verify window was refreshed
				count3, err := store.Increment(ctx, key, window)
				if err != nil {
					tb.Fatalf("increment within refreshed window failed: %v", err)
				}
				if count3 != 2 {
					tb.Fatalf("expected count 2 in refreshed window, got: %d", count3)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testRateLimitStore_Concurrency(tb TB, store kagi.RateLimitStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "parallel increments against shared key yield exact total with zero lost updates",
			run: func(tb TB) {
				key := uniqueID("rl:concurrent")
				window := 1 * time.Minute // Safe 1-minute window
				const numGoroutines = 20

				startGate := make(chan struct{})
				var wg sync.WaitGroup
				errCh := make(chan error, numGoroutines)
				results := make([]int, numGoroutines)

				for i := range numGoroutines {
					wg.Add(1)
					go func(idx int) {
						defer wg.Done()
						<-startGate
						count, err := store.Increment(ctx, key, window)
						if err != nil {
							errCh <- fmt.Errorf("goroutine %d: %w", idx, err)
							return
						}
						results[idx] = count
					}(i)
				}

				close(startGate)
				wg.Wait()
				close(errCh)

				for err := range errCh {
					tb.Fatalf("concurrent increment error: %v", err)
				}

				seen := make(map[int]bool, numGoroutines)
				for _, count := range results {
					if count < 1 || count > numGoroutines {
						tb.Fatalf("expected count between 1 and %d, got %d", numGoroutines, count)
					}
					if seen[count] {
						tb.Fatalf("duplicate counter value observed under concurrency: %d", count)
					}
					seen[count] = true
				}

				if len(seen) != numGoroutines {
					tb.Fatalf("expected %d unique count values, got %d", numGoroutines, len(seen))
				}

				// Verify next sequential increment is numGoroutines + 1
				finalCount, err := store.Increment(ctx, key, window)
				if err != nil {
					tb.Fatalf("post-concurrency increment failed: %v", err)
				}
				if finalCount != numGoroutines+1 {
					tb.Fatalf("expected post-concurrency count %d, got %d", numGoroutines+1, finalCount)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}

func testRateLimitStore_DeleteExpired(tb TB, store kagi.RateLimitStore) {
	tb.Helper()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(tb TB)
	}{
		{
			name: "batched cleanup removes only expired rate limit entries up to batchSize",
			run: func(tb TB) {
				// Allow any short-window entries from earlier tests (e.g. 50ms test) to expire
				time.Sleep(60 * time.Millisecond)
				// Clean up all pre-existing expired entries first
				for {
					cleaned, err := store.DeleteExpired(ctx, 100)
					if err != nil {
						tb.Fatalf("pre-cleanup failed: %v", err)
					}
					if cleaned == 0 {
						break
					}
				}
				// Create 4 expired entries with short 20ms window
				expiredKeys := make([]string, 4)
				for i := range expiredKeys {
					k := uniqueID(fmt.Sprintf("rl:del:exp:%d", i))
					expiredKeys[i] = k
					count, err := store.Increment(ctx, k, 20*time.Millisecond)
					if err != nil {
						tb.Fatalf("failed to create expired test key %s: %v", k, err)
					}
					if count != 1 {
						tb.Fatalf("expected count 1, got %d", count)
					}
				}

				// Create 1 active entry with long 1-hour window
				activeKey := uniqueID("rl:del:active")
				actCount, err := store.Increment(ctx, activeKey, 1*time.Hour)
				if err != nil {
					tb.Fatalf("failed to create active test key %s: %v", activeKey, err)
				}
				if actCount != 1 {
					tb.Fatalf("expected count 1, got %d", actCount)
				}

				// Wait for the 4 entries to expire (wait 100ms)
				time.Sleep(100 * time.Millisecond)

				// Batch 1: delete at most 2 expired rows
				deleted1, err := store.DeleteExpired(ctx, 2)
				if err != nil {
					tb.Fatalf("batch 1 DeleteExpired failed: %v", err)
				}
				if deleted1 != 2 {
					tb.Fatalf("expected batch 1 to delete exactly 2 rows, got %d", deleted1)
				}

				// Batch 2: delete remaining expired rows with batchSize=5 (should delete remaining 2)
				deleted2, err := store.DeleteExpired(ctx, 5)
				if err != nil {
					tb.Fatalf("batch 2 DeleteExpired failed: %v", err)
				}
				if deleted2 != 2 {
					tb.Fatalf("expected batch 2 to delete remaining 2 rows, got %d", deleted2)
				}

				// Batch 3: delete again, should delete 0
				deleted3, err := store.DeleteExpired(ctx, 10)
				if err != nil {
					tb.Fatalf("batch 3 DeleteExpired failed: %v", err)
				}
				if deleted3 != 0 {
					tb.Fatalf("expected batch 3 to delete 0 rows, got %d", deleted3)
				}

				// Active key must still be active and its count increment to 2 (not reset to 1)
				nextCount, err := store.Increment(ctx, activeKey, 1*time.Hour)
				if err != nil {
					tb.Fatalf("incrementing active key after cleanup failed: %v", err)
				}
				if nextCount != 2 {
					tb.Fatalf("expected active key count to be 2 (preserving active state), got %d", nextCount)
				}
			},
		},
	}

	for _, tt := range tests {
		runSubtest(tb, tt.name, tt.run)
	}
}
