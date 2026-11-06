package clock_test

import (
	"sync"
	"testing"
	"time"

	"github.com/kilip/kagi/internal/clock"
)

var (
	_ clock.Clock = (*clock.FakeClock)(nil)
	_ clock.Clock = &clock.FakeClock{}
)

func TestFakeClock_InterfaceCompliance(t *testing.T) {
	fc := clock.NewFake(time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC))
	var c clock.Clock = fc
	if c == nil {
		t.Fatal("expected non-nil Clock implementation")
	}

	var zeroFc clock.FakeClock
	var cZero clock.Clock = &zeroFc
	if cZero == nil {
		t.Fatal("expected non-nil Clock implementation for address of zero-value FakeClock")
	}
}

func TestFakeClock_Initialization(t *testing.T) {
	initial := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	fc := clock.NewFake(initial)

	if fc == nil {
		t.Fatal("expected NewFake to return non-nil instance")
	}

	if !fc.Now().Equal(initial) {
		t.Fatalf("expected Now() = %v, got %v", initial, fc.Now())
	}
}

func TestFakeClock_ZeroValue(t *testing.T) {
	tests := []struct {
		name string
		get  func() *clock.FakeClock
	}{
		{
			name: "value allocated variable",
			get: func() *clock.FakeClock {
				var fc clock.FakeClock
				return &fc
			},
		},
		{
			name: "pointer struct literal",
			get: func() *clock.FakeClock {
				return &clock.FakeClock{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := tt.get()

			// Zero value should return time.Time{}
			if !fc.Now().IsZero() {
				t.Fatalf("expected zero-value Now() to be zero, got %v", fc.Now())
			}
			if !fc.Now().Equal(time.Time{}) {
				t.Fatalf("expected zero-value Now() to equal time.Time{}, got %v", fc.Now())
			}

			// Since and Until with zero value
			if since := fc.Since(time.Time{}); since != 0 {
				t.Fatalf("expected Since(zero) to be 0, got %v", since)
			}
			if until := fc.Until(time.Time{}); until != 0 {
				t.Fatalf("expected Until(zero) to be 0, got %v", until)
			}

			// Advance on zero value
			fc.Advance(5 * time.Minute)
			expected := time.Time{}.Add(5 * time.Minute)
			if !fc.Now().Equal(expected) {
				t.Fatalf("expected Now() after advance on zero-value to be %v, got %v", expected, fc.Now())
			}

			// Set on zero value
			newTime := time.Date(2026, 11, 6, 15, 30, 0, 0, time.UTC)
			fc.Set(newTime)
			if !fc.Now().Equal(newTime) {
				t.Fatalf("expected Now() after Set to be %v, got %v", newTime, fc.Now())
			}
		})
	}
}

func TestFakeClock_Advance(t *testing.T) {
	base := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		initial  time.Time
		advances []time.Duration
		want     time.Time
	}{
		{
			name:     "positive duration advances forward",
			initial:  base,
			advances: []time.Duration{10 * time.Second},
			want:     base.Add(10 * time.Second),
		},
		{
			name:     "multiple positive advances",
			initial:  base,
			advances: []time.Duration{5 * time.Minute, 15 * time.Second, 500 * time.Millisecond},
			want:     base.Add(5*time.Minute + 15*time.Second + 500*time.Millisecond),
		},
		{
			name:     "zero duration does not change time",
			initial:  base,
			advances: []time.Duration{0},
			want:     base,
		},
		{
			name:     "negative duration moves backward",
			initial:  base,
			advances: []time.Duration{-30 * time.Minute},
			want:     base.Add(-30 * time.Minute),
		},
		{
			name:     "mixed positive and negative advances cancel or move accordingly",
			initial:  base,
			advances: []time.Duration{1 * time.Hour, -45 * time.Minute, 15 * time.Minute, -30 * time.Minute},
			want:     base, // 1h - 45m + 15m - 30m = 0
		},
		{
			name:     "sub-microsecond precision advance",
			initial:  base,
			advances: []time.Duration{42 * time.Nanosecond},
			want:     base.Add(42 * time.Nanosecond),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := clock.NewFake(tt.initial)

			for _, d := range tt.advances {
				fc.Advance(d)
			}

			if !fc.Now().Equal(tt.want) {
				t.Fatalf("expected Now() = %v, got %v", tt.want, fc.Now())
			}
		})
	}
}

func TestFakeClock_Set(t *testing.T) {
	initial := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		target  time.Time
		wantNow time.Time
	}{
		{
			name:    "set to future time",
			target:  time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC),
			wantNow: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC),
		},
		{
			name:    "set to past time",
			target:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			wantNow: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:    "set to zero time",
			target:  time.Time{},
			wantNow: time.Time{},
		},
		{
			name:    "set with non-UTC location",
			target:  time.Date(2026, 11, 6, 10, 0, 0, 0, time.FixedZone("EST", -5*3600)),
			wantNow: time.Date(2026, 11, 6, 10, 0, 0, 0, time.FixedZone("EST", -5*3600)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := clock.NewFake(initial)
			fc.Set(tt.target)

			if !fc.Now().Equal(tt.wantNow) {
				t.Fatalf("expected Now() = %v, got %v", tt.wantNow, fc.Now())
			}
		})
	}
}

func TestFakeClock_Since(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	fc := clock.NewFake(now)

	tests := []struct {
		name string
		t    time.Time
		want time.Duration
	}{
		{
			name: "time in the past returns positive duration",
			t:    now.Add(-15 * time.Minute),
			want: 15 * time.Minute,
		},
		{
			name: "exact current time returns zero duration",
			t:    now,
			want: 0,
		},
		{
			name: "time in the future returns negative duration",
			t:    now.Add(30 * time.Minute),
			want: -30 * time.Minute,
		},
		{
			name: "zero time returns difference from zero time",
			t:    time.Time{},
			want: now.Sub(time.Time{}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fc.Since(tt.t)
			if got != tt.want {
				t.Fatalf("Since(%v) = %v, want %v", tt.t, got, tt.want)
			}
		})
	}
}

func TestFakeClock_Until(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	fc := clock.NewFake(now)

	tests := []struct {
		name string
		t    time.Time
		want time.Duration
	}{
		{
			name: "time in the future returns positive duration",
			t:    now.Add(45 * time.Minute),
			want: 45 * time.Minute,
		},
		{
			name: "exact current time returns zero duration",
			t:    now,
			want: 0,
		},
		{
			name: "time in the past returns negative duration",
			t:    now.Add(-20 * time.Minute),
			want: -20 * time.Minute,
		},
		{
			name: "zero time returns negative difference to zero time",
			t:    time.Time{},
			want: time.Time{}.Sub(now),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fc.Until(tt.t)
			if got != tt.want {
				t.Fatalf("Until(%v) = %v, want %v", tt.t, got, tt.want)
			}

			// Verify relationship: Since(t) == -Until(t) for non-overflowing durations
			if !tt.t.IsZero() {
				since := fc.Since(tt.t)
				if got != -since {
					t.Fatalf("expected Until(%v) [%v] to equal -Since(%v) [%v]", tt.t, got, tt.t, -since)
				}
			}
		})
	}
}

func TestFakeClock_BoundaryValues(t *testing.T) {
	tests := []struct {
		name     string
		initial  time.Time
		advance  time.Duration
		expected time.Time
	}{
		{
			name:     "century advance",
			initial:  time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
			advance:  100 * 365 * 24 * time.Hour,
			expected: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Add(100 * 365 * 24 * time.Hour),
		},
		{
			name:     "negative century advance",
			initial:  time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
			advance:  -100 * 365 * 24 * time.Hour,
			expected: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).Add(-100 * 365 * 24 * time.Hour),
		},
		{
			name:     "leap year boundary advance across February 29",
			initial:  time.Date(2024, 2, 28, 23, 0, 0, 0, time.UTC),
			advance:  2 * time.Hour,
			expected: time.Date(2024, 2, 29, 1, 0, 0, 0, time.UTC),
		},
		{
			name:     "nanosecond boundary advance",
			initial:  time.Date(2026, 11, 6, 23, 59, 59, 999999999, time.UTC),
			advance:  1 * time.Nanosecond,
			expected: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := clock.NewFake(tt.initial)
			fc.Advance(tt.advance)

			if !fc.Now().Equal(tt.expected) {
				t.Fatalf("expected %v after advance %v, got %v", tt.expected, tt.advance, fc.Now())
			}
		})
	}
}

func TestFakeClock_MonotonicClockSafety(t *testing.T) {
	// time.Now() retains a monotonic clock reading in Go.
	// Stripping the monotonic reading via Round(0) simulates timestamps loaded from
	// database, serialization, or different clock sources.
	nowWithMonotonic := time.Now()
	nowWithoutMonotonic := nowWithMonotonic.Round(0)

	// In Go, == between a time with monotonic reading and without it returns false,
	// but t.Equal() returns true.
	if nowWithMonotonic == nowWithoutMonotonic {
		t.Skip("runtime did not attach monotonic clock reading to time.Now()")
	}

	fc := clock.NewFake(nowWithMonotonic)

	// Direct == comparison would fail, but Equal must succeed
	if !fc.Now().Equal(nowWithoutMonotonic) {
		t.Fatalf("expected fc.Now().Equal(nowWithoutMonotonic) to be true")
	}

	// Verify Since and Until work accurately regardless of monotonic presence
	if since := fc.Since(nowWithoutMonotonic); since != 0 {
		t.Fatalf("expected Since to be 0 for identical wall time, got %v", since)
	}

	if until := fc.Until(nowWithoutMonotonic); until != 0 {
		t.Fatalf("expected Until to be 0 for identical wall time, got %v", until)
	}
}

func TestFakeClock_Concurrency(t *testing.T) {
	const goroutines = 100
	const iterationsPerGoroutine = 100

	initialTime := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	fc := clock.NewFake(initialTime)

	var wg sync.WaitGroup
	ready := make(chan struct{})

	for i := range goroutines {
		wg.Add(1)
		goroutineID := i

		go func(id int) {
			defer wg.Done()

			// Wait for barrier to maximize concurrent contention
			<-ready

			for j := range iterationsPerGoroutine {
				switch id % 5 {
				case 0:
					// Concurrent Advance (positive, negative, zero)
					delta := time.Duration((j%11)-5) * time.Millisecond
					fc.Advance(delta)
				case 1:
					// Concurrent Set
					tVal := initialTime.Add(time.Duration(j) * time.Second)
					fc.Set(tVal)
				case 2:
					// Concurrent Now reads
					now := fc.Now()
					if now.IsZero() {
						t.Errorf("unexpected zero time during concurrent Now()")
					}
				case 3:
					// Concurrent Since reads
					_ = fc.Since(initialTime)
				case 4:
					// Concurrent Until reads
					_ = fc.Until(initialTime.Add(1 * time.Hour))
				}
			}
		}(goroutineID)
	}

	// Release all goroutines simultaneously
	close(ready)
	wg.Wait()

	// Verify the clock remains in a valid non-zero state after all concurrent operations
	finalNow := fc.Now()
	if finalNow.IsZero() {
		t.Fatal("expected non-zero time after concurrent operations")
	}
}
