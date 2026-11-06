package clock_test

import (
	"testing"
	"time"

	"github.com/kilip/kagi/internal/clock"
)

var (
	_ clock.Clock = clock.RealClock{}
	_ clock.Clock = (*clock.RealClock)(nil)
)

func TestRealClock_InterfaceCompliance(t *testing.T) {
	var c clock.Clock = clock.RealClock{}
	if c == nil {
		t.Fatal("expected non-nil Clock implementation")
	}

	var ptr clock.Clock = &clock.RealClock{}
	if ptr == nil {
		t.Fatal("expected non-nil pointer Clock implementation")
	}
}

func TestRealClock_Now(t *testing.T) {
	rc := clock.RealClock{}

	t1 := time.Now()
	now := rc.Now()
	t2 := time.Now()

	if now.IsZero() {
		t.Fatal("expected RealClock.Now() to return a non-zero time")
	}

	if now.Before(t1) || now.After(t2) {
		t.Fatalf("expected RealClock.Now() %v to be between %v and %v", now, t1, t2)
	}

	// Verify monotonic clock equality handling via Equal rather than ==
	nowCopy := now
	if !now.Equal(nowCopy) {
		t.Fatalf("expected now.Equal(nowCopy) to be true for %v and %v", now, nowCopy)
	}
}

func TestRealClock_Since(t *testing.T) {
	rc := clock.RealClock{}

	tests := []struct {
		name      string
		offset    time.Duration
		wantSign  int // -1 for negative, 0 for near-zero, 1 for positive
		tolerance time.Duration
	}{
		{
			name:      "past time returns positive duration",
			offset:    -50 * time.Millisecond,
			wantSign:  1,
			tolerance: 100 * time.Millisecond,
		},
		{
			name:      "future time returns negative duration",
			offset:    50 * time.Millisecond,
			wantSign:  -1,
			tolerance: 100 * time.Millisecond,
		},
		{
			name:      "current time returns near-zero duration",
			offset:    0,
			wantSign:  1,
			tolerance: 50 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := time.Now().Add(tt.offset)
			got := rc.Since(target)

			expected := -tt.offset
			diff := got - expected
			if diff < 0 {
				diff = -diff
			}

			if diff > tt.tolerance {
				t.Fatalf("Since(%v) = %v, expected ~%v (diff %v exceeds tolerance %v)",
					target, got, expected, diff, tt.tolerance)
			}

			switch tt.wantSign {
			case 1:
				if got < 0 {
					t.Fatalf("expected positive duration, got %v", got)
				}
			case -1:
				if got > 0 {
					t.Fatalf("expected negative duration, got %v", got)
				}
			}
		})
	}
}

func TestRealClock_Until(t *testing.T) {
	rc := clock.RealClock{}

	tests := []struct {
		name      string
		offset    time.Duration
		wantSign  int // -1 for negative, 0 for near-zero, 1 for positive
		tolerance time.Duration
	}{
		{
			name:      "future time returns positive duration",
			offset:    50 * time.Millisecond,
			wantSign:  1,
			tolerance: 100 * time.Millisecond,
		},
		{
			name:      "past time returns negative duration",
			offset:    -50 * time.Millisecond,
			wantSign:  -1,
			tolerance: 100 * time.Millisecond,
		},
		{
			name:      "current time returns near-zero duration",
			offset:    0,
			wantSign:  0,
			tolerance: 50 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := time.Now().Add(tt.offset)
			got := rc.Until(target)

			expected := tt.offset
			diff := got - expected
			if diff < 0 {
				diff = -diff
			}

			if diff > tt.tolerance {
				t.Fatalf("Until(%v) = %v, expected ~%v (diff %v exceeds tolerance %v)",
					target, got, expected, diff, tt.tolerance)
			}

			switch tt.wantSign {
			case 1:
				if got < 0 {
					t.Fatalf("expected positive duration, got %v", got)
				}
			case -1:
				if got > 0 {
					t.Fatalf("expected negative duration, got %v", got)
				}
			}
		})
	}
}
