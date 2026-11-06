package clock

import (
	"sync"
	"time"
)

var _ Clock = (*FakeClock)(nil)

// FakeClock is a deterministic, thread-safe implementation of Clock for testing.
//
// The zero value of FakeClock is valid and immediately usable; its initial time
// is time.Time{} (the zero time), and its methods are safe to call without prior
// initialization.
//
// State transitions and time reads are protected by a sync.Mutex to guarantee
// thread safety across concurrent goroutines without the atomic counter overhead
// or re-entrancy deadlock risks associated with sync.RWMutex.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a new FakeClock initialized to the specified time.
func NewFake(initial time.Time) *FakeClock {
	return &FakeClock{
		now: initial,
	}
}

// Now returns the current fake time.
func (f *FakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Since returns the time elapsed since t relative to the fake clock's current time.
// It is equivalent to Now().Sub(t).
func (f *FakeClock) Since(t time.Time) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now.Sub(t)
}

// Until returns the duration until t relative to the fake clock's current time.
// It is equivalent to t.Sub(Now()).
func (f *FakeClock) Until(t time.Time) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return t.Sub(f.now)
}

// Advance advances the fake clock's current time by duration d.
// The duration d can be positive, negative, or zero.
func (f *FakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Set sets the fake clock's current time to t.
func (f *FakeClock) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}
