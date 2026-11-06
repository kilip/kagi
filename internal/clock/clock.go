package clock

import "time"

// Clock provides an interface for time operations to enable deterministic unit tests.
// Production code uses RealClock, while tests can substitute a fake or mock clock
// to control time progression without relying on real-world wall-clock time.
type Clock interface {
	// Now returns the current time.
	Now() time.Time

	// Since returns the time elapsed since t.
	// It is shorthand for Now().Sub(t).
	Since(t time.Time) time.Duration

	// Until returns the duration until t.
	// It is shorthand for t.Sub(Now()).
	Until(t time.Time) time.Duration
}

// RealClock implements Clock using the standard time package, delegating directly
// to real-world system wall-clock operations.
type RealClock struct{}

var _ Clock = RealClock{}

// Now returns the current local time using time.Now.
func (RealClock) Now() time.Time {
	return time.Now()
}

// Since returns the time elapsed since t using time.Since.
func (RealClock) Since(t time.Time) time.Duration {
	return time.Since(t)
}

// Until returns the duration until t using time.Until.
func (RealClock) Until(t time.Time) time.Duration {
	return time.Until(t)
}
