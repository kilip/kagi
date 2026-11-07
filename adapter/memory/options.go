package memory

import "github.com/kilip/kagi/internal/clock"

// Option configures an in-memory store instance.
type Option func(*options)

type options struct {
	clock clock.Clock
}

func defaultOptions() *options {
	return &options{
		clock: clock.RealClock{},
	}
}

// WithClock configures an explicit clock implementation for time-dependent operations.
func WithClock(c clock.Clock) Option {
	return func(o *options) {
		if c != nil {
			o.clock = c
		}
	}
}
