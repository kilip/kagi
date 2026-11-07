// Package kagi is a reusable, framework-agnostic authentication library for Go.
package kagi

import (
	"context"
	"time"

	"github.com/kilip/kagi/internal/clock"
)

// Config configures the core Kagi authentication engine.
type Config struct {
	// Storage Ports (Required) - ADR-0007
	UserStore         UserStore
	AccountStore      AccountStore
	SessionStore      SessionStore
	VerificationStore VerificationStore
	RateLimitStore    RateLimitStore

	// Secondary Storage (Optional) - ADR-0007
	// When provided (e.g. Redis), caches sessions and handles distributed rate limits.
	// When nil, primary database handles all queries and rate limits directly.
	SecondaryStorage SecondaryStorage

	// Mailer Port (Required if email OTP, verification, or reset are used) - ADR-0005
	Mailer Mailer

	// Master Secret (Required) - ADR-0015
	// Must contain at least 32 bytes (256 bits) of entropy.
	// Derived internally via HKDF-SHA256 into separate CSRF and OAuth AEAD encryption subkeys.
	Secret string

	// OAuth Providers (Optional) - ADR-0008
	OAuthProviders map[string]OAuthProvider

	// Subsystem Policies (Optional with secure defaults)
	Session  SessionConfig
	Password PasswordConfig
	OTP      OTPConfig

	// Deterministic clock for unit testing (defaults to real system clock)
	Clock clock.Clock
}

// Kagi is the primary authentication coordinator, exposing domain services and maintenance routines.
type Kagi struct {
	Credentials *CredentialService
	Sessions    *SessionService
	OTP         *OTPService
	OAuth       *OAuthService

	cfg Config
}

// New initializes and validates a new Kagi authentication engine.
func New(cfg Config) (*Kagi, error) {
	if cfg.UserStore == nil || cfg.AccountStore == nil ||
		cfg.SessionStore == nil || cfg.VerificationStore == nil ||
		cfg.RateLimitStore == nil {
		return nil, ErrNilStore
	}

	if len(cfg.Secret) < 32 {
		return nil, ErrWeakMasterSecret
	}

	// Apply safe defaults if not provided
	if cfg.Session.IdleTimeout == 0 {
		cfg.Session = DefaultSessionConfig()
	}
	if cfg.Password.Memory == 0 {
		cfg.Password = DefaultPasswordConfig()
	}
	if cfg.OTP.TTL == 0 {
		cfg.OTP = DefaultOTPConfig()
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.RealClock{}
	}

	// Invariant validation (ADR-0014)
	if cfg.Session.RenewalThreshold <= 0 || cfg.Session.RenewalThreshold >= 1 {
		return nil, ErrInvalidConfig
	}
	if cfg.Session.Pending2FATimeout <= 0 ||
		cfg.Session.Pending2FATimeout > cfg.Session.IdleTimeout ||
		cfg.Session.IdleTimeout > cfg.Session.AbsoluteTimeout {
		return nil, ErrInvalidConfig
	}

	sessions := NewSessionService(cfg.SessionStore, cfg.SecondaryStorage, cfg.Session, cfg.Clock)
	credentials := NewCredentialService(cfg.UserStore, cfg.AccountStore, cfg.Password, cfg.Clock, WithSessionService(sessions))

	k := &Kagi{
		Credentials: credentials,
		Sessions:    sessions,
		OTP:         &OTPService{},
		OAuth:       &OAuthService{},
		cfg:         cfg,
	}

	return k, nil
}

// Cleanup performs a single batched, idempotent deletion of expired sessions,
// verifications, and rate limit counters (ADR-0010).
func (k *Kagi) Cleanup(ctx context.Context) error {
	const batchSize = 500

	if _, err := k.cfg.SessionStore.DeleteExpired(ctx, batchSize); err != nil {
		return err
	}
	if _, err := k.cfg.VerificationStore.DeleteExpired(ctx, batchSize); err != nil {
		return err
	}
	if _, err := k.cfg.RateLimitStore.DeleteExpired(ctx, batchSize); err != nil {
		return err
	}

	return nil
}

// RunCleanup starts an opt-in background ticker executing Cleanup periodically until ctx cancellation (ADR-0010).
func (k *Kagi) RunCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = k.Cleanup(ctx)
			}
		}
	}()
}
