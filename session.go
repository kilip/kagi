package kagi

import (
	"context"
	"time"
)

// Session represents an active opaque session in Kagi (ADR-0004, ADR-0014).
type Session struct {
	// ID is the unique string identifier for the session entity (ADR-0011).
	ID string `json:"id"`

	// UserID is the foreign key identifier linking this session to a User (ADR-0011).
	UserID string `json:"user_id"`

	// TokenHash is the 64-character lowercase hex SHA-256 digest of the 256-bit raw token (ADR-0014).
	// Never stores the plaintext raw token. Masked from JSON serialization for security.
	TokenHash string `json:"-"`

	// ExpiresAt is the timestamp when this session expires, governed by idle and absolute timeouts.
	ExpiresAt time.Time `json:"expires_at"`

	// IPAddress is the client IP address observed during session creation or renewal; empty if unknown.
	IPAddress string `json:"ip_address,omitempty"`

	// UserAgent is the client User-Agent header observed during session creation or renewal; empty if unknown.
	UserAgent string `json:"user_agent,omitempty"`

	// Pending2FA indicates whether the session is awaiting two-factor verification.
	// Protected endpoints strictly reject sessions with Pending2FA == true (ADR-0014).
	Pending2FA bool `json:"pending_2fa"`

	// CreatedAt is the timestamp when the session was created, defining the absolute timeout ceiling.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when the session was last refreshed or updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// SessionConfig configures session timeouts and renewal behavior (ADR-0014).
type SessionConfig struct {
	// IdleTimeout is the sliding window TTL. Default: 7 days.
	IdleTimeout time.Duration

	// AbsoluteTimeout is the maximum hard ceiling from initial session creation. Default: 30 days.
	AbsoluteTimeout time.Duration

	// RenewalThreshold defines when sliding renewal updates storage.
	// Only updates when remaining time <= IdleTimeout * RenewalThreshold. Default: 0.5.
	RenewalThreshold float64

	// Pending2FATimeout is the non-sliding TTL for sessions awaiting 2FA OTP. Default: 10 minutes.
	Pending2FATimeout time.Duration
}

// DefaultSessionConfig returns the secure-by-default session configuration.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		IdleTimeout:       7 * 24 * time.Hour,
		AbsoluteTimeout:   30 * 24 * time.Hour,
		RenewalThreshold:  0.5,
		Pending2FATimeout: 10 * time.Minute,
	}
}

// SessionService manages session lifecycles, validation, rotation, and revocation.
type SessionService struct {
	// unexported fields
}

// Validate checks the session token, verifies constant-time hash, executes sliding renewal
// when within the renewal threshold, and rejects pending-2FA sessions with ErrSessionPending2FA.
func (s *SessionService) Validate(ctx context.Context, rawToken string) (*Session, bool, error) {
	return nil, false, nil
}

// Rotate generates a new 256-bit opaque token while preserving CreatedAt (AbsoluteTimeout ceiling).
func (s *SessionService) Rotate(ctx context.Context, rawToken string) (string, *Session, error) {
	return "", nil, nil
}

// SignOut revokes the session matching rawToken and evicts it from SecondaryStorage.
func (s *SessionService) SignOut(ctx context.Context, rawToken string) error {
	return nil
}

// Revoke revokes a specific session belonging to userID.
func (s *SessionService) Revoke(ctx context.Context, userID, sessionID string) error {
	return nil
}

// SignOutOthers revokes all sessions for userID except currentSessionID.
func (s *SessionService) SignOutOthers(ctx context.Context, userID, currentSessionID string) error {
	return nil
}

// SignOutAll revokes every session for userID across all devices.
func (s *SessionService) SignOutAll(ctx context.Context, userID string) error {
	return nil
}

// List returns active, unexpired sessions for userID without exposing token hashes.
func (s *SessionService) List(ctx context.Context, userID string) ([]*Session, error) {
	return nil, nil
}
