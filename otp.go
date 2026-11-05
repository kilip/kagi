package kagi

import (
	"context"
	"time"
)

// OTPConfig defines configuration for email one-time passwords (ADR-0005).
type OTPConfig struct {
	TTL         time.Duration // Default: 10 minutes
	Length      int           // Default: 6 digits
	MaxAttempts int           // Default: 5 attempts before invalidation
	ResendDelay time.Duration // Default: 60 seconds rate limit cooldown
}

// DefaultOTPConfig returns safe defaults for email OTP verification.
func DefaultOTPConfig() OTPConfig {
	return OTPConfig{
		TTL:         10 * time.Minute,
		Length:      6,
		MaxAttempts: 5,
		ResendDelay: 60 * time.Second,
	}
}

// SendOTPInput contains parameters for generating and sending an email OTP.
type SendOTPInput struct {
	Email     string           `json:"email"`
	Reason    VerificationType `json:"reason"` // VerificationTypeLogin, VerificationTypeTwoFactor, VerificationTypeEmailVerify
	IPAddress string           `json:"ip_address,omitempty"`
}

// VerifyOTPInput contains parameters for validating an email OTP.
type VerifyOTPInput struct {
	Email     string           `json:"email"`
	Code      string           `json:"code"`
	Reason    VerificationType `json:"reason"`
	RawToken  string           `json:"raw_token,omitempty"` // Required when Reason == VerificationTypeTwoFactor
	IPAddress string           `json:"ip_address,omitempty"`
	UserAgent string           `json:"user_agent,omitempty"`
}

// OTPService handles email OTP generation, verification, and rate-limited resends.
type OTPService struct {
	// unexported fields
}

// Send generates a cryptographically random numeric OTP, saves its hash, and dispatches it via Mailer.
func (s *OTPService) Send(ctx context.Context, in SendOTPInput) error {
	return nil
}

// Verify validates an OTP against its stored hash using constant-time comparison,
// enforces max-attempt thresholds, and returns an AuthResult upon successful verification.
func (s *OTPService) Verify(ctx context.Context, in VerifyOTPInput) (*AuthResult, error) {
	return nil, nil
}

// Resend checks the cooldown rate-limit before re-issuing a new OTP.
func (s *OTPService) Resend(ctx context.Context, in SendOTPInput) error {
	return nil
}
