package kagi

import "time"

// VerificationType distinguishes the purpose of a verification code or token.
type VerificationType string

const (
	VerificationTypeLogin         VerificationType = "login"
	VerificationTypeTwoFactor     VerificationType = "two_factor"
	VerificationTypeEmailVerify   VerificationType = "email_verify"
	VerificationTypePasswordReset VerificationType = "password_reset"
)

// Verification represents an ephemeral verification code or token (e.g. OTP or password reset).
type Verification struct {
	ID        string           `json:"id"`
	Target    string           `json:"target"` // Email or identifier to which the code was issued
	Type      VerificationType `json:"type"`
	CodeHash  string           `json:"-"`
	ExpiresAt time.Time        `json:"expires_at"`
	Attempts  int              `json:"attempts"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}
