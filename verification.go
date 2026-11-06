package kagi

import "time"

// VerificationType distinguishes the purpose of a verification code or token.
type VerificationType string

const (
	// VerificationTypeLogin denotes passwordless email OTP authentication.
	VerificationTypeLogin VerificationType = "login"

	// VerificationTypeTwoFactor denotes a two-factor authentication challenge via email OTP.
	VerificationTypeTwoFactor VerificationType = "two_factor"

	// VerificationTypeEmailVerify denotes verification of a user's email address ownership.
	VerificationTypeEmailVerify VerificationType = "email_verify"

	// VerificationTypePasswordReset denotes an unauthenticated password recovery token or OTP.
	VerificationTypePasswordReset VerificationType = "password_reset"
)

// Verification represents an ephemeral verification code or token, e.g. OTP or password reset (ADR-0004, ADR-0005).
type Verification struct {
	// ID is the unique string identifier for the verification entity (ADR-0011).
	ID string `json:"id"`

	// Target is the recipient email or identifier to which the verification was issued.
	Target string `json:"target"`

	// Type distinguishes the purpose of this verification record.
	Type VerificationType `json:"type"`

	// CodeHash is the cryptographic hash of the verification code or token.
	// Never stores plaintext codes. Masked from JSON serialization for security.
	CodeHash string `json:"-"`

	// ExpiresAt is the timestamp after which this verification record is expired and invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// Attempts is the count of failed verification attempts, capped to prevent brute-force attacks.
	Attempts int `json:"attempts"`

	// CreatedAt is the timestamp when this verification record was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when this verification record was last updated or attempted.
	UpdatedAt time.Time `json:"updated_at"`
}
