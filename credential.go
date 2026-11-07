package kagi

import (
	"context"

	"github.com/kilip/kagi/internal/clock"
)

// PasswordConfig defines argon2id hashing parameters and complexity requirements.
type PasswordConfig struct {
	MinLength   int    // Default: 8
	MaxLength   int    // Default: 72
	Memory      uint32 // Default: 64 MB (64 * 1024)
	Iterations  uint32 // Default: 3
	Parallelism uint8  // Default: 2
	SaltLength  uint32 // Default: 16
	KeyLength   uint32 // Default: 32
}

// DefaultPasswordConfig returns safe, OWASP-recommended argon2id defaults.
func DefaultPasswordConfig() PasswordConfig {
	return PasswordConfig{
		MinLength:   8,
		MaxLength:   72,
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// SignUpInput contains the fields needed to register a new user with credentials.
type SignUpInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"`
}

// SignInInput contains the credentials and request metadata for authentication.
type SignInInput struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// AuthResult represents the outcome of a successful primary authentication step.
type AuthResult struct {
	User     *User    `json:"user"`
	Session  *Session `json:"session"`
	RawToken string   `json:"raw_token"` // Fixed 43-character base64url random token
}

// CredentialService manages email/password sign-up, sign-in, and password lifecycle.
type CredentialService struct {
	users    UserStore
	accounts AccountStore
	password PasswordConfig
	clock    clock.Clock
}

// NewCredentialService initializes and returns a new CredentialService.
// Missing or zero-valued password configuration falls back to DefaultPasswordConfig().
// A nil clock falls back to clock.RealClock{}.
func NewCredentialService(users UserStore, accounts AccountStore, password PasswordConfig, clk clock.Clock) *CredentialService {
	if password.Memory == 0 {
		password = DefaultPasswordConfig()
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &CredentialService{
		users:    users,
		accounts: accounts,
		password: password,
		clock:    clk,
	}
}

// SignUp registers a new user and creates their primary credential account.
func (s *CredentialService) SignUp(ctx context.Context, in SignUpInput) (*User, error) {
	return nil, nil
}

// SignIn authenticates email/password credentials with constant-time equality checks
// and Argon2id timing equalization against user enumeration.
func (s *CredentialService) SignIn(ctx context.Context, in SignInInput) (*AuthResult, error) {
	return nil, nil
}

// RequestPasswordReset generates a verification token and delivers reset instructions via Mailer.
// Always returns nil (or generic success) to prevent account enumeration.
func (s *CredentialService) RequestPasswordReset(ctx context.Context, email string) error {
	return nil
}

// ResetPassword consumes a valid reset token, updates the password hash, and revokes all active sessions.
func (s *CredentialService) ResetPassword(ctx context.Context, token, newPassword string) error {
	return nil
}

// ChangePassword updates an authenticated user's password, revokes other sessions,
// and rotates the current session token to preserve sign-in on the active device.
func (s *CredentialService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) (string, error) {
	return "", nil
}
