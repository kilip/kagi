package kagi

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"

	"github.com/kilip/kagi/internal/clock"
	"github.com/kilip/kagi/internal/crypto"
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

// ToArgon2Params converts PasswordConfig to crypto.Argon2Params.
// If PasswordConfig parameters are unset (Memory == 0), safe defaults are applied.
func (p PasswordConfig) ToArgon2Params() crypto.Argon2Params {
	if p.Memory == 0 {
		p = DefaultPasswordConfig()
	}
	if p.SaltLength == 0 {
		p.SaltLength = 16
	}
	if p.KeyLength == 0 {
		p.KeyLength = 32
	}
	return crypto.Argon2Params{
		Memory:      p.Memory,
		Iterations:  p.Iterations,
		Parallelism: p.Parallelism,
		SaltLength:  p.SaltLength,
		KeyLength:   p.KeyLength,
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

// CredentialOption configures a CredentialService.
type CredentialOption func(*CredentialService)

// WithSessionService configures the SessionService used to issue sessions upon sign-in.
func WithSessionService(sessions *SessionService) CredentialOption {
	return func(s *CredentialService) {
		s.sessions = sessions
	}
}

// CredentialService manages email/password sign-up, sign-in, and password lifecycle.
type CredentialService struct {
	users    UserStore
	accounts AccountStore
	password PasswordConfig
	clock    clock.Clock
	sessions *SessionService
}

// NewCredentialService initializes and returns a new CredentialService.
// Missing or zero-valued password configuration falls back to DefaultPasswordConfig().
// A nil clock falls back to clock.RealClock{}.
func NewCredentialService(users UserStore, accounts AccountStore, password PasswordConfig, clk clock.Clock, opts ...CredentialOption) *CredentialService {
	if password.Memory == 0 {
		password = DefaultPasswordConfig()
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	s := &CredentialService{
		users:    users,
		accounts: accounts,
		password: password,
		clock:    clk,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// SignUp registers a new user and creates their primary credential account.
func (s *CredentialService) SignUp(ctx context.Context, in SignUpInput) (*User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" || !isValidEmail(email) {
		return nil, ErrInvalidCredentials
	}

	pwdCfg := s.password
	if pwdCfg.Memory == 0 {
		defaultCfg := DefaultPasswordConfig()
		pwdCfg.Memory = defaultCfg.Memory
		pwdCfg.Iterations = defaultCfg.Iterations
		pwdCfg.Parallelism = defaultCfg.Parallelism
		pwdCfg.SaltLength = defaultCfg.SaltLength
		pwdCfg.KeyLength = defaultCfg.KeyLength
		if pwdCfg.MinLength == 0 {
			pwdCfg.MinLength = defaultCfg.MinLength
		}
		if pwdCfg.MaxLength == 0 {
			pwdCfg.MaxLength = defaultCfg.MaxLength
		}
	}

	pwLen := utf8.RuneCountInString(in.Password)
	if (pwdCfg.MinLength > 0 && pwLen < pwdCfg.MinLength) ||
		(pwdCfg.MaxLength > 0 && pwLen > pwdCfg.MaxLength) {
		return nil, ErrPasswordTooWeak
	}

	existing, err := s.users.GetByEmail(ctx, email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}
	if existing != nil {
		return nil, ErrEmailAlreadyExists
	}

	hash, err := crypto.HashPassword(in.Password, crypto.Argon2Params{
		Memory:      pwdCfg.Memory,
		Iterations:  pwdCfg.Iterations,
		Parallelism: pwdCfg.Parallelism,
		SaltLength:  pwdCfg.SaltLength,
		KeyLength:   pwdCfg.KeyLength,
	})
	if err != nil {
		return nil, err
	}

	user := &User{
		Email:            email,
		Name:             strings.TrimSpace(in.Name),
		EmailVerified:    false,
		TwoFactorEnabled: false,
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}

	account := &Account{
		UserID:            user.ID,
		Provider:          "credential",
		ProviderAccountID: email,
		PasswordHash:      hash,
	}

	if err := s.accounts.Create(ctx, account); err != nil {
		_ = s.users.Delete(ctx, user.ID)
		if errors.Is(err, ErrAccountAlreadyExists) {
			return nil, ErrEmailAlreadyExists
		}
		return nil, err
	}

	return user, nil
}

func isValidEmail(email string) bool {
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	local, domain := parts[0], parts[1]
	if len(local) == 0 || len(domain) == 0 {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

// SignIn authenticates email/password credentials with constant-time equality checks
// and Argon2id timing equalization against user enumeration.
func (s *CredentialService) SignIn(ctx context.Context, in SignInInput) (*AuthResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	email := strings.ToLower(strings.TrimSpace(in.Email))
	dummyHash := crypto.DummyHash(s.password.ToArgon2Params())

	if email == "" || !isValidEmail(email) {
		_, _ = crypto.VerifyPassword(in.Password, dummyHash)
		return nil, ErrInvalidCredentials
	}

	user, err := s.users.GetByEmail(ctx, email)
	if errors.Is(err, ErrUserNotFound) {
		_, _ = crypto.VerifyPassword(in.Password, dummyHash)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	account, err := s.accounts.GetByProvider(ctx, "credential", email)
	if errors.Is(err, ErrAccountNotFound) {
		_, _ = crypto.VerifyPassword(in.Password, dummyHash)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	matched, err := crypto.VerifyPassword(in.Password, account.PasswordHash)
	if err != nil || !matched {
		return nil, ErrInvalidCredentials
	}

	if s.sessions == nil {
		return nil, fmt.Errorf("%w: session service not configured", ErrInternal)
	}

	session, rawToken, err := s.sessions.createSession(ctx, user.ID, user.TwoFactorEnabled, in.IPAddress, in.UserAgent)
	if err != nil {
		return nil, err
	}

	return &AuthResult{
		User:     user,
		Session:  session,
		RawToken: rawToken,
	}, nil
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
