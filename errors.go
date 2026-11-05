package kagi

import "errors"

// Sentinel errors representing domain failures in Kagi.
// HTTP wrappers map these errors to HTTP status codes and OpenAPI schemas (ADR-0013).
var (
	// Credential & Authentication Errors
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrEmailUnverified    = errors.New("email is not verified")
	ErrPasswordTooWeak    = errors.New("password does not meet complexity requirements")
	ErrAccountDisabled    = errors.New("account is disabled")

	// Session Errors (ADR-0014)
	ErrInvalidSessionToken = errors.New("invalid session token format")
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionExpired      = errors.New("session has expired")
	ErrSessionPending2FA   = errors.New("session requires two-factor authentication")

	// OTP & Verification Errors (ADR-0005)
	ErrOTPNotFound            = errors.New("verification code not found")
	ErrOTPExpired             = errors.New("verification code has expired")
	ErrOTPInvalid             = errors.New("invalid verification code")
	ErrOTPMaxAttemptsExceeded = errors.New("maximum verification attempts exceeded")
	ErrOTPCooldown            = errors.New("please wait before requesting another code")

	// OAuth Errors (ADR-0008, ADR-0012, ADR-0015)
	ErrOAuthStateMismatch     = errors.New("oauth state verification failed")
	ErrOAuthStateExpired      = errors.New("oauth state has expired")
	ErrOAuthEmailUnverified   = errors.New("oauth provider did not return a verified email")
	ErrCannotUnlinkLastMethod = errors.New("cannot unlink user's sole authentication method")

	// CSRF & Rate Limiting Errors (ADR-0015)
	ErrCSRFTokenMismatch = errors.New("csrf token mismatch or missing")
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// Configuration & Initialization Errors
	ErrNilStore         = errors.New("required storage port is nil")
	ErrWeakMasterSecret = errors.New("master secret must be at least 32 bytes (256 bits) of entropy")
	ErrInvalidConfig    = errors.New("invalid configuration parameters")
	ErrInternal         = errors.New("internal authentication error")
)
