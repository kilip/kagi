// Package kagi provides core domain types, storage ports, and authentication services.
//
// # Sentinel Errors and Error Model
//
// Domain failures in Kagi are represented as exported sentinel errors (defined with errors.New)
// and must be inspected using standard errors.Is (ADR-0013).
//
// HTTP wrappers (e.g. http/fiber) translate these sentinel errors into standard HTTP status codes
// and OpenAPI 3.1 error responses.
//
// # Wrapping Conventions for Adapters and Services
//
// Storage adapters (such as ent, gorm, sqlc, or in-memory) and domain services follow these wrapping rules:
//
//  1. Adapters map underlying database errors to domain sentinels. For example, a unique constraint
//     violation on the user email column must return ErrEmailAlreadyExists, and missing rows must
//     return the corresponding NotFound sentinel (e.g. ErrUserNotFound, ErrAccountNotFound, ErrSessionNotFound).
//
//  2. Adapters and services may wrap sentinel errors with operational context using fmt.Errorf with %w:
//     return fmt.Errorf("user store: %w: %v", kagi.ErrEmailAlreadyExists, dbErr)
//     or multiple errors using errors.Join.
//
//  3. Callers must inspect errors using errors.Is(err, kagi.ErrXYZ) or errors.As, which seamlessly
//     traverse wrapped error chains at any nesting depth.
//
// # Security Rules for Error Messages
//
// Error messages and wrapped error context MUST NEVER contain secrets or sensitive parameters.
// Specifically:
//   - Never include plaintext passwords, raw session tokens, OTP verification codes,
//     OAuth access tokens, refresh tokens, authorization codes, or master secret keys
//     in error strings or error wrappers.
//   - Identifiers (such as user IDs or account provider IDs) may be included for operational
//     diagnostics, but credentials, hashes, and secrets must remain strictly masked.
package kagi

import "errors"

var (
	// Credential & Authentication Errors

	// ErrInvalidCredentials indicates that the supplied email or password was incorrect.
	// Kagi performs timing-equalized verification to defend against user enumeration attacks.
	ErrInvalidCredentials = errors.New("invalid email or password")

	// ErrUserNotFound indicates that the requested user entity does not exist in storage.
	ErrUserNotFound = errors.New("user not found")

	// ErrEmailAlreadyExists indicates that a user registration or email update failed
	// because the email address is already registered to an existing account.
	ErrEmailAlreadyExists = errors.New("email already exists")

	// ErrEmailUnverified indicates that an operation requires a verified email address,
	// but the user's email has not yet been verified.
	ErrEmailUnverified = errors.New("email is not verified")

	// ErrPasswordTooWeak indicates that a password does not satisfy length or complexity requirements.
	ErrPasswordTooWeak = errors.New("password does not meet complexity requirements")

	// ErrAccountDisabled indicates that the user account has been suspended or disabled.
	ErrAccountDisabled = errors.New("account is disabled")

	// Account & Multi-Method Errors (ADR-0004, ADR-0012)

	// ErrAccountNotFound indicates that the requested account (credential or OAuth link) does not exist.
	ErrAccountNotFound = errors.New("account not found")

	// ErrAccountAlreadyExists indicates that an account linking attempt failed because
	// the provider account is already linked to another user.
	ErrAccountAlreadyExists = errors.New("account already exists")

	// ErrCannotUnlinkLastMethod indicates that an unlink request was rejected because the user
	// must retain at least one active authentication method (ADR-0012).
	ErrCannotUnlinkLastMethod = errors.New("cannot unlink user's sole authentication method")

	// Session Errors (ADR-0003, ADR-0014)

	// ErrInvalidSessionToken indicates that a raw session token is malformed or invalid in format.
	ErrInvalidSessionToken = errors.New("invalid session token format")

	// ErrSessionNotFound indicates that the session token hash was not found in storage.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired indicates that the session's expiration timestamp is in the past.
	ErrSessionExpired = errors.New("session has expired")

	// ErrSessionPending2FA indicates that the session is in a pending two-factor verification state
	// and cannot be used to access protected resources (ADR-0014).
	ErrSessionPending2FA = errors.New("session requires two-factor authentication")

	// OTP & Verification Errors (ADR-0005)

	// ErrVerificationNotFound indicates that a verification token or OTP entry was not found.
	ErrVerificationNotFound = errors.New("verification not found")

	// ErrOTPNotFound indicates that an OTP verification record was not found for the target.
	ErrOTPNotFound = errors.New("verification code not found")

	// ErrOTPExpired indicates that an OTP or verification token has exceeded its time-to-live.
	ErrOTPExpired = errors.New("verification code has expired")

	// ErrOTPInvalid indicates that the supplied verification code does not match the stored hash.
	ErrOTPInvalid = errors.New("invalid verification code")

	// ErrOTPMaxAttemptsExceeded indicates that maximum verification attempts have been reached
	// and the verification record has been invalidated.
	ErrOTPMaxAttemptsExceeded = errors.New("maximum verification attempts exceeded")

	// ErrOTPCooldown indicates that an OTP resend was requested before the cooldown period elapsed.
	ErrOTPCooldown = errors.New("please wait before requesting another code")

	// OAuth Errors (ADR-0008, ADR-0012, ADR-0015)

	// ErrOAuthStateMissing indicates that the state parameter was missing from the OAuth callback request.
	ErrOAuthStateMissing = errors.New("oauth state parameter missing")

	// ErrOAuthStateMismatch indicates that the OAuth state parameter did not match the encrypted state cookie.
	ErrOAuthStateMismatch = errors.New("oauth state verification failed")

	// ErrOAuthStateExpired indicates that the encrypted OAuth state cookie has expired (ADR-0015).
	ErrOAuthStateExpired = errors.New("oauth state has expired")

	// ErrOAuthProviderMismatch indicates that the OAuth callback provider does not match the state payload.
	ErrOAuthProviderMismatch = errors.New("oauth provider mismatch")

	// ErrOAuthRemoteError indicates that the remote OAuth identity provider returned an error.
	ErrOAuthRemoteError = errors.New("oauth remote provider error")

	// ErrOAuthEmailUnverified indicates that the OAuth provider did not return a verified email address (ADR-0012).
	ErrOAuthEmailUnverified = errors.New("oauth provider did not return a verified email")

	// CSRF & Rate Limiting Errors (ADR-0015)

	// ErrCSRFTokenMissing indicates that a mutating request lacked the required CSRF token.
	ErrCSRFTokenMissing = errors.New("csrf token missing")

	// ErrCSRFTokenInvalid indicates that the CSRF token was invalid or failed cryptographic verification.
	ErrCSRFTokenInvalid = errors.New("csrf token invalid")

	// ErrCSRFTokenMismatch indicates a mismatch or missing CSRF token.
	ErrCSRFTokenMismatch = errors.New("csrf token mismatch or missing")

	// ErrRateLimitExceeded indicates that a request exceeded the configured rate limit threshold.
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// Configuration & Initialization Errors

	// ErrNilStore indicates that a required storage port passed to kagi.New was nil.
	ErrNilStore = errors.New("required storage port is nil")

	// ErrWeakMasterSecret indicates that the configured master secret contains less than 32 bytes of entropy.
	ErrWeakMasterSecret = errors.New("master secret must be at least 32 bytes (256 bits) of entropy")

	// ErrInvalidConfig indicates that configuration parameters passed to kagi.New are invalid.
	ErrInvalidConfig = errors.New("invalid configuration parameters")

	// ErrInternal indicates an unexpected internal authentication or storage error.
	ErrInternal = errors.New("internal authentication error")
)
