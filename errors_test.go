package kagi_test

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kilip/kagi"
)

type sentinelTestCase struct {
	name string
	err  error
}

var allSentinels = []sentinelTestCase{
	// Credential & Authentication Errors
	{name: "ErrInvalidCredentials", err: kagi.ErrInvalidCredentials},
	{name: "ErrUserNotFound", err: kagi.ErrUserNotFound},
	{name: "ErrEmailAlreadyExists", err: kagi.ErrEmailAlreadyExists},
	{name: "ErrEmailUnverified", err: kagi.ErrEmailUnverified},
	{name: "ErrPasswordTooWeak", err: kagi.ErrPasswordTooWeak},
	{name: "ErrAccountDisabled", err: kagi.ErrAccountDisabled},

	// Account & Multi-Method Errors
	{name: "ErrAccountNotFound", err: kagi.ErrAccountNotFound},
	{name: "ErrAccountAlreadyExists", err: kagi.ErrAccountAlreadyExists},
	{name: "ErrCannotUnlinkLastMethod", err: kagi.ErrCannotUnlinkLastMethod},

	// Session Errors
	{name: "ErrInvalidSessionToken", err: kagi.ErrInvalidSessionToken},
	{name: "ErrSessionNotFound", err: kagi.ErrSessionNotFound},
	{name: "ErrSessionExpired", err: kagi.ErrSessionExpired},
	{name: "ErrSessionPending2FA", err: kagi.ErrSessionPending2FA},

	// OTP & Verification Errors
	{name: "ErrVerificationNotFound", err: kagi.ErrVerificationNotFound},
	{name: "ErrOTPNotFound", err: kagi.ErrOTPNotFound},
	{name: "ErrOTPExpired", err: kagi.ErrOTPExpired},
	{name: "ErrOTPInvalid", err: kagi.ErrOTPInvalid},
	{name: "ErrOTPMaxAttemptsExceeded", err: kagi.ErrOTPMaxAttemptsExceeded},
	{name: "ErrOTPCooldown", err: kagi.ErrOTPCooldown},

	// OAuth Errors
	{name: "ErrOAuthStateMissing", err: kagi.ErrOAuthStateMissing},
	{name: "ErrOAuthStateMismatch", err: kagi.ErrOAuthStateMismatch},
	{name: "ErrOAuthStateExpired", err: kagi.ErrOAuthStateExpired},
	{name: "ErrOAuthProviderMismatch", err: kagi.ErrOAuthProviderMismatch},
	{name: "ErrOAuthRemoteError", err: kagi.ErrOAuthRemoteError},
	{name: "ErrOAuthEmailUnverified", err: kagi.ErrOAuthEmailUnverified},

	// CSRF & Rate Limiting Errors
	{name: "ErrCSRFTokenMissing", err: kagi.ErrCSRFTokenMissing},
	{name: "ErrCSRFTokenInvalid", err: kagi.ErrCSRFTokenInvalid},
	{name: "ErrCSRFTokenMismatch", err: kagi.ErrCSRFTokenMismatch},
	{name: "ErrRateLimitExceeded", err: kagi.ErrRateLimitExceeded},

	// Configuration & Initialization Errors
	{name: "ErrNilStore", err: kagi.ErrNilStore},
	{name: "ErrWeakMasterSecret", err: kagi.ErrWeakMasterSecret},
	{name: "ErrInvalidConfig", err: kagi.ErrInvalidConfig},
	{name: "ErrInternal", err: kagi.ErrInternal},
}

// TestErrors_Sentinel_ErrorsIs asserts that errors.Is works across direct,
// single-wrapped (%w), multi-level nested (%w), and errors.Join error chains.
func TestErrors_Sentinel_ErrorsIs(t *testing.T) {
	for _, tc := range allSentinels {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// 1. Direct comparison
			if !errors.Is(tc.err, tc.err) {
				t.Fatalf("errors.Is direct comparison failed for %s", tc.name)
			}

			// 2. Single wrap with %w
			singleWrapped := fmt.Errorf("adapter failure: %w", tc.err)
			if !errors.Is(singleWrapped, tc.err) {
				t.Fatalf("errors.Is failed for single-wrapped %s", tc.name)
			}

			// 3. Multi-level nested wrap (%w)
			multiWrapped := fmt.Errorf("service layer: %w",
				fmt.Errorf("storage layer: %w",
					fmt.Errorf("database driver: %w", tc.err),
				),
			)
			if !errors.Is(multiWrapped, tc.err) {
				t.Fatalf("errors.Is failed for multi-wrapped %s", tc.name)
			}

			// 4. errors.Join chain
			joined := errors.Join(errors.New("preceding operational note"), tc.err, errors.New("subsequent cleanup note"))
			if !errors.Is(joined, tc.err) {
				t.Fatalf("errors.Is failed for errors.Join containing %s", tc.name)
			}

			// 5. Unrelated error should not match
			unrelated := errors.New("unrelated error")
			if errors.Is(unrelated, tc.err) {
				t.Fatalf("errors.Is unexpectedly returned true for unrelated error against %s", tc.name)
			}
		})
	}
}

// TestErrors_Sentinel_PairwiseDistinct asserts that every exported sentinel error has
// a distinct identity and does not falsely match another sentinel error via errors.Is.
func TestErrors_Sentinel_PairwiseDistinct(t *testing.T) {
	for i := 0; i < len(allSentinels); i++ {
		for j := 0; j < len(allSentinels); j++ {
			if i == j {
				continue
			}
			a := allSentinels[i]
			b := allSentinels[j]

			if errors.Is(a.err, b.err) {
				t.Errorf("sentinel error collision: errors.Is(%s, %s) returned true, expected distinct identities",
					a.name, b.name)
			}
		}
	}
}

// TestErrors_Sentinel_NoSecretsInMessages asserts that static sentinel error messages
// do not contain sensitive tokens, keys, passwords, or credential keywords.
func TestErrors_Sentinel_NoSecretsInMessages(t *testing.T) {
	forbiddenSubstrings := []string{
		"bearer",
		"password=",
		"token=",
		"secret=",
		"code=",
		"hash=",
		"argon2id",
		"BEGIN PRIVATE KEY",
		"Authorization",
		"Set-Cookie",
	}

	for _, tc := range allSentinels {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if strings.TrimSpace(msg) == "" {
				t.Errorf("sentinel error %s has empty error message", tc.name)
			}

			lowerMsg := strings.ToLower(msg)
			for _, forbidden := range forbiddenSubstrings {
				if strings.Contains(lowerMsg, strings.ToLower(forbidden)) {
					t.Errorf("sentinel %s error message %q contains forbidden sensitive substring %q",
						tc.name, msg, forbidden)
				}
			}
		})
	}
}

// TestErrors_AdapterWrapping_Scenarios simulates realistic adapter and service error
// wrapping patterns, verifying that domain sentinel inspection succeeds seamlessly.
func TestErrors_AdapterWrapping_Scenarios(t *testing.T) {
	t.Run("Ent adapter unique constraint mapping and wrapping", func(t *testing.T) {
		dbErr := errors.New("pq: duplicate key value violates unique constraint \"users_email_key\"")

		// Adapter maps constraint violation to kagi.ErrEmailAlreadyExists and wraps dbErr for diagnostics
		adapterErr := fmt.Errorf("adapter/ent: create user: %w: %v", kagi.ErrEmailAlreadyExists, dbErr)

		// Service returns error to handler
		serviceErr := fmt.Errorf("credential service: sign up: %w", adapterErr)

		if !errors.Is(serviceErr, kagi.ErrEmailAlreadyExists) {
			t.Fatalf("expected errors.Is(serviceErr, ErrEmailAlreadyExists) to be true, got false")
		}

		// Verify that error message contains operational context but preserves sentinel
		if !strings.Contains(serviceErr.Error(), "email already exists") {
			t.Errorf("expected error message to include sentinel text, got %q", serviceErr.Error())
		}
	})

	t.Run("Storage adapter record not found mapping and wrapping", func(t *testing.T) {
		// Adapter wraps both domain sentinel and sql.ErrNoRows using multiple %w (Go 1.20+)
		wrappedErr := fmt.Errorf("user store: %w: %w", kagi.ErrUserNotFound, sql.ErrNoRows)

		if !errors.Is(wrappedErr, kagi.ErrUserNotFound) {
			t.Errorf("expected errors.Is(wrappedErr, ErrUserNotFound) to be true")
		}
		if !errors.Is(wrappedErr, sql.ErrNoRows) {
			t.Errorf("expected errors.Is(wrappedErr, sql.ErrNoRows) to be true")
		}
	})

	t.Run("Session store expired check wrapping", func(t *testing.T) {
		adapterErr := fmt.Errorf("session store: get token: %w", kagi.ErrSessionExpired)

		if !errors.Is(adapterErr, kagi.ErrSessionExpired) {
			t.Errorf("expected errors.Is(adapterErr, ErrSessionExpired) to be true")
		}
	})

	t.Run("OAuth remote provider error wrapping", func(t *testing.T) {
		remoteErr := errors.New("remote server returned status 503")
		wrapped := fmt.Errorf("oauth service: exchange code: %w: %v", kagi.ErrOAuthRemoteError, remoteErr)

		if !errors.Is(wrapped, kagi.ErrOAuthRemoteError) {
			t.Errorf("expected errors.Is(wrapped, ErrOAuthRemoteError) to be true")
		}
	})
}
