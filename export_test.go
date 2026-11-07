package kagi

import (
	"context"

	"github.com/kilip/kagi/internal/clock"
)

// CredentialServiceDependenciesForTest exposes unexported fields of CredentialService
// strictly for package-level testing in kagi_test.
func CredentialServiceDependenciesForTest(s *CredentialService) (UserStore, AccountStore, PasswordConfig, clock.Clock) {
	if s == nil {
		return nil, nil, PasswordConfig{}, nil
	}
	return s.users, s.accounts, s.password, s.clock
}

// CredentialServiceSessionServiceForTest exposes unexported sessions field of CredentialService
// strictly for package-level testing in kagi_test.
func CredentialServiceSessionServiceForTest(s *CredentialService) *SessionService {
	if s == nil {
		return nil
	}
	return s.sessions
}

// SessionServiceDependenciesForTest exposes unexported fields of SessionService
// strictly for package-level testing in kagi_test.
func SessionServiceDependenciesForTest(s *SessionService) (SessionStore, SecondaryStorage, SessionConfig, clock.Clock) {
	if s == nil {
		return nil, nil, SessionConfig{}, nil
	}
	return s.store, s.secondary, s.config, s.clock
}

// SessionServiceCreateSessionForTest calls the unexported createSession method on SessionService
// for unit testing in kagi_test.
func SessionServiceCreateSessionForTest(s *SessionService, ctx context.Context, userID string, pending2FA bool, ip, userAgent string) (*Session, string, error) {
	return s.createSession(ctx, userID, pending2FA, ip, userAgent)
}
