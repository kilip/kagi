package kagi

import "github.com/kilip/kagi/internal/clock"

// CredentialServiceDependenciesForTest exposes unexported fields of CredentialService
// strictly for package-level testing in kagi_test.
func CredentialServiceDependenciesForTest(s *CredentialService) (UserStore, AccountStore, PasswordConfig, clock.Clock) {
	if s == nil {
		return nil, nil, PasswordConfig{}, nil
	}
	return s.users, s.accounts, s.password, s.clock
}
