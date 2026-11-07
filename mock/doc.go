// Package mock provides generated GoMock implementations for Kagi storage ports.
//
// These mocks allow unit and integration testing of Kagi authentication services
// and business logic without requiring concrete database adapters or external dependencies.
//
// Generated mock types include:
//   - MockUserStore: UserStore mock for identity persistence testing.
//   - MockAccountStore: AccountStore mock for authentication credential testing.
//   - MockSessionStore: SessionStore mock for session lifecycle and token rotation testing.
//   - MockVerificationStore: VerificationStore mock for verification challenge testing.
//   - MockRateLimitStore: RateLimitStore mock for rate limiting testing.
//   - MockSecondaryStorage: SecondaryStorage mock for fast-tier session cache testing.
//
// Run `mise run mock` (or `go generate ./...`) from repository root to regenerate mocks.
package mock
