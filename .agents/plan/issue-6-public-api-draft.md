# Implementation Plan: Draft Public API in README (Issue #6)

- **Issue:** [#6 Draft public API in README (README-driven design)](https://github.com/kilip/kagi/issues/6)
- **Status:** Proposed & Awaiting User Approval
- **Milestone:** M0 Foundation
- **Principle:** PRD Principle 4 (*README-driven API design; stay small and stable*)

---

## 1. Executive Summary

This plan outlines the design and implementation strategy to resolve GitHub Issue #6. By adopting **README-Driven Design (RDD)**, we define the developer experience, configuration signatures, core service boundaries, storage ports, error hierarchy, security constraints, and Fiber HTTP integration in `README.md` and core stub files before writing concrete runtime implementations.

This synthesis combines inputs from three specialized perspectives:
1. **Product Manager (PM / DX):** Developer journey, ergonomic quickstarts, mental models, documentation boundaries, and feature discoverability.
2. **Chief Architect:** Multi-module architecture, zero-framework core isolation, `kagi.Config` & `kagi.New(cfg)`, coordinator & domain service design, storage ports, and Fiber wrapper integration.
3. **Security Expert:** Threat modeling, master secret handling (HKDF derivation), safe defaults, `__Host-` cookies, pending-2FA isolation, dual-layer CSRF with BREACH mitigation, OAuth PKCE, timing-safe equality, and account enumeration defenses.

---

## 2. Product Manager & Developer Experience (DX)

### 2.1 Developer Persona & Journey
- **Target Persona:** Go backend engineers / tech leads building production web services who want full database ownership (Ent/PostgreSQL) and zero vendor lock-in, with security defaults on par with modern auth engines (like Better Auth).
- **The 5-Minute Conversion Journey:**
  1. **0:00–0:30 (Relevance Scan):** Clear tagline and mental model diagram showing how Kagi Core decouples from storage adapters and web routers.
  2. **0:30–2:00 (Quickstart):** A concise ~30-line snippet showing Ent + Kagi Core + Fiber running with full session and CSRF support.
  3. **2:00–4:00 (Modularity & Extensibility):** Clear demonstration of how Kagi can be used without Redis (DB-backed rate limiting) and how Ent mixins let users add custom columns to the User entity.
  4. **4:00–5:00 (API & Error Ergonomics):** Clean standard Go error checks (`errors.Is`) and intuitive route protection middleware (`handler.RequireAuth()`).

### 2.2 Mental Model & Architecture

```
┌────────────────────────────────────────────────────────┐
│                   HTTP / Router Layer                  │
│   (e.g., http/fiber — handles cookies, CSRF, JSON)     │
└───────────────────────────┬────────────────────────────┘
                            │ Calls Go methods
┌───────────────────────────▼────────────────────────────┐
│                    KAGI CORE ENGINE                    │
│        (kagi.New(cfg) — 100% HTTP & ORM Agnostic)      │
│  - Credentials        - OAuth (PKCE S256)              │
│  - OTP                - Sessions (Opaque/Sliding)      │
└──────────────┬───────────────────────────┬─────────────┘
               │ Uses Ports                │ Uses Ports
┌──────────────▼────────────┐ ┌────────────▼─────────────┐
│    Primary Storage        │ │ Optional Secondary Storage│
│   (adapter/ent — Mixins)  │ │      (adapter/redis)      │
│   Source of Truth         │ │ Cache & Fast Rate Limit   │
└───────────────────────────┘ └───────────────────────────┘
```

### 2.3 Documentation Boundaries
- **In `README.md`:** Quickstart, Core constructor & configuration, high-level service signatures, Fiber wiring, primary sentinel errors table, security callouts, and cleanup scheduling.
- **In `docs/` & `examples/`:** Ent schema mixin generation guide, complete OpenAPI 3.1 generation instructions, adapter conformance suite documentation (`adaptertest`), and runnable apps (`examples/fiber-ent`).

---

## 3. Chief Architect: Architecture & API Design

### 3.1 Configuration Struct (`kagi.Config`)

```go
package kagi

import (
	"time"

	"github.com/kilip/kagi/internal/clock"
)

// Config holds dependencies and options for Kagi Core.
type Config struct {
	// Storage Ports (Required) - ADR-0007
	UserStore         UserStore
	AccountStore      AccountStore
	SessionStore      SessionStore
	VerificationStore VerificationStore
	RateLimitStore    RateLimitStore

	// Secondary Storage (Optional) - ADR-0007
	// When provided (e.g. Redis), handles fast session caching and rate limits.
	// When nil, primary database handles all queries and rate limiting.
	SecondaryStorage SecondaryStorage

	// Mailer Port (Required if email OTP, verification, or reset are used)
	Mailer Mailer

	// Master Secret (Required) - ADR-0015
	// Minimum 32 bytes of cryptographically secure entropy.
	// Used via HKDF-SHA256 to derive subkeys for CSRF and OAuth AEAD encryption.
	Secret string

	// OAuth Providers (Optional) - ADR-0008
	OAuthProviders map[string]OAuthProvider

	// Subsystem Policies (Optional with secure defaults)
	Session  SessionConfig
	Password PasswordConfig
	OTP      OTPConfig

	// Deterministic clock for testing
	Clock clock.Clock
}

type SessionConfig struct {
	IdleTimeout       time.Duration // Default: 7 days
	AbsoluteTimeout   time.Duration // Default: 30 days
	RenewalThreshold  float64       // Default: 0.5 (renew when <= 50% idle window remains)
	Pending2FATimeout time.Duration // Default: 10 minutes
}

type PasswordConfig struct {
	MinLength   int    // Default: 8
	MaxLength   int    // Default: 72
	Memory      uint32 // Default: 64 MB
	Iterations  uint32 // Default: 3
	Parallelism uint8  // Default: 2
	SaltLength  uint32 // Default: 16
	KeyLength   uint32 // Default: 32
}

type OTPConfig struct {
	TTL         time.Duration // Default: 10 minutes
	Length      int           // Default: 6 digits
	MaxAttempts int           // Default: 5 attempts before invalidation
	ResendDelay time.Duration // Default: 60 seconds
}
```

### 3.2 Constructor & Invariants
```go
func New(cfg Config) (*Kagi, error)
```
- Validates presence of all 5 mandatory stores.
- Validates `len(cfg.Secret) >= 32` (returns `ErrWeakMasterSecret`).
- Validates `0 < RenewalThreshold < 1` and `0 < Pending2FATimeout <= IdleTimeout <= AbsoluteTimeout`.

### 3.3 Core Coordinator & Domain Services
```go
type Kagi struct {
	Credentials *CredentialService
	OAuth       *OAuthService
	OTP         *OTPService
	Sessions    *SessionService
}

func (k *Kagi) Cleanup(ctx context.Context) error
func (k *Kagi) RunCleanup(ctx context.Context, interval time.Duration)
```

#### Service Signatures
1. **`Credentials` (`credential.go`):**
   - `SignUp(ctx context.Context, in SignUpInput) (*User, error)`
   - `SignIn(ctx context.Context, in SignInInput) (*AuthResult, error)`
   - `RequestPasswordReset(ctx context.Context, email string) error`
   - `ResetPassword(ctx context.Context, token string, newPassword string) error`
   - `ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) (newRawToken string, err error)`

2. **`Sessions` (`session.go` - ADR-0014):**
   - `Validate(ctx context.Context, rawToken string) (session *Session, renewed bool, err error)`
   - `Rotate(ctx context.Context, rawToken string) (newRawToken string, session *Session, err error)`
   - `SignOut(ctx context.Context, rawToken string) error`
   - `Revoke(ctx context.Context, userID, sessionID string) error`
   - `SignOutOthers(ctx context.Context, userID, currentSessionID string) error`
   - `SignOutAll(ctx context.Context, userID string) error`
   - `List(ctx context.Context, userID string) ([]*Session, error)`

3. **`OTP` (`otp.go` - ADR-0005, ADR-0014):**
   - `Send(ctx context.Context, in SendOTPInput) error`
   - `Verify(ctx context.Context, in VerifyOTPInput) (*AuthResult, error)`
   - `Resend(ctx context.Context, in SendOTPInput) error`

4. **`OAuth` (`oauth.go` - ADR-0008, ADR-0012, ADR-0015):**
   - `GenerateAuthURL(ctx context.Context, in GenerateAuthURLInput) (*OAuthAuthURLResult, error)`
   - `HandleCallback(ctx context.Context, in OAuthCallbackInput) (*AuthResult, error)`
   - `Unlink(ctx context.Context, userID, provider string) error`

### 3.4 Sentinel Error Hierarchy (`errors.go` - ADR-0013)
| Core Sentinel Error | Description | HTTP Status | OpenAPI Code |
| :--- | :--- | :--- | :--- |
| `ErrInvalidCredentials` | Incorrect email or password | 401 Unauthorized | `invalid_credentials` |
| `ErrUserNotFound` | Target user does not exist | 404 Not Found | `user_not_found` |
| `ErrEmailAlreadyExists` | Sign-up email conflict | 409 Conflict | `email_already_exists` |
| `ErrEmailUnverified` | Email verification required | 403 Forbidden | `email_unverified` |
| `ErrPasswordTooWeak` | Password complexity failure | 400 Bad Request | `password_too_weak` |
| `ErrAccountDisabled` | Account suspended | 403 Forbidden | `account_disabled` |
| `ErrInvalidSessionToken`| Format/length != 43 invalid | 401 Unauthorized | `invalid_session` |
| `ErrSessionNotFound` | Session does not exist | 401 Unauthorized | `session_not_found` |
| `ErrSessionExpired` | Expired session | 401 Unauthorized | `session_expired` |
| `ErrSessionPending2FA` | 2FA verification pending | 403 Forbidden | `session_pending_2fa` |
| `ErrOTPNotFound` | Code not found | 400 Bad Request | `otp_not_found` |
| `ErrOTPExpired` | Code expired | 400 Bad Request | `otp_expired` |
| `ErrOTPInvalid` | Mismatched code hash | 400 Bad Request | `invalid_otp` |
| `ErrOTPMaxAttemptsExceeded`| Attempt limit reached | 429 Too Many Requests | `otp_attempts_exceeded`|
| `ErrOTPCooldown` | Resend cooldown active | 429 Too Many Requests | `otp_cooldown_active` |
| `ErrOAuthStateMismatch` | CSRF state check failure | 400 Bad Request | `oauth_state_mismatch` |
| `ErrOAuthStateExpired` | Transient cookie expired | 400 Bad Request | `oauth_state_expired` |
| `ErrOAuthEmailUnverified`| Provider email unverified | 400 Bad Request | `oauth_email_unverified`|
| `ErrCannotUnlinkLastMethod`| Cannot remove sole auth method | 400 Bad Request | `cannot_unlink_last_method` |
| `ErrCSRFTokenMismatch` | Missing or invalid CSRF token | 403 Forbidden | `csrf_token_mismatch` |
| `ErrRateLimitExceeded` | Too many requests | 429 Too Many Requests | `rate_limit_exceeded` |
| `ErrWeakMasterSecret` | Secret < 32 bytes | Startup Error | - |

### 3.5 Fiber HTTP Wrapper Integration (`http/fiber`)
```go
app := fiber.New()
handler := kagifiber.Register(app, auth, kagifiber.WithPrefix("/api/auth"))

// Protected route middleware
app.Get("/api/me", handler.RequireAuth(), func(c *fiber.Ctx) error {
    session := kagifiber.SessionFromCtx(c)
    return c.JSON(fiber.Map{
        "user_id": session.UserID,
        "session": session,
    })
})
```

---

## 4. Security Expert: Threat Modeling & Defensive Design

### 4.1 Threat Mitigations & Standards
1. **Secret Management:**
   - Secrets are loaded from environment (`os.Getenv("KAGI_MASTER_SECRET")`), never hardcoded.
   - HKDF-SHA256 automatically derives isolated `CSRFKey` and `OAuthKey` subkeys from `MasterSecret`.
2. **Cookie Attributes & Prefixes:**
   - Defaults: `__Host-` cookie prefix, `HttpOnly: true`, `Secure: true`, `SameSite: Lax`.
   - Insecure HTTP allowed only via explicit `InsecureDevMode: true`.
3. **Session Hardening (ADR-0014):**
   - 43-character base64url random tokens (256-bit entropy).
   - Database stores lowercase hex SHA-256 digests; verified in constant-time (`subtle.ConstantTimeCompare`).
   - Token rotation preserves initial `created_at` timestamp to enforce the 30-day absolute ceiling.
   - `ValidateSession` returns `(nil, false, ErrSessionPending2FA)` for pending 2FA; never exposes a non-nil `*Session`.
4. **Dual-Layer CSRF & BREACH Defense (ADR-0015):**
   - `SameSite=Lax` + HMAC-SHA256 signed double-submit cookies.
   - Client token masked using random XOR one-time pad per response (`base64url(mask || raw ^ mask)`).
   - Enforced on all mutating routes (`POST`, `PUT`, `DELETE`), including login/signup to thwart Login CSRF.
5. **OAuth 2.0 PKCE & State Isolation (ADR-0015):**
   - Encrypted with AES-256-GCM in stateless cookie (`__Host-kagi_oauth_<provider>`).
   - S256 PKCE challenge; cookie purged (`Max-Age=0`) immediately on callback.
   - Account linking strictly verifies `action: "link"` and provider-verified email.
6. **Information Leakage & Timing Attacks:**
   - Single sentinel error `ErrInvalidCredentials` for all failed sign-in attempts.
   - Dummy Argon2id hash calculated on unknown emails to equalize timing.
   - Password reset and email OTP return uniform success responses regardless of email existence.

### 4.2 Developer Warnings in README
- **HTTPS & `__Host-` Cookies:** Explaining why browsers reject `__Host-` cookies on plaintext HTTP and when to use `InsecureDevMode`.
- **Master Secret Entropy:** Warning on 32-byte requirement and generating with `openssl rand -base64 32`.
- **Reverse Proxies & IP Spoofing:** Mandatory warning to configure Fiber's `EnableTrustedProxyCheck` when behind proxies to prevent rate-limit evasion.
- **Login CSRF Defense:** Explanation of why public endpoints require CSRF token validation.

---

## 5. File Breakdown & Implementation Steps

### 5.1 Affected Files
| File | Action | Purpose |
| :--- | :--- | :--- |
| `README.md` | Update | Complete public API draft, Quickstart, Config, Fiber wiring, errors, and security callouts. |
| `kagi.go` | Update | `Config`, `SessionConfig`, `PasswordConfig`, `OTPConfig`, `New` signature, `Kagi` struct. |
| `store.go` | Update | Complete interfaces for `UserStore`, `AccountStore`, `SessionStore`, `VerificationStore`, `RateLimitStore`. |
| `secondary.go` | Update | Complete interface for `SecondaryStorage`. |
| `mailer.go` | Update | `Mailer` interface and `EmailMessage` DTO. |
| `errors.go` | Update | Full list of domain sentinel errors matching ADR-0013. |
| `credential.go` | Update | `CredentialService` method signatures and DTOs (`SignUpInput`, `SignInInput`, `AuthResult`). |
| `session.go` | Update | `SessionService` method signatures and session management DTOs. |
| `otp.go` | Update | `OTPService` method signatures and DTOs. |
| `oauth.go` | Update | `OAuthService` method signatures and DTOs. |
| `examples/fiber-ent/main.go` | Update | Demonstrative multi-module integration code matching the README quickstart. |

### 5.2 Execution Sequence
1. Create and checkout branch `docs/draft-public-api-readme`.
2. Update `README.md` with the full API draft and security callouts.
3. Update core type definitions, interfaces, and signatures in `kagi.go`, `store.go`, `secondary.go`, `errors.go`, `credential.go`, `session.go`, `otp.go`, `oauth.go`, and `mailer.go`.
4. Update `examples/fiber-ent/main.go` to match the exact wiring described in the README.
5. Run formatters and linters:
   - `mise run fmt` (`gofmt -s -w .`)
   - `mise run vet` (`go vet ./...`) across all workspace modules.
6. Present the diff to the user for explicit review and approval before any commit.
