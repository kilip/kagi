# Kagi Public API Specification

[![Go Reference](https://pkg.go.dev/badge/github.com/kilip/kagi.svg)](https://pkg.go.dev/github.com/kilip/kagi)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1.0-green.svg)](./adr/0013-openapi-v3-contract.md)

This document specifies Kagi's public API specification created via [README-driven design (PRD Principle 4)](./prd.md) as part of milestone **M0 Foundation** ([GitHub Issue #6](https://github.com/kilip/kagi/issues/6)).

---

## Overview & Architecture

Kagi provides Go backend teams with a self-hosted, batteries-included authentication layer without locking them into a web framework, ORM, or fixed database schema.

```
┌────────────────────────────────────────────────────────┐
│                   HTTP / Router Layer                  │
│    (e.g., http/fiber — handles cookies, CSRF, JSON)    │
└───────────────────────────┬────────────────────────────┘
                            │ Calls Go methods
┌───────────────────────────▼────────────────────────────┐
│                    KAGI CORE ENGINE                    │
│        (kagi.New(cfg) — 100% HTTP & ORM Agnostic)      │
│  - Credentials        - OAuth 2.0 (PKCE S256)          │
│  - Email OTP          - Sessions (Opaque & Sliding)    │
└──────────────┬───────────────────────────┬─────────────┘
               │ Uses Ports                │ Uses Ports
┌──────────────▼────────────┐ ┌────────────▼─────────────┐
│    Primary Storage        │ │ Optional Secondary Storage│
│   (adapter/ent — Mixins)  │ │      (adapter/redis)      │
│   Source of Truth         │ │ Cache & Fast Rate Limit   │
└───────────────────────────┘ └───────────────────────────┘
```

- **Framework-agnostic core:** Depends exclusively on the Go standard library and `golang.org/x/*`. Core never imports Fiber, fasthttp, Ent, GORM, sqlc, or Redis clients.
- **Pluggable storage adapters:** Core consumes pure interface ports (`UserStore`, `AccountStore`, `SessionStore`, `VerificationStore`, `RateLimitStore`, and optional `SecondaryStorage`). All entity IDs are standard `string`s across core interfaces ([ADR-0011](./adr/0011-string-ids.md)).
- **Thin HTTP wrappers:** `http/fiber` translates HTTP requests to core service calls, sets secure `__Host-` cookies, and enforces CSRF tokens.

---

## Quickstart (Fiber + Ent)

Below is an end-to-end example wiring Ent primary storage, Kagi Core, and the Fiber HTTP router with session cookies and CSRF protection.

```go
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"

	// 1. Kagi Core Module
	"github.com/kilip/kagi"

	// 2. Storage Adapter (Ent)
	kagiEnt "github.com/kilip/kagi/adapter/ent"
	"my-app/ent" // User's generated Ent client

	// 3. Fiber HTTP Wrapper
	kagifiber "github.com/kilip/kagi/http/fiber"

	// 4. OAuth Presets
	"github.com/kilip/kagi/oauth/google"
)

func main() {
	// Initialize Ent DB Client (PostgreSQL / SQLite)
	entClient, err := ent.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("failed opening connection to postgres: %v", err)
	}
	defer entClient.Close()

	// Wrap Ent client with Kagi's storage adapter
	store := kagiEnt.NewAdapter(entClient)

	// Initialize Kagi Core Engine
	auth, err := kagi.New(kagi.Config{
		UserStore:         store.User(),
		AccountStore:      store.Account(),
		SessionStore:      store.Session(),
		VerificationStore: store.Verification(),
		RateLimitStore:    store.RateLimit(),
		Mailer:            appMailer{}, // Implements kagi.Mailer
		Secret:            os.Getenv("KAGI_MASTER_SECRET"), // Min 32 bytes (256 bits)
		OAuthProviders: map[string]kagi.OAuthProvider{
			"google": google.New(google.Config{
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  "https://example.com/api/auth/oauth/google/callback",
			}),
		},
	})
	if err != nil {
		log.Fatalf("failed initializing kagi: %v", err)
	}

	// Schedule periodic background cleanup for expired rows (optional helper)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth.RunCleanup(ctx, 1*time.Hour)

	// Mount Kagi HTTP handlers onto Fiber router
	app := fiber.New(fiber.Config{
		EnableTrustedProxyCheck: true,
		TrustedProxies:          []string{"127.0.0.1"},
	})
	handler := kagifiber.Register(app, auth, kagifiber.WithPrefix("/api/auth"))

	// Protect Application Endpoints with Session Middleware
	app.Get("/api/me", handler.RequireAuth(), func(c *fiber.Ctx) error {
		session := kagifiber.SessionFromCtx(c)
		return c.JSON(fiber.Map{
			"user_id": session.UserID,
			"session": session.ID,
		})
	})

	log.Fatal(app.Listen(":3000"))
}

// Minimal implementation of kagi.Mailer
type appMailer struct{}

func (appMailer) Send(ctx context.Context, msg kagi.EmailMessage) error {
	log.Printf("Delivering %s email to %s with code %s", msg.Type, msg.To, msg.Code)
	return nil
}
```

---

## Core Configuration (`kagi.Config`)

`kagi.New(cfg)` initializes and validates the core authentication engine.

```go
type Config struct {
    // Storage Ports (Required) - ADR-0007
    UserStore         UserStore
    AccountStore      AccountStore
    SessionStore      SessionStore
    VerificationStore VerificationStore
    RateLimitStore    RateLimitStore

    // Secondary Storage (Optional) - ADR-0007
    // When provided (e.g. Redis), caches sessions and handles distributed rate limits.
    // When nil, primary database handles all queries and rate limits directly.
    SecondaryStorage  SecondaryStorage

    // Mailer Port (Required if email OTP, verification, or reset are used) - ADR-0005
    Mailer            Mailer

    // Master Secret (Required) - ADR-0015
    // Must contain at least 32 bytes (256 bits) of entropy.
    // Derived internally via HKDF-SHA256 into separate CSRF and OAuth AEAD subkeys.
    Secret            string

    // OAuth Providers (Optional) - ADR-0008
    OAuthProviders    map[string]OAuthProvider

    // Subsystem Policies (Optional with secure defaults)
    Session           SessionConfig
    Password          PasswordConfig
    OTP               OTPConfig

    // Deterministic clock for testing (defaults to real system clock)
    Clock             clock.Clock
}
```

### Configuration Defaults

| Subsystem | Setting | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **Session** | `IdleTimeout` | `7 * 24 * time.Hour` | Sliding expiration window for active use |
| | `AbsoluteTimeout` | `30 * 24 * time.Hour` | Maximum lifetime ceiling from `created_at` |
| | `RenewalThreshold`| `0.5` | Extends session only when $\le 50\%$ idle TTL remains (prevents DB write amplification) |
| | `Pending2FATimeout`| `10 * time.Minute` | Fixed non-sliding TTL for intermediate 2FA sessions |
| **Password** | `Memory` | `64 * 1024` (64 MB) | Argon2id memory cost |
| | `Iterations` | `3` | Argon2id time cost |
| | `Parallelism` | `2` | Argon2id thread count |
| | `MinLength` | `8` | Minimum password character length |
| **OTP** | `TTL` | `10 * time.Minute` | Email verification code validity duration |
| | `Length` | `6` | Number of numeric digits |
| | `MaxAttempts` | `5` | Maximum failed attempts before code invalidation |
| | `ResendDelay` | `60 * time.Second` | Mandatory cooldown window between resend requests |

---

## Programmatic Core API (Framework-Agnostic)

Kagi Core is completely decoupled from HTTP and can be invoked directly in background workers, CLI tools, or gRPC services.

```go
ctx := context.Background()

// 1. Sign up a new user with credentials
user, err := auth.Credentials.SignUp(ctx, kagi.SignUpInput{
    Email:    "alice@example.com",
    Password: "secure-password-123",
    Name:     "Alice Doe",
})

// 2. Sign in with email and password
result, err := auth.Credentials.SignIn(ctx, kagi.SignInInput{
    Email:     "alice@example.com",
    Password:  "secure-password-123",
    IPAddress: "192.168.1.50",
    UserAgent: "Mozilla/5.0 ...",
})
// result.User     -> *kagi.User
// result.Session  -> *kagi.Session (Pending2FA may be true if 2FA enabled)
// result.RawToken -> 43-character base64url random token

// 3. Validate session token and check sliding renewal
session, renewed, err := auth.Sessions.Validate(ctx, result.RawToken)
if errors.Is(err, kagi.ErrSessionPending2FA) {
    // Requires second-factor verification
}

// 4. Request passwordless email OTP
err = auth.OTP.Send(ctx, kagi.SendOTPInput{
    Email:  "alice@example.com",
    Reason: kagi.VerificationTypeLogin,
})

// 5. Verify email OTP
otpResult, err := auth.OTP.Verify(ctx, kagi.VerifyOTPInput{
    Email:  "alice@example.com",
    Code:   "482910",
    Reason: kagi.VerificationTypeLogin,
})

// 6. Device revocation & session rotation
newRawToken, session, err := auth.Sessions.Rotate(ctx, rawToken) // Preserves 30-day absolute ceiling
err = auth.Sessions.SignOutOthers(ctx, user.ID, session.ID)     // Revokes all other devices
```

---

## HTTP Wrapper Integration (`http/fiber`)

The `http/fiber` module mounts authentication endpoints, provides cookie handling with `__Host-` prefixes, manages CSRF defense, and exposes middleware.

### Router Mounting & Middleware

```go
app := fiber.New()

// Mount all Kagi endpoints under /api/auth
handler := kagifiber.Register(app, auth, kagifiber.WithPrefix("/api/auth"))

// Protect routes requiring active authentication
app.Get("/dashboard", handler.RequireAuth(), func(c *fiber.Ctx) error {
    session := kagifiber.SessionFromCtx(c)
    userID := kagifiber.UserIDFromCtx(c)
    return c.SendString("Welcome, user " + userID)
})
```

### Endpoints Registered by `http/fiber`

| Method | Path | Summary | Auth Required |
| :--- | :--- | :--- | :---: |
| `GET` | `/csrf` | Retrieve masked CSRF token | No |
| `POST` | `/sign-up` | Register a new user | No (CSRF checked) |
| `POST` | `/sign-in` | Authenticate with email and password | No (CSRF checked) |
| `POST` | `/sign-out` | Revoke current session cookie | Yes |
| `POST` | `/password/reset-request` | Request password reset email | No (CSRF checked) |
| `POST` | `/password/reset` | Complete password reset using token | No (CSRF checked) |
| `POST` | `/password/change` | Update password and rotate token | Yes |
| `GET` | `/oauth/:provider` | Initiate OAuth flow with PKCE redirect | No |
| `GET` | `/oauth/:provider/callback`| Handle provider OAuth callback | No |
| `POST` | `/otp/send` | Send email OTP (login / 2FA / verify) | No (CSRF checked) |
| `POST` | `/otp/verify` | Verify email OTP and obtain session | No (CSRF checked) |
| `POST` | `/otp/resend` | Resend email OTP after cooldown | No (CSRF checked) |
| `GET` | `/sessions` | List active user devices and sessions | Yes |
| `DELETE` | `/sessions/:id` | Revoke specific session device | Yes |
| `DELETE` | `/sessions` | Revoke all other active sessions | Yes |

---

## Sentinel Errors & Error Handling

Core domain failures are exposed as standard Go sentinel errors (`errors.New`). The `http/fiber` wrapper translates these into HTTP status codes and machine-readable JSON schemas ([ADR-0013](./adr/0013-openapi-v3-contract.md)).

```go
result, err := auth.Credentials.SignIn(ctx, input)
if err != nil {
    switch {
    case errors.Is(err, kagi.ErrInvalidCredentials):
        // Incorrect email or password (timing-equalized)
    case errors.Is(err, kagi.ErrSessionPending2FA):
        // Primary factor valid; prompt for 2FA OTP
    case errors.Is(err, kagi.ErrRateLimitExceeded):
        // IP or account rate limit triggered
    default:
        // Internal system failure
    }
}
```

### Sentinel Error Mapping

| Sentinel Error | Description | HTTP Status | JSON Error Code |
| :--- | :--- | :--- | :--- |
| `ErrInvalidCredentials` | Incorrect email or password | `401 Unauthorized` | `invalid_credentials` |
| `ErrUserNotFound` | Target user does not exist | `404 Not Found` | `user_not_found` |
| `ErrEmailAlreadyExists` | Sign-up email conflict | `409 Conflict` | `email_already_exists` |
| `ErrEmailUnverified` | Email verification required | `403 Forbidden` | `email_unverified` |
| `ErrPasswordTooWeak` | Password complexity failure | `400 Bad Request` | `password_too_weak` |
| `ErrAccountDisabled` | Account suspended or disabled | `403 Forbidden` | `account_disabled` |
| `ErrInvalidSessionToken` | Malformed token (length != 43) | `401 Unauthorized` | `invalid_session` |
| `ErrSessionNotFound` | Session does not exist in store | `401 Unauthorized` | `session_not_found` |
| `ErrSessionExpired` | Session read-check failed | `401 Unauthorized` | `session_expired` |
| `ErrSessionPending2FA` | Access attempted on pending-2FA session | `403 Forbidden` | `session_pending_2fa` |
| `ErrOTPNotFound` | Verification code not found | `400 Bad Request` | `otp_not_found` |
| `ErrOTPExpired` | OTP TTL has elapsed | `400 Bad Request` | `otp_expired` |
| `ErrOTPInvalid` | Mismatched code hash | `400 Bad Request` | `invalid_otp` |
| `ErrOTPMaxAttemptsExceeded`| Attempt limit reached; code purged | `429 Too Many Requests` | `otp_attempts_exceeded`|
| `ErrOTPCooldown` | Resend cooldown active | `429 Too Many Requests` | `otp_cooldown_active` |
| `ErrOAuthStateMismatch` | State or PKCE verification failed | `400 Bad Request` | `oauth_state_mismatch` |
| `ErrOAuthStateExpired` | OAuth transient cookie expired | `400 Bad Request` | `oauth_state_expired` |
| `ErrOAuthEmailUnverified`| Provider email is not verified | `400 Bad Request` | `oauth_email_unverified`|
| `ErrCannotUnlinkLastMethod`| Attempt to unlink sole login account | `400 Bad Request` | `cannot_unlink_last_method` |
| `ErrCSRFTokenMismatch` | Missing or mismatched CSRF token | `403 Forbidden` | `csrf_token_mismatch` |
| `ErrRateLimitExceeded` | Rate limit threshold exceeded | `429 Too Many Requests` | `rate_limit_exceeded` |

---

## Security Guarantees & Defensive Callouts

> [!WARNING]
> **Production Master Secret Requirement (`Secret`)**
> `Secret` must be at least 32 cryptographically secure random bytes (256 bits). Kagi derives independent subkeys for session integrity, CSRF HMAC verification, and OAuth AEAD encryption using HKDF-SHA256 ([ADR-0015](./adr/0015-csrf-and-oauth-state.md)). Never hardcode secrets in source code. Generate a secure secret using:
> ```bash
> openssl rand -base64 32
> ```
> `kagi.New` will refuse to start if `Secret` is shorter than 32 bytes.

> [!IMPORTANT]
> **HTTPS Required for `__Host-` Cookie Prefixes**
> By default, Kagi uses the `__Host-` cookie prefix (`__Host-kagi_session`, `__Host-kagi_csrf`) with `Secure: true`, `HttpOnly: true`, and `SameSite: Lax`.
> Browsers will **silently reject** `__Host-` cookies sent over unencrypted HTTP. In local development without TLS, enable `InsecureDevMode: true` in your cookie config to allow unprefixed cookies over HTTP. **Never enable `InsecureDevMode` in production.**

> [!NOTE]
> **Why Public Endpoints Require CSRF Protection**
> Kagi enforces CSRF token validation on **all** mutating routes (`POST`, `PUT`, `DELETE`), including public endpoints (`/sign-in`, `/sign-up`, `/password/reset-request`).
> This defends against *Login CSRF*, where an attacker forces a victim's browser into signing into an attacker-controlled account to harvest sensitive user behavior. Single Page Applications (SPAs) should fetch an initial CSRF token via `GET /api/auth/csrf` before submitting credentials.

> [!IMPORTANT]
> **Account Enumeration Defense**
> - Sign-in failures always return `ErrInvalidCredentials` (HTTP 401). Kagi executes a dummy Argon2id hash when an email is not found to equalize response timing.
> - Password reset and email OTP requests return an identical generic HTTP 200 response regardless of whether the email is registered.

> [!WARNING]
> **Reverse Proxies & IP Spoofing**
> Kagi's built-in rate limiters and session audits inspect the remote client IP.
> If your application runs behind a reverse proxy (Cloudflare, NGINX, AWS ALB), you **must** configure your router's trusted proxy settings (such as Fiber's `EnableTrustedProxyCheck` and `TrustedProxies`). Failure to do so allows attackers to spoof `X-Forwarded-For` headers to bypass rate limits.

---

## Maintenance & Cleanup

Kagi guarantees that expired sessions, verifications, and rate limits are never honored by evaluating `expires_at > now` on every read ([ADR-0010](./adr/0010-expiry-and-cleanup.md)).

To purge accumulated expired rows without table lock contention, Kagi provides an idempotent, batched cleanup helper:

```go
// 1. Run a single batched cleanup pass (e.g., in a cron job or worker)
err := auth.Cleanup(ctx)

// 2. Or start an opt-in non-blocking background ticker
auth.RunCleanup(ctx, 1*time.Hour)
```
