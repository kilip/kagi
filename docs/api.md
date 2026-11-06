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
| **Password** | `Memory` | `64 * 1024` (64 MB) | Argon2id memory cost in KiB |
| | `Iterations` | `3` | Argon2id time cost (passes over memory) |
| | `Parallelism` | `2` | Argon2id degree of parallelism (lanes/threads) |
| | `SaltLength` | `16` | Cryptographic random salt length in bytes |
| | `KeyLength` | `32` | Derived key length in bytes |
| | `MinLength` | `8` | Minimum password character length |
| | `MaxLength` | `72` | Maximum password character length |
| **OTP** | `TTL` | `10 * time.Minute` | Email verification code validity duration |
| | `Length` | `6` | Number of numeric digits |
| | `MaxAttempts` | `5` | Maximum failed attempts before code invalidation |
| | `ResendDelay` | `60 * time.Second` | Mandatory cooldown window between resend requests |

---

---

## Storage Ports Specification (`kagi.Store`)

Kagi decouples authentication business logic from persistence technologies via 6 storage port interfaces ([ADR-0007](./adr/0007-storage-ports-and-conformance.md)). All entity IDs and foreign keys across storage ports are standard `string`s ([ADR-0011](./adr/0011-string-ids.md)).

### Architectural Invariants & Port Contracts

1. **Strict Dependency Isolation:** Core storage definitions (`store.go`, `secondary.go`) import exclusively from the Go standard library (`context`, `time`). Zero third-party, ORM, or database driver dependencies are permitted.
2. **Context-First & Error-Last Signatures:** Every port method accepts `context.Context` as its initial parameter and returns `error` as its final return value.
3. **Expiry Contract ([ADR-0010](./adr/0010-expiry-and-cleanup.md)):** Correctness of expiration never relies on background cleanup routines. All reads on time-bound entities (`SessionStore.GetByTokenHash`, `VerificationStore.Get`, `SecondaryStorage.GetSession`) verify `expires_at > now`. Expired records are treated as non-existent.
4. **Atomicity & Concurrency Guarantees ([ADR-0014](./adr/0014-session-policy.md)):** Critical security state transitions enforce atomic execution:
   - `SessionStore.UpdateTokenHash` uses Compare-And-Swap (CAS) to prevent race conditions during token rotation and 2FA graduation.
   - `RateLimitStore.Increment` and `SecondaryStorage.IncrementRateLimit` enforce atomic fixed-window upsert/increment semantics.
5. **Primary-First Multi-Tier Ordering ([ADR-0007](./adr/0007-storage-ports-and-conformance.md), [ADR-0014](./adr/0014-session-policy.md)):** When `SecondaryStorage` is configured, session mutations commit to primary `SessionStore` *first*, and cache invalidation or update occurs *second*.
6. **Cache Fallback Semantics:** `SecondaryStorage.GetSession` returns `(nil, nil)` on cache misses (key absent or expired), allowing callers to fall back to `SessionStore.GetByTokenHash`. Operational failures return `(nil, error)`.
7. **Deterministic Eviction:** Primary deletion methods return deleted `token_hash` values, enabling direct eviction from secondary cache without maintaining secondary user index sets in Redis.

### 1. `UserStore`

Primary persistence port for User identity entities ([ADR-0004](./adr/0004-data-model.md), [ADR-0011](./adr/0011-string-ids.md)).

```go
type UserStore interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id string) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
    Update(ctx context.Context, user *User) error
    Delete(ctx context.Context, id string) error
}
```

- **`Create(ctx, user)`:** Inserts a new user record. Assigns generated string ID (UUID/ULID) to `user.ID`. Returns `ErrEmailAlreadyExists` if email conflicts.
- **`GetByID(ctx, id)`:** Retrieves user by string ID. Returns `ErrUserNotFound` if missing.
- **`GetByEmail(ctx, email)`:** Retrieves user by normalized primary email. Returns `ErrUserNotFound` if missing.
- **`Update(ctx, user)`:** Persists updated fields (`Name`, `Email`, `EmailVerified`, `TwoFactorEnabled`, `UpdatedAt`). Returns `ErrUserNotFound` or `ErrEmailAlreadyExists`.
- **`Delete(ctx, id)`:** Permanently removes user record. Returns `ErrUserNotFound` if missing.

### 2. `AccountStore`

Persistence port for authentication credentials and linked OAuth accounts ([ADR-0004](./adr/0004-data-model.md), [ADR-0012](./adr/0012-account-linking-policy.md)). Enforces unique constraint on `(provider, provider_account_id)`.

```go
type AccountStore interface {
    Create(ctx context.Context, account *Account) error
    GetByProvider(ctx context.Context, provider, providerAccountID string) (*Account, error)
    ListByUserID(ctx context.Context, userID string) ([]*Account, error)
    Update(ctx context.Context, account *Account) error
    Delete(ctx context.Context, id string) error
    DeleteByUserID(ctx context.Context, userID string) error
}
```

- **`Create(ctx, account)`:** Links an authentication method to `account.UserID`. Returns `ErrAccountAlreadyExists` on provider collision.
- **`GetByProvider(ctx, provider, providerAccountID)`:** Looks up account by provider tuple. Returns `ErrAccountNotFound` if missing.
- **`ListByUserID(ctx, userID)`:** Returns all accounts linked to a user. Returns empty slice `[]*Account{}` if none.
- **`Update(ctx, account)`:** Updates credentials, tokens, or profile metadata. Returns `ErrAccountNotFound`.
- **`Delete(ctx, id)`:** Removes linked account by string ID. Returns `ErrAccountNotFound`.
- **`DeleteByUserID(ctx, userID)`:** Cascades deletion of all accounts for a user during user account deletion.

### 3. `SessionStore`

Authoritative primary persistence port for opaque session state, token rotation, and revocation ([ADR-0004](./adr/0004-data-model.md), [ADR-0010](./adr/0010-expiry-and-cleanup.md), [ADR-0014](./adr/0014-session-policy.md)).

```go
type SessionStore interface {
    Create(ctx context.Context, session *Session) error
    GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
    Update(ctx context.Context, session *Session) error
    UpdateTokenHash(ctx context.Context, id, oldTokenHash, newTokenHash string, expiresAt time.Time) error
    DeleteByID(ctx context.Context, id string) (deletedTokenHash string, err error)
    DeleteByTokenHash(ctx context.Context, tokenHash string) error
    DeleteByUserID(ctx context.Context, userID string) (deletedTokenHashes []string, err error)
    DeleteOthersByUserID(ctx context.Context, userID, currentSessionID string) (deletedTokenHashes []string, err error)
    ListByUserID(ctx context.Context, userID string) ([]*Session, error)
    DeleteExpired(ctx context.Context, batchSize int) (int, error)
}
```

- **`Create(ctx, session)`:** Persists session record with SHA-256 `TokenHash`, `ExpiresAt`, and `Pending2FA`.
- **`GetByTokenHash(ctx, tokenHash)`:** Queries active session enforcing `expires_at > now`. Returns `ErrSessionNotFound` (or `ErrSessionExpired`) if absent or expired.
- **`Update(ctx, session)`:** Updates mutable metadata and extends `ExpiresAt` on sliding renewal while preserving original `CreatedAt`.
- **`UpdateTokenHash(ctx, id, oldTokenHash, newTokenHash, expiresAt)`:** Executes atomic Compare-And-Swap (CAS) update: matches `id`, `oldTokenHash`, and `expires_at > now`, resets `pending_2fa = false` (2FA graduation guard), and updates `token_hash` and `expires_at`. Returns `ErrSessionNotFound` if CAS guard fails.
- **`DeleteByID(ctx, id)`:** Deletes session and returns its `deletedTokenHash` for immediate secondary cache eviction.
- **`DeleteByTokenHash(ctx, tokenHash)`:** Revokes session matching SHA-256 token hash.
- **`DeleteByUserID(ctx, userID)`:** Revokes all sessions for user (SignOutAll, password reset) and returns `deletedTokenHashes` for batch cache eviction.
- **`DeleteOthersByUserID(ctx, userID, currentSessionID)`:** Revokes all sessions except `currentSessionID` and returns `deletedTokenHashes`.
- **`ListByUserID(ctx, userID)`:** Returns active, non-pending sessions (`expires_at > now AND pending_2fa = false`) for device management.
- **`DeleteExpired(ctx, batchSize)`:** Idempotently deletes expired sessions (`expires_at <= now`) in bounded batches to avoid database locks. Returns deleted count.

### 4. `VerificationStore`

Primary persistence port for ephemeral OTP codes, email verifications, and password reset tokens ([ADR-0004](./adr/0004-data-model.md), [ADR-0005](./adr/0005-email-otp.md), [ADR-0010](./adr/0010-expiry-and-cleanup.md)).

```go
type VerificationStore interface {
    Create(ctx context.Context, v *Verification) error
    Get(ctx context.Context, target string, vType VerificationType) (*Verification, error)
    Update(ctx context.Context, v *Verification) error
    Delete(ctx context.Context, id string) error
    DeleteExpired(ctx context.Context, batchSize int) (int, error)
}
```

- **`Create(ctx, v)`:** Persists verification challenge storing hashed code (`CodeHash`), target, type, and expiration.
- **`Get(ctx, target, vType)`:** Retrieves challenge enforcing `expires_at > now`. Returns `ErrVerificationNotFound` if missing or expired.
- **`Update(ctx, v)`:** Updates mutable fields such as failed `Attempts` counter.
- **`Delete(ctx, id)`:** Permanently removes challenge record upon consumption or invalidation.
- **`DeleteExpired(ctx, batchSize)`:** Batched deletion of expired verification challenges (`expires_at <= now`). Returns deleted count.

### 5. `RateLimitStore`

Database-backed atomic rate limiting port for Redis-free deployments ([ADR-0004](./adr/0004-data-model.md), [ADR-0007](./adr/0007-storage-ports-and-conformance.md), [ADR-0010](./adr/0010-expiry-and-cleanup.md)).

```go
type RateLimitStore interface {
    Increment(ctx context.Context, key string, window time.Duration) (count int, err error)
    DeleteExpired(ctx context.Context, batchSize int) (int, error)
}
```

- **`Increment(ctx, key, window)`:** Executes atomic fixed-window upsert:
  - If key missing: inserts record with `count = 1` and `expires_at = now + window`.
  - If expired (`expires_at <= now`): resets record with `count = 1` and `expires_at = now + window`.
  - If active (`expires_at > now`): increments `count = count + 1` while strictly preserving original `expires_at`.
  Returns updated `count >= 1`.
- **`DeleteExpired(ctx, batchSize)`:** Batched deletion of expired rate limit counter entries (`expires_at <= now`). Returns deleted count.

### 6. `SecondaryStorage` (Optional Fast-Tier Cache)

Optional fast-tier storage port (typically Redis) for low-latency session caching and fast distributed rate limiting ([ADR-0007](./adr/0007-storage-ports-and-conformance.md), [ADR-0010](./adr/0010-expiry-and-cleanup.md), [ADR-0014](./adr/0014-session-policy.md)).

```go
type SecondaryStorage interface {
    GetSession(ctx context.Context, tokenHash string) (*Session, error)
    SetSession(ctx context.Context, session *Session, ttl time.Duration) error
    DeleteSession(ctx context.Context, tokenHash string) error
    DeleteSessions(ctx context.Context, tokenHashes []string) error
    IncrementRateLimit(ctx context.Context, key string, window time.Duration) (count int, err error)
}
```

- **`GetSession(ctx, tokenHash)`:**
  - Cache Hit: returns `(*Session, nil)` for active, unexpired session (`ExpiresAt > now`).
  - Cache Miss: returns `(nil, nil)` if key absent or expired (`ExpiresAt <= now`). Callers fall back to primary `SessionStore`.
  - Failure: returns `(nil, error)` on network or operational failure.
- **`SetSession(ctx, session, ttl)`:**
  - Primary-First Ordering: called *after* primary database write commits.
  - Active-Only Rule: only caches fully authenticated sessions (`Pending2FA == false`). Intermediate pending-2FA sessions are *never* cached.
  - TTL: sets key TTL matching `ttl`.
- **`DeleteSession(ctx, tokenHash)`:** Idempotently evicts cached session. Returns `nil` if key absent.
- **`DeleteSessions(ctx, tokenHashes)`:** Bulk-evicts multiple sessions via single round-trip (e.g. Redis `DEL`). Idempotent no-op returning `nil` when `len(tokenHashes) == 0`.
- **`IncrementRateLimit(ctx, key, window)`:** Atomically increments distributed fixed-window counter without touching the primary database. Returns updated `count >= 1`.

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


## Password Hashing & Cryptography (Argon2id)

Kagi Core implements password hashing and verification in `internal/crypto` exclusively using **Argon2id** (via `golang.org/x/crypto/argon2`), adhering strictly to the **OWASP Password Storage Cheat Sheet** recommendations. Argon2id combines Argon2d's resistance to GPU/ASIC cracking with Argon2i's resistance to side-channel cache-timing attacks.

### Default OWASP Parameters

Kagi configures default parameters via `DefaultPasswordConfig()` matching OWASP recommendations for general server authentication:

| Parameter | Default Value | Bounds / Enforcement | Description |
| :--- | :--- | :--- | :--- |
| **Memory** | `65536` KiB (64 MB) | `8 * Parallelism` KiB .. `1048576` KiB (1 GB) | Memory cost to defend against GPU/ASIC brute-force |
| **Iterations** | `3` | `1` .. `100` (defaults to 3) | Time cost (number of sequential memory passes) |
| **Parallelism** | `2` | `1` .. `64` | Degree of parallelism (lanes/threads) |
| **SaltLength** | `16` bytes (128 bits) | $\ge 16$ bytes | Cryptographically secure random salt (`crypto/rand`) |
| **KeyLength** | `32` bytes (256 bits) | $\ge 16$ bytes | Length of derived authentication key |

### PHC String Wire Format

Argon2id hashes are serialized into standard [Password Hashing Competition (PHC)](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md) string format:

```
$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s
```

- **`$argon2id`:** Algorithm identifier.
- **`$v=19`:** Argon2 version (`0x13`), the current standard version supported by `golang.org/x/crypto/argon2`.
- **`$m=%d,t=%d,p=%d`:** Comma-separated cost parameters (`m` = memory in KiB, `t` = iterations, `p` = parallelism).
- **`$%s` (Salt):** Raw salt encoded with **unpadded standard base64** (`base64.RawStdEncoding`, RFC 4648).
- **`$%s` (Key):** Derived key encoded with **unpadded standard base64** (`base64.RawStdEncoding`, RFC 4648).

**Example PHC Hash String:**
```
$argon2id$v=19$m=65536,t=3,p=2$n2bYv6R5s+fQzK7X9w1A2g$U0f2o8M4j6l8V0x1Y3z5A7b9C1d3E5f7G9h1J3k5M7o
```

### Constant-Time Verification (`VerifyPassword`)

Password verification defends against timing attacks, panics, and authentication bypass:

1. **Strict Syntactic Validation:** Validates the 5 dollar-separated fields, algorithm name (`argon2id`), and version (`v=19`). Returns `ErrInvalidHash` or `ErrIncompatibleVersion` on mismatch.
2. **Parameter Boundary Validation:** Enforces strict parameter limits prior to key computation. This prevents memory exhaustion Denial of Service (DoS) attacks from maliciously crafted hashes (e.g., specifying tens of gigabytes of RAM) and protects against integer overflows or crashes.
3. **Key Derivation:** Recomputes the Argon2id key using `argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(key)))`.
4. **Constant-Time Comparison:** Evaluates equality using `crypto/subtle.ConstantTimeCompare(expectedKey, actualKey) == 1`. This ensures character-by-character comparison runs in constant time, preventing side-channel timing leaks that would allow attackers to deduce valid hashes.

### Parameter Migration & Rehashing (`NeedsRehash`)

When security requirements increase (e.g., upgrading memory from 64 MB to 128 MB), `NeedsRehash(encodedHash, targetParams)` checks whether a stored hash matches the current application configuration. If parameters differ, Kagi rehashes the password upon next successful login without interrupting user experience.

### User Enumeration Defense (`DummyHash`)

To prevent user enumeration side-channel attacks during sign-in:

- When a sign-in attempt targets a non-existent email, returning an immediate `ErrInvalidCredentials` reveals that the user does not exist due to the latency difference (~0.1ms vs ~50ms for Argon2id derivation).
- Calling full `HashPassword` for non-existent users would double the CPU cost and open a Denial-of-Service vector.
- **Solution (`DummyHash`):** `DummyHash(params)` constructs a syntactically valid Argon2id PHC string in $O(1)$ time with zero key derivation work. The authentication handler passes this dummy hash and the submitted password to `VerifyPassword`, executing the identical Argon2id key derivation and constant-time comparison path. This ensures identical response latency for existing and non-existent users without computational amplification.


### Token & OTP Cryptography

Kagi manages opaque session tokens, numeric one-time passwords (OTP), verification tokens, and hash verification in `internal/crypto` using standard library primitives (`crypto/rand`, `crypto/sha256`, `crypto/subtle`, `encoding/base64`, `encoding/hex`) following ADR-0003, ADR-0005, and ADR-0014:

#### Opaque Session Tokens

- **Entropy Generation:** Session tokens draw 32 bytes (256 bits, `TokenEntropyBytes = 32`) from `crypto/rand`.
- **Encoding:** Formatted as unpadded Base64URL strings (`base64.RawURLEncoding`, RFC 4648 §5) yielding exactly 43 ASCII characters (`SessionTokenLength = 43`).
- **Format Validation:** `ValidateSessionTokenFormat(token)` validates both exact length (43 characters) and valid character set (`[A-Za-z0-9-_]`), rejecting malformed tokens before database lookups.
- **Storage Hashing:** Raw session tokens are never stored in plaintext. They are hashed using SHA-256 (`HashToken` / `HashSHA256`) and stored as 64-character lowercase hex strings (`SHA256HexLength = 64`) in `session.token_hash`.
- **Entropy Hygiene:** Buffer memory used during generation is immediately zeroized via `zeroize([]byte)`.

#### Numeric OTP Generation

- **Rejection Sampling:** Implements unbiased byte rejection sampling over $b < 250$ using $b \pmod{10}$ to eliminate modulo bias across numeric digits (`0`-`9`), reading entropy from `crypto/rand`.
- **NIST / OWASP Compliance:** Adheres to NIST SP 800-63B and OWASP ASVS guidelines with length constrained between `MinOTPLength = 6` and `MaxOTPLength = 10` digits (defaults to `DefaultOTPLength = 6`).
- **Storage Hashing:** OTP codes are hashed via SHA-256 (`HashSHA256`) before persistence in storage models (`verification.CodeHash`).

#### Verification Tokens

- **Entropy & Encoding:** Verification tokens (e.g. email verification, password reset) generate 32 bytes of cryptographically secure entropy (`TokenEntropyBytes = 32`) encoded as 43-character unpadded Base64URL strings (`GenerateVerificationToken`).
- **Storage Hashing:** Hashed via SHA-256 (`HashSHA256`) and stored in `verification.CodeHash` to protect against token leakage via database compromise.

#### Constant-Time Verification

- **Side-Channel Defense:** `ConstantTimeCompare(a, b)` wraps `crypto/subtle.ConstantTimeCompare([]byte(a), []byte(b))` to evaluate strings in constant time relative to input length, preventing side-channel timing attacks on hash lookups.
- **Helper:** `VerifyHash(data, expectedHash)` hashes incoming data with SHA-256 and compares it against `expectedHash` using constant-time evaluation.
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
| `ErrAccountNotFound` | Target account link does not exist | `404 Not Found` | `account_not_found` |
| `ErrAccountAlreadyExists` | Provider account already linked | `409 Conflict` | `account_already_exists` |
| `ErrCannotUnlinkLastMethod`| Attempt to unlink sole login account | `400 Bad Request` | `cannot_unlink_last_method` |
| `ErrInvalidSessionToken` | Malformed token (length != 43) | `401 Unauthorized` | `invalid_session` |
| `ErrSessionNotFound` | Session does not exist in store | `401 Unauthorized` | `session_not_found` |
| `ErrSessionExpired` | Session read-check failed | `401 Unauthorized` | `session_expired` |
| `ErrSessionPending2FA` | Access attempted on pending-2FA session | `403 Forbidden` | `session_pending_2fa` |
| `ErrVerificationNotFound` | Verification record not found | `400 Bad Request` | `verification_not_found` |
| `ErrOTPNotFound` | Verification code not found | `400 Bad Request` | `otp_not_found` |
| `ErrOTPExpired` | OTP TTL has elapsed | `400 Bad Request` | `otp_expired` |
| `ErrOTPInvalid` | Mismatched code hash | `400 Bad Request` | `invalid_otp` |
| `ErrOTPMaxAttemptsExceeded`| Attempt limit reached; code purged | `429 Too Many Requests` | `otp_attempts_exceeded`|
| `ErrOTPCooldown` | Resend cooldown active | `429 Too Many Requests` | `otp_cooldown_active` |
| `ErrOAuthStateMissing` | OAuth callback missing state parameter | `400 Bad Request` | `oauth_state_missing` |
| `ErrOAuthStateMismatch` | State or PKCE verification failed | `400 Bad Request` | `oauth_state_mismatch` |
| `ErrOAuthStateExpired` | OAuth transient cookie expired | `400 Bad Request` | `oauth_state_expired` |
| `ErrOAuthProviderMismatch` | OAuth callback provider mismatch | `400 Bad Request` | `oauth_provider_mismatch` |
| `ErrOAuthRemoteError` | Remote identity provider error | `400 Bad Request` | `oauth_remote_error` |
| `ErrOAuthEmailUnverified`| Provider email is not verified | `400 Bad Request` | `oauth_email_unverified`|
| `ErrCSRFTokenMissing` | CSRF token missing from request | `403 Forbidden` | `csrf_token_missing` |
| `ErrCSRFTokenInvalid` | CSRF token HMAC verification failed | `403 Forbidden` | `csrf_token_invalid` |
| `ErrCSRFTokenMismatch` | Missing or mismatched CSRF token | `403 Forbidden` | `csrf_token_mismatch` |
| `ErrRateLimitExceeded` | Rate limit threshold exceeded | `429 Too Many Requests` | `rate_limit_exceeded` |
| `ErrNilStore` | Required storage port is nil | Startup Error | - |
| `ErrWeakMasterSecret` | Master secret entropy < 32 bytes | Startup Error | - |
| `ErrInvalidConfig` | Invalid configuration parameters | Startup Error | - |
| `ErrInternal` | Internal authentication error | `500 Internal Server Error` | `internal_error` |

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
> - Sign-in failures always return `ErrInvalidCredentials` (HTTP 401). When an email is not found, Kagi invokes `VerifyPassword` using `crypto.DummyHash(params)`—an $O(1)$ syntactically valid PHC string—to execute identical Argon2id key derivation and constant-time comparison, equalizing response timing and neutralizing timing side-channel enumeration.
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
