# ADR-0015: CSRF protection and OAuth state/PKCE storage

Status: Accepted · Date: 2026-11-05

## Context
Kagi authenticates users through stateful opaque sessions delivered via browser cookies ([ADR-0003](0003-opaque-sessions.md), [ADR-0014](0014-session-policy.md)). In browser-based environments, cookie-authenticated endpoints are susceptible to Cross-Site Request Forgery (CSRF) unless strict origin and request verifications are enforced.

Furthermore, Kagi supports OAuth 2.0 sign-in and account linking ([ADR-0004](0004-data-model.md), [ADR-0008](0008-oauth-x-oauth2.md), [ADR-0012](0012-account-linking-policy.md)). Secure OAuth flows require:
1. A cryptographically random `state` parameter to prevent OAuth login CSRF and authorization code injection (RFC 6749 Section 10.12).
2. Proof Key for Code Exchange (PKCE, RFC 7636) using a transient `code_verifier` and `code_challenge` (`S256`) to prevent authorization code interception attacks.

Per [ADR-0001](0001-http-agnostic-core.md), Kagi's core service layer must remain strictly HTTP-agnostic, with cookies, headers, and HTTP request lifecycles managed exclusively by HTTP wrappers (`http/fiber` for the MVP). This decision resolves GitHub Issue #5, defining the CSRF mitigation strategy for cookie sessions and establishing the storage and lifecycle model for OAuth `state` and PKCE verifiers.

## Decision

### 1. CSRF protection strategy for cookie sessions

#### Architectural boundary
- **HTTP wrappers (`http/*`):** CSRF defense is inherently an HTTP-layer countermeasure against browser ambient credential transmission. Request inspection, header/cookie extraction, and HTTP error responses live strictly in `http/*` wrappers.
- **Core layer (`internal/crypto`):** Core remains HTTP-agnostic, providing cryptographic primitives: cryptographically secure random token generation (`crypto/rand`), constant-time token comparison (`crypto/subtle.ConstantTimeCompare`), and HMAC signing/verification (`crypto/hmac`).

#### Defense-in-depth: Dual-layer protection
Kagi enforces two complementary layers of CSRF defense:
1. **Cookie attribute baseline:** Session and CSRF cookies are configured with `SameSite=Lax`, `HttpOnly`, `Secure` (in production/TLS), and the `__Host-` cookie prefix (`__Host-kagi_session`, `__Host-kagi_csrf`).
   - `SameSite=Lax` prevents modern browsers from sending session cookies on cross-site subrequests (`fetch`, `XMLHttpRequest`, `<img>`, `<iframe>`) and cross-site HTTP `POST` form submissions.
   - The `__Host-` prefix enforces `Secure=true`, `Path=/`, and prevents cookie overriding or tossing from untrusted subdomains.
2. **Cryptographic token verification (Masked HMAC Double Submit Cookie):** Because `SameSite=Lax` cookies are still sent on cross-site top-level GET navigations, and to protect legacy/non-compliant browsers and defense against subdomain attacks, mutating requests must present a matching CSRF token.

#### Token format, masking, and verification
- **Cookie payload:** The CSRF cookie stores a raw 32-byte (256-bit) cryptographically random token concatenated with its HMAC-SHA256 signature using the server's authentication secret key: `raw_token || HMAC-SHA256(raw_token, secret)`.
- **Client token masking (BREACH mitigation):** When exposing the CSRF token to clients (via the `GET /auth/csrf` endpoint or response headers), the token is masked using a per-request random 32-byte one-time pad (`XOR` mask). The client receives `mask || (raw_token ^ mask)`. This ensures that identical CSRF tokens produce different string representations in successive HTTP responses, thwarting compression side-channel attacks (BREACH).
- **Extraction:** For mutating requests, the HTTP wrapper extracts the masked token from:
  1. Header `X-CSRF-Token` or `X-Kagi-CSRF-Token` (standard for SPAs and AJAX clients), or
  2. URL-encoded / multipart form field `_csrf` (for traditional server-rendered HTML forms).
- **Validation:** The HTTP wrapper unmasks the submitted token, verifies the cookie's HMAC signature, and checks equality with the cookie's `raw_token` using constant-time comparison (`crypto/subtle.ConstantTimeCompare`).

#### Safe vs. mutating methods and login CSRF
- **Safe methods (exempt):** `GET`, `HEAD`, `OPTIONS`, `TRACE` are treated as read-only and exempt from CSRF token validation. Handlers for safe methods must never execute state-changing domain operations.
- **Mutating methods (enforced):** All `POST`, `PUT`, `PATCH`, `DELETE` requests using cookie authentication must provide a valid CSRF token.
- **Login CSRF protection:** Public mutating auth endpoints (`/sign-up`, `/sign-in`, `/password/reset`, `/otp/*`) also require CSRF token validation. This prevents login CSRF attacks, where an attacker tricks a victim's browser into authenticating into an attacker-controlled account.

---

### 2. OAuth state and PKCE verifier storage

#### Stateless encrypted cookie storage
Kagi stores the transient OAuth `state` and PKCE `code_verifier` in a **stateless, encrypted, and authenticated HTTP cookie** (`__Host-kagi_oauth_state` or `kagi_oauth_state` on plaintext local development).

#### Rationale against database storage
- **Write amplification:** Storing ephemeral OAuth state in the database (`verification` table) would introduce an unnecessary database insert on every OAuth redirect and a delete on callback.
- **Orphaned records:** Users frequently abandon OAuth flows by closing the browser tab or hitting back. Database storage leaves orphaned rows that accumulate until background cleanup runs ([ADR-0010](0010-expiry-and-cleanup.md)).
- **Horizontal scalability without dependencies:** An authenticated encrypted cookie requires **zero database writes**, **zero cleanup queries**, and functions seamlessly across multiple application instances behind a load balancer without requiring Redis or sticky sessions.

#### Ephemeral cookie payload and encryption
- **Payload structure:**
  ```json
  {
    "state": "43-character base64url random string",
    "code_verifier": "43-character base64url PKCE verifier",
    "provider": "google",
    "redirect_uri": "https://app.example.com/api/auth/oauth/google/callback",
    "created_at": 1730800000
  }
  ```
- **Encryption algorithm:** Authenticated Encryption with Associated Data (AEAD) using **AES-256-GCM** (or **ChaCha20-Poly1305**) keyed with the application's auth secret key. Tampering or truncation causes decryption failure.
- **Cookie attributes:**
  - `HttpOnly`: `true` (unreadable by client-side JavaScript).
  - `Secure`: `true` (enforced via `__Host-` prefix in production).
  - `SameSite`: strictly `Lax`. (Must **not** be `Strict`, because the OAuth provider callback is an incoming top-level GET navigation from a third-party origin).
  - `Path`: `/` (or the configured auth mount path).
  - `Max-Age`: `600` seconds (10-minute lifetime).

#### OAuth flow lifecycle and single-use invalidation
1. **Initiation (`GET /auth/oauth/:provider`):**
   - Core's `OAuthService.GenerateAuthURL` generates:
     - `state`: 32 random bytes, base64url-encoded (256 bits of entropy).
     - `code_verifier`: 32 random bytes, base64url-encoded (43 chars, RFC 7636 compliant).
     - `code_challenge`: `base64url(sha256(code_verifier))`.
     - Authorization URL with `code_challenge_method=S256` (the `plain` method is strictly disallowed).
   - The HTTP wrapper serializes and encrypts the payload, sets the `__Host-kagi_oauth_state` cookie (`Max-Age=600`), and redirects the user to the provider's authorization URL.
2. **Callback (`GET /auth/oauth/:provider/callback`):**
   - The HTTP wrapper immediately issues a `Set-Cookie` header invalidating `__Host-kagi_oauth_state` (`Max-Age=0`), guaranteeing that state and PKCE verifiers are strictly single-use regardless of whether downstream operations succeed or fail.
   - The wrapper reads and decrypts the cookie payload:
     - If the cookie is missing or cannot be decrypted: returns `400 Bad Request` (`ErrOAuthStateExpired`).
     - If `payload.created_at + 10m < now`: returns `400 Bad Request` (`ErrOAuthStateExpired`).
     - If `payload.provider != route.provider`: returns `400 Bad Request` (`ErrOAuthProviderMismatch`).
     - Constant-time verification of `payload.state` against query parameter `?state=...`: if mismatched, returns `400 Bad Request` (`ErrOAuthStateMismatch`).
   - The wrapper passes `code` and the decrypted `payload.code_verifier` to Core's `OAuthService.Exchange(ctx, provider, code, codeVerifier)`.
   - Core exchanges the code for tokens with the identity provider using PKCE verification and completes sign-in or account linking ([ADR-0012](0012-account-linking-policy.md)).

---

### 3. Core interfaces and HTTP wrapper contracts

#### Core service contract (`oauth.go`)
```go
package kagi

import "context"

type AuthURLResult struct {
    URL          string
    State        string
    CodeVerifier string
}

type OAuthService interface {
    // GenerateAuthURL generates the provider authorization URL with PKCE (S256) and a secure random state.
    GenerateAuthURL(ctx context.Context, provider string, opts ...AuthURLOption) (*AuthURLResult, error)

    // Exchange verifies the authorization code using the PKCE code_verifier, fetches user profile,
    // and creates or links the user account.
    Exchange(ctx context.Context, provider string, code string, codeVerifier string) (*User, *Account, error)
}
```

#### HTTP wrapper configuration (`http/fiber`)
```go
type CSRFConfig struct {
    SecretKey     []byte        // 32-byte key for HMAC signing and masking
    CookieName    string        // Default: "__Host-kagi_csrf" ("kagi_csrf" if !Secure)
    HeaderName    string        // Default: "X-CSRF-Token"
    FormFieldName string        // Default: "_csrf"
    CookieMaxAge  time.Duration // Default: 24 * time.Hour
    Secure        bool          // Default: true (set false only in tests/dev)
}

type OAuthConfig struct {
    SecretKey    []byte        // 32-byte key for AEAD cookie encryption
    CookieName   string        // Default: "__Host-kagi_oauth_state"
    StateTTL     time.Duration // Default: 10 * time.Minute
    Secure       bool          // Default: true
}
```

#### Sentinel error mapping per ADR-0013
The following sentinel errors are defined in Core and mapped to HTTP status codes by `http/*`:
- `ErrCSRFTokenMissing` -> `403 Forbidden` (`{"error": "csrf_token_missing"}`)
- `ErrCSRFTokenInvalid` -> `403 Forbidden` (`{"error": "csrf_token_invalid"}`)
- `ErrOAuthStateMissing` -> `400 Bad Request` (`{"error": "oauth_state_missing"}`)
- `ErrOAuthStateMismatch` -> `400 Bad Request` (`{"error": "oauth_state_mismatch"}`)
- `ErrOAuthStateExpired` -> `400 Bad Request` (`{"error": "oauth_state_expired"}`)
- `ErrOAuthProviderMismatch` -> `400 Bad Request` (`{"error": "oauth_provider_mismatch"}`)

---

## Consequences

### Positive
- **Zero database write amplification:** Ephemeral OAuth handshakes create no database rows or cleanup queries.
- **Horizontal scalability:** Any number of stateless API replicas can initiate and complete OAuth flows without shared storage or sticky sessions, provided they share the application secret key.
- **Robust CSRF defense:** The combination of `SameSite=Lax`, `__Host-` cookie prefixes, HMAC-signed tokens, and client token masking provides industry-standard defense against CSRF, Login CSRF, BREACH compression attacks, and subdomain cookie-tossing.
- **Strict single-use lifecycle:** OAuth state cookies are immediately purged on the callback request, preventing replay or authorization code reuse.
- **Clean architectural boundaries:** Core remains strictly HTTP-agnostic ([ADR-0001](0001-http-agnostic-core.md)), while `http/fiber` provides comprehensive, turnkey security for web applications.

### Tradeoffs and considerations
- **Cookie size:** Encrypted OAuth state cookies are approximately 250–350 bytes; well below the 4KB browser cookie limit, but present during active OAuth handshakes.
- **Secret key distribution:** Multi-replica deployments must supply a consistent 32-byte secret key to all instances for cookie decryption and HMAC verification.
- **SPA CSRF token bootstrapping:** Single Page Applications need to fetch an initial CSRF token via `GET /auth/csrf` (or read a masked token provided on initial page load) before dispatching mutating API calls.
