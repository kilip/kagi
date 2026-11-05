# ADR-0015: CSRF protection and OAuth state/PKCE storage

Status: Accepted · Date: 2026-11-05

## Context
Kagi authenticates users through stateful opaque sessions delivered via browser cookies ([ADR-0003](0003-opaque-sessions.md), [ADR-0014](0014-session-policy.md)). In browser-based environments, cookie-authenticated endpoints are susceptible to Cross-Site Request Forgery (CSRF) unless strict origin and request verifications are enforced.

Furthermore, Kagi supports OAuth 2.0 sign-in and account linking ([ADR-0004](0004-data-model.md), [ADR-0008](0008-oauth-x-oauth2.md), [ADR-0012](0012-account-linking-policy.md)). Secure OAuth flows require:
1. A cryptographically random `state` parameter to prevent OAuth login CSRF, state injection, and authorization code injection (RFC 6749 Section 10.12).
2. Proof Key for Code Exchange (PKCE, RFC 7636) using a transient `code_verifier` and `code_challenge` (`S256`) to prevent authorization code interception and injection attacks.

Per [ADR-0001](0001-http-agnostic-core.md), Kagi's core service layer must remain strictly HTTP-agnostic, with cookies, headers, and HTTP request lifecycles managed exclusively by HTTP wrappers (`http/fiber` for the MVP). This decision resolves GitHub Issue #5, defining the CSRF mitigation strategy for cookie sessions and establishing the storage, cryptographic model, and lifecycle for OAuth `state` and PKCE verifiers.

## Decision

### 1. CSRF protection strategy for cookie sessions

#### Architectural boundary
- **HTTP wrappers (`http/*`):** CSRF defense is an HTTP-layer countermeasure against browser ambient credential transmission. Request inspection, header/cookie extraction, and HTTP error responses live strictly in `http/*` wrappers.
- **Core layer (`internal/crypto`):** Core remains HTTP-agnostic, providing cryptographic primitives: cryptographically secure random token generation (`crypto/rand`), constant-time token comparison (`crypto/subtle.ConstantTimeCompare`), HKDF subkey derivation (`golang.org/x/crypto/hkdf`), and HMAC signing/verification (`crypto/hmac`).

#### Cryptographic key derivation (HKDF)
To avoid multi-protocol cross-cipher key reuse when a single application master secret is supplied:
- `internal/crypto` uses HKDF with SHA-256 to derive distinct 32-byte subkeys:
  - `CSRFKey = HKDF-Expand(masterSecret, "kagi-csrf-hmac-sha256-v1", 32)`
  - `OAuthKey = HKDF-Expand(masterSecret, "kagi-oauth-aead-encryption-v1", 32)`

#### Defense-in-depth: Dual-layer protection
Kagi enforces two complementary layers of CSRF defense:
1. **Cookie attribute baseline:** Session and CSRF cookies are configured with `SameSite=Lax`, `HttpOnly`, `Secure` (in production/TLS), and the `__Host-` cookie prefix (`__Host-kagi_session`, `__Host-kagi_csrf`).
   - `SameSite=Lax` prevents modern browsers from sending session cookies on cross-site subrequests (`fetch`, `XMLHttpRequest`, `<img>`, `<iframe>`) and cross-site HTTP `POST` form submissions.
   - The `__Host-` prefix enforces `Secure=true`, `Path=/`, and prevents cookie overriding or tossing from untrusted subdomains.
2. **Cryptographic token verification (Masked HMAC Double Submit Cookie):** Because `SameSite=Lax` cookies are still sent on cross-site top-level GET navigations, and to protect against legacy/non-compliant browsers and subdomain attacks in non-prefixed environments, mutating requests must present a matching CSRF token.

#### Token format, wire encoding, masking, and verification
- **Cookie payload:** The CSRF cookie stores a 32-byte (256-bit) cryptographically random token concatenated with its HMAC-SHA256 signature:
  $$\text{Payload} = \text{raw\_token}_{32\text{B}} \parallel \text{HMAC-SHA256}(\text{raw\_token}, \text{CSRFKey})_{32\text{B}}$$
  The 64-byte payload is encoded as an **86-character unpadded Base64URL string** (`base64.RawURLEncoding`) stored in `__Host-kagi_csrf`.
- **Client token masking (BREACH mitigation):** When exposing the CSRF token to clients (via the `GET /auth/csrf` endpoint returning `{"csrf_token": "..."}` or response headers), the token is masked using a per-request random 32-byte one-time pad (`XOR` mask). The client receives:
  $$\text{ClientToken} = \text{base64url}(\text{mask}_{32\text{B}} \parallel (\text{raw\_token} \oplus \text{mask})_{32\text{B}})$$
  This ensures that identical CSRF tokens produce different string representations on successive HTTP responses, thwarting compression side-channel attacks (BREACH).
- **Extraction:** For mutating requests, the HTTP wrapper extracts the masked token from:
  1. Header `X-CSRF-Token` or `X-Kagi-CSRF-Token` (standard for SPAs and AJAX clients), or
  2. URL-encoded / multipart form field `_csrf` (for traditional server-rendered HTML forms).
- **Validation:** The HTTP wrapper decodes the submitted token, unmasks `raw_token`, verifies the cookie's HMAC-SHA256 signature using `crypto/subtle.ConstantTimeCompare`, and verifies equality between the unmasked token and the cookie's `raw_token`.
- **Token rotation on authentication boundaries:** The CSRF cookie is rotated whenever user session state changes (successful `/sign-in`, `/sign-up`, `/sign-out`, or privilege elevation) to prevent session fixation and privilege-escalation token reuse.

#### Safe vs. mutating methods and login CSRF
- **Safe methods (exempt):** `GET`, `HEAD`, `OPTIONS`, `TRACE` are treated as read-only and exempt from CSRF token validation. Handlers for safe methods must never execute state-changing domain operations (e.g. sign-out is strictly `POST /auth/sign-out`, never `GET`).
- **Mutating methods (enforced):** All `POST`, `PUT`, `PATCH`, `DELETE` requests using cookie authentication must provide a valid CSRF token.
- **Login CSRF protection:** Public mutating auth endpoints (`/sign-up`, `/sign-in`, `/password/reset`, `/otp/*`) also require CSRF token validation. This prevents login CSRF attacks, where an attacker tricks a victim's browser into authenticating into an attacker-controlled account.

---

### 2. OAuth state and PKCE verifier storage

#### Stateless encrypted cookie storage
Kagi stores transient OAuth `state` and PKCE `code_verifier` data in a **stateless, encrypted, and authenticated HTTP cookie** scoped per provider:
$$\text{Cookie Name: } \text{\_\_Host-kagi\_oauth\_<provider>}$$
*(e.g., `__Host-kagi_oauth_google`, `__Host-kagi_oauth_github`, or `kagi_oauth_<provider>` in non-TLS environments).*

#### Rationale against database storage
- **Zero write amplification:** Ephemeral OAuth handshakes require no database rows, eliminating inserts on redirect and deletes on callback.
- **Zero orphaned records:** Abandoned OAuth attempts leave no dangling database records, avoiding table bloat and lock contention during background cleanup ([ADR-0010](0010-expiry-and-cleanup.md)).
- **Horizontal scalability without dependencies:** Replicas sharing the master auth secret key can initiate and complete OAuth flows across any instance without Redis, database synchronization, or sticky load balancing.
- **Provider-scoped cookie isolation:** Scoping the cookie name by provider (`__Host-kagi_oauth_<provider>`) prevents multi-tab race conditions where a user simultaneously initiating flows for different providers (e.g., Google and GitHub) would otherwise overwrite the in-flight state.

#### Ephemeral cookie payload and AEAD cipher construction
- **Payload structure:**
  ```json
  {
    "state": "43-character base64url random string",
    "code_verifier": "43-character base64url PKCE verifier",
    "provider": "google",
    "redirect_uri": "https://app.example.com/api/auth/oauth/google/callback",
    "action": "sign_in",
    "user_id": "",
    "created_at": 1730800000
  }
  ```
  *(When initiating account linking per [ADR-0012](0012-account-linking-policy.md), `action` is set to `"link"` and `user_id` is bound to the currently authenticated user's ID).*

- **AEAD encryption algorithm:** Authenticated Encryption with Associated Data using **AES-256-GCM** (or **ChaCha20-Poly1305**) keyed with `OAuthKey`.
- **Nonce & AAD hygiene:**
  - Every cookie emission generates a fresh, cryptographically secure 12-byte random nonce via `crypto/rand`. Nonce reuse is strictly prohibited.
  - Associated Authenticated Data (AAD) is explicitly bound:
    $$\text{AAD} = \text{"kagi-oauth-state:"} \parallel \text{provider}$$
  - The encrypted cookie value is serialized as:
    $$\text{Cookie Value} = \text{base64url}(\text{nonce}_{12\text{B}} \parallel \text{ciphertext} \parallel \text{tag}_{16\text{B}})$$
- **Cookie attributes:**
  - `HttpOnly`: `true` (unreadable by client-side JavaScript).
  - `Secure`: `true` (enforced via `__Host-` prefix in production).
  - `SameSite`: strictly `Lax`. (Must **not** be `Strict`, because the OAuth provider callback is an incoming top-level GET navigation from an external origin).
  - `Path`: `/` (or configured auth mount path).
  - `Max-Age`: `600` seconds (10-minute lifetime).

#### OAuth flow lifecycle and single-use invalidation
1. **Initiation (`GET /auth/oauth/:provider`):**
   - Core's `OAuthService.GenerateAuthURL` generates:
     - `state`: 32 random bytes, base64url-encoded (256 bits of entropy).
     - `code_verifier`: 32 random bytes, base64url-encoded (43 chars, RFC 7636 compliant).
     - `code_challenge`: `base64url(sha256(code_verifier))`.
     - Authorization URL with `code_challenge_method=S256` (`plain` is strictly disallowed).
   - If an authenticated session exists and the request intends to link an account, `action` is set to `"link"` and `user_id` is set to the current user.
   - The HTTP wrapper serializes and encrypts the payload, sets `__Host-kagi_oauth_<provider>` (`Max-Age=600`), and redirects the browser.
2. **Callback (`GET /auth/oauth/:provider/callback`):**
   - **Immediate cookie purge:** The HTTP wrapper immediately issues `Set-Cookie` with `Max-Age=0` for `__Host-kagi_oauth_<provider>`, guaranteeing that state and PKCE verifiers are strictly single-use regardless of outcome.
   - **Defensive headers:** Sets `Referrer-Policy: no-referrer` and `Cache-Control: no-store` to prevent transient authorization codes from leaking into upstream headers or browser history.
   - **Provider error handling:** If the callback query includes `?error=...` (e.g., user denied consent), maps to `400 Bad Request` (`ErrOAuthRemoteError`).
   - **Cookie decryption & validation:**
     - Missing or undecryptable cookie: returns `400 Bad Request` (`ErrOAuthStateExpired`).
     - Expired timestamp (`created_at + 10m < now`): returns `400 Bad Request` (`ErrOAuthStateExpired`).
     - Provider mismatch (`payload.provider != route.provider`): returns `400 Bad Request` (`ErrOAuthProviderMismatch`).
     - Constant-time verification of `payload.state` against query parameter `?state=...`: if mismatched, returns `400 Bad Request` (`ErrOAuthStateMismatch`).
     - **Account linking integrity:** If `payload.action == "link"`, validates that the requesting session is authenticated and matches `payload.user_id`.
   - **Exchange execution:** Passes parameters to Core's `OAuthService.Exchange(ctx, params)`.
   - **Session establishment per ADR-0014:**
     - If the user has `two_factor_enabled = true` and authenticated via primary OAuth, Core creates a session with `pending_2fa = true` (short 10m TTL, no Redis cache) and returns `ErrSessionPending2FA`.
     - If 2FA is not required, Core creates an active session (`pending_2fa = false`). The HTTP wrapper delivers the session token via `__Host-kagi_session` cookie (`SameSite=Lax`, `HttpOnly`, `Secure`).

---

### 3. Core interfaces and HTTP wrapper contracts

#### Core service contracts (`oauth.go`)
```go
package kagi

import "context"

type AuthURLResult struct {
    URL          string
    State        string
    CodeVerifier string
}

type AuthURLOption func(*AuthURLOptions)

type AuthURLOptions struct {
    RedirectURI string
    Scopes      []string
}

type OAuthExchangeParams struct {
    Provider     string
    Code         string
    CodeVerifier string
    RedirectURI  string
    LinkUserID   string // Non-empty when explicitly linking an account (ADR-0012)
    IP           string // Client IP for session auditing (ADR-0014)
    UserAgent    string // Client User Agent for session auditing (ADR-0014)
}

type OAuthAuthResult struct {
    User      *User
    Account   *Account
    Session   *Session // Opaque session per ADR-0014 (active or pending 2FA)
    RawToken  string   // 43-character raw session token for Set-Cookie
    IsNewUser bool     // True if a new user was registered
}

type OAuthService interface {
    // GenerateAuthURL generates the provider authorization URL with PKCE (S256) and a secure random state.
    GenerateAuthURL(ctx context.Context, provider string, opts ...AuthURLOption) (*AuthURLResult, error)

    // Exchange verifies the authorization code using the PKCE code_verifier, fetches user profile,
    // resolves account linking, and creates the session per ADR-0014.
    Exchange(ctx context.Context, params OAuthExchangeParams) (*OAuthAuthResult, error)
}
```

#### HTTP wrapper configuration (`http/fiber`)
```go
type CSRFConfig struct {
    SecretKey     []byte        // Master key used with HKDF to derive CSRF signing key
    CookieName    string        // Default: "__Host-kagi_csrf" ("kagi_csrf" if !Secure)
    HeaderName    string        // Default: "X-CSRF-Token"
    FormFieldName string        // Default: "_csrf"
    CookieMaxAge  time.Duration // Default: 24 * time.Hour
    Secure        bool          // Default: true (false only in non-TLS dev)
}

type OAuthConfig struct {
    SecretKey    []byte        // Master key used with HKDF to derive AEAD encryption key
    CookiePrefix string        // Default: "__Host-kagi_oauth_" ("kagi_oauth_" if !Secure)
    StateTTL     time.Duration // Default: 10 * time.Minute
    Secure       bool          // Default: true
}
```

#### Sentinel error mapping per ADR-0013
Core defines the authoritative sentinel errors; `http/*` translates them into HTTP status codes and uniform JSON responses:
- `ErrCSRFTokenMissing` -> `403 Forbidden` (`{"error": "csrf_token_missing"}`)
- `ErrCSRFTokenInvalid` -> `403 Forbidden` (`{"error": "csrf_token_invalid"}`)
- `ErrOAuthStateMissing` -> `400 Bad Request` (`{"error": "oauth_state_missing"}`)
- `ErrOAuthStateMismatch` -> `400 Bad Request` (`{"error": "oauth_state_mismatch"}`)
- `ErrOAuthStateExpired` -> `400 Bad Request` (`{"error": "oauth_state_expired"}`)
- `ErrOAuthProviderMismatch` -> `400 Bad Request` (`{"error": "oauth_provider_mismatch"}`)
- `ErrOAuthRemoteError` -> `400 Bad Request` (`{"error": "oauth_remote_error"}`)
- `ErrOAuthEmailUnverified` -> `409 Conflict` (`{"error": "oauth_email_unverified"}`)

---

## Consequences

### Positive
- **Cryptographic rigor:** Subkey derivation via HKDF prevents multi-protocol key reuse between HMAC and AEAD ciphers. Mandatory 12-byte random nonces and AAD binding prevent AES-GCM nonce collision and cross-context ciphertext replay.
- **Zero database write amplification:** Ephemeral OAuth handshakes create no database rows or cleanup contention.
- **Horizontal scalability:** Replicas sharing the master secret initiate and complete OAuth flows statelessly across any node.
- **Robust CSRF defense:** Pairing `SameSite=Lax`, `__Host-` prefixes, HMAC-SHA256 signing, and per-response XOR masking protects against CSRF, Login CSRF, BREACH compression attacks, and subdomain cookie-tossing.
- **Account linking security:** Explicit binding of `action: link` and `user_id` inside the state payload guarantees that account linking cannot be hijacked by a malicious third-party OAuth redirect.
- **Multi-tab isolation:** Provider-scoped cookies (`__Host-kagi_oauth_<provider>`) eliminate race conditions during concurrent authentication attempts.
- **Seamless ADR-0014 integration:** `OAuthService.Exchange` yields complete session credentials (`*Session`, `rawToken`), respecting 2FA status and avoiding session logic duplication in HTTP wrappers.

### Tradeoffs and considerations
- **Cookie size:** Encrypted OAuth state cookies are approximately 250–350 bytes; well below the 4KB browser limit, but present during active OAuth handshakes.
- **Secret key distribution:** Multi-replica deployments must supply a consistent master secret key across instances for cookie decryption and HMAC verification.
- **SPA CSRF token bootstrapping:** Single Page Applications must fetch an initial CSRF token via `GET /auth/csrf` before dispatching mutating API calls.
