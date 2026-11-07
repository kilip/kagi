// Package fiber provides Fiber handlers and middleware for Kagi.
//
// # Middleware
//
// The package provides session validation middleware that extracts and validates
// session cookies, enforces sliding session renewal, and populates the authenticated
// session and user information into Fiber locals and request context.
//
// Use [Handler.RequireAuth] to require an authenticated session (returning 401 Unauthorized
// for missing or invalid sessions):
//
//	app.Get("/profile", authHandler.RequireAuth(), func(c *fiber.Ctx) error {
//		session := fiber.SessionFromCtx(c)
//		userID := fiber.UserIDFromCtx(c)
//		return c.JSON(fiber.Map{
//			"session_id": session.ID,
//			"user_id":    userID,
//		})
//	})
//
// Use [Handler.Session] for optional session handling where unauthenticated requests
// are allowed to proceed without a valid session:
//
//	app.Get("/public", authHandler.Session(), func(c *fiber.Ctx) error {
//		if session := fiber.SessionFromCtx(c); session != nil {
//			return c.SendString("Hello user " + session.UserID)
//		}
//		return c.SendString("Hello guest")
//	})
//
// Middleware can also be instantiated standalone via [NewRequireAuth] or [NewSessionMiddleware].
//
// # Configuration Options
//
// Middleware behavior can be customized using [MiddlewareOption] functions:
//
//   - [WithMiddlewareFetchUser]: fetch the full [*kagi.User] entity from the user store.
//   - [WithMiddlewareOptional]: override whether session authentication is optional.
//   - [WithMiddlewareErrorHandler]: custom callback for handling session errors.
//   - [WithMiddlewareFilter]: predicate to bypass middleware execution for specific requests.
//   - [WithMiddlewareCookie]: override cookie configuration for session extraction and sliding renewal.
//
// Example with options:
//
//	app.Use(authHandler.RequireAuth(
//		fiber.WithMiddlewareFetchUser(true),
//		fiber.WithMiddlewareErrorHandler(func(c *fiber.Ctx, err error) error {
//			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
//		}),
//	))
//
// # Context Accessors
//
// Helper functions extract session and user data from [*fiber.Ctx] locals or request [context.Context]:
//
//   - [SessionFromCtx] / [SessionFromContext]: retrieve [*kagi.Session].
//   - [UserIDFromCtx] / [UserIDFromContext]: retrieve user ID string.
//   - [UserFromCtx] / [UserFromContext]: retrieve [*kagi.User] (when populated via [WithMiddlewareFetchUser]).
//
// # CSRF Protection
//
// Kagi Fiber integration implements Cross-Site Request Forgery (CSRF) defense using
// a Masked HMAC Double-Submit Cookie architecture per ADR-0015.
//
// State-changing HTTP requests (POST, PUT, PATCH, DELETE) require a matching CSRF token,
// while safe HTTP methods (GET, HEAD, OPTIONS, TRACE) are exempt from validation.
//
// ## Architecture & Cryptographic Primitives
//
// CSRF protection employs dual-layer defense-in-depth:
//
//   - Cookie payload: The CSRF cookie stores a 32-byte cryptographically secure random token
//     concatenated with its HMAC-SHA256 signature, derived from the coordinator master secret
//     via HKDF-SHA256 (RFC 5869):
//     Cookie = base64url(raw_token_32B || HMAC-SHA256(raw_token, CSRFKey)_32B)
//     The cookie defaults to "__Host-kagi_csrf", SameSite=Lax, HttpOnly, and Secure.
//
//   - Client token masking (BREACH mitigation): When clients fetch a CSRF token via GET /csrf,
//     the raw token is masked with a per-request random 32-byte one-time pad (XOR mask):
//     ClientToken = base64url(mask_32B || (raw_token ^ mask)_32B)
//     Successive requests with the same cookie yield distinct masked token strings, preventing
//     BREACH side-channel compression attacks while verifying against the same cookie.
//
//   - Token rotation: The CSRF cookie is automatically rotated on authentication boundaries
//     (successful /sign-in, /sign-up, and /sign-out) to prevent session fixation and privilege elevation.
//
//   - Insecure Dev Mode: When [WithInsecureDevMode] is enabled or CSRFConfig.Secure is false,
//     the "__Host-" cookie prefix is omitted ("kagi_csrf") and the Secure attribute is disabled,
//     permitting local HTTP development without TLS.
//
// ## Token Extraction
//
// The CSRF middleware extracts client tokens from:
//  1. The "X-CSRF-Token" request header (primary, standard for SPAs and AJAX clients).
//  2. The "X-Kagi-CSRF-Token" request header (fallback).
//  3. The "_csrf" form field (for application/x-www-form-urlencoded and multipart forms).
//
// ## Middleware Usage
//
// Use [Handler.CSRF] to protect application routes using the handler's configured CSRF settings:
//
//	app.Post("/api/transfer", authHandler.CSRF(), transferHandler)
//
// Use [NewCSRF] to instantiate a standalone CSRF middleware with custom options:
//
//	csrfMid := fiber.NewCSRF(auth, fiberCfg,
//		fiber.WithCSRFFilter(func(c *fiber.Ctx) bool {
//			return c.Path() == "/webhooks" // bypass webhook endpoints
//		}),
//		fiber.WithCSRFErrorHandler(func(c *fiber.Ctx, err error) error {
//			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
//		}),
//	)
//	app.Use(csrfMid)
//
// ## Configuration & Options
//
// CSRF settings can be customized using [CSRFConfig] via [WithCSRFConfig]:
//
//   - SecretKey: custom master key for HKDF CSRF subkey derivation (defaults to coordinator secret).
//   - CookieName: custom cookie name (default: "__Host-kagi_csrf" or "kagi_csrf").
//   - HeaderName: custom header name (default: "X-CSRF-Token").
//   - FormFieldName: custom form field name (default: "_csrf").
//   - CookieMaxAge: cookie expiration duration (default: 24h).
//   - Secure: whether cookie requires HTTPS (default: true).
//   - Disabled: disables CSRF enforcement across endpoints (e.g. for testing).
//   - [WithCSRFFilter]: predicate to bypass CSRF verification for specific requests.
//   - [WithCSRFErrorHandler]: custom handler invoked when CSRF validation fails.
//
// # OpenAPI Specification
//
//	@title						Kagi Authentication API
//	@version					1.0.0
//	@description				Reusable authentication HTTP API powered by Kagi.
//	@license.name				MIT
//	@license.url				https://opensource.org/licenses/MIT
//	@BasePath					/auth
//	@securityDefinitions.apikey	SessionCookie
//	@in							cookie
//	@name						kagi_session
//	@description				Opaque session token stored in an HttpOnly, Secure cookie.
package fiber
