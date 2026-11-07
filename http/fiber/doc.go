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
