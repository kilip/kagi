package fiber

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

// setSessionCookie configures and sets the session cookie on the Fiber response.
func setSessionCookie(c *fiber.Ctx, cfg CookieConfig, rawToken string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}

	c.Cookie(&fiber.Cookie{
		Name:     cfg.CookieName(),
		Value:    rawToken,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		MaxAge:   maxAge,
		Expires:  expiresAt,
		Secure:   cfg.IsSecure(),
		HTTPOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
	})
}

// clearSessionCookie clears the session cookie by issuing an expired cookie with MaxAge: -1.
func clearSessionCookie(c *fiber.Ctx, cfg CookieConfig) {
	c.Cookie(&fiber.Cookie{
		Name:     cfg.CookieName(),
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   cfg.IsSecure(),
		HTTPOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
	})
}

// getSessionToken extracts the raw session token from the incoming request cookie.
func getSessionToken(c *fiber.Ctx, cfg CookieConfig) string {
	return c.Cookies(cfg.CookieName())
}
