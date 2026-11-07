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

// setCSRFCookie configures and sets the CSRF cookie on the Fiber response.
func setCSRFCookie(c *fiber.Ctx, cfg CSRFConfig, cookieValue string) {
	maxAge := int(cfg.CookieMaxAge.Seconds())
	if maxAge <= 0 {
		maxAge = int((24 * time.Hour).Seconds())
	}

	c.Cookie(&fiber.Cookie{
		Name:     cfg.EffectiveCookieName(),
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   maxAge,
		Expires:  time.Now().Add(time.Duration(maxAge) * time.Second),
		Secure:   cfg.IsSecure(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// clearCSRFCookie clears the CSRF cookie by issuing an expired cookie with MaxAge: -1.
func clearCSRFCookie(c *fiber.Ctx, cfg CSRFConfig) {
	c.Cookie(&fiber.Cookie{
		Name:     cfg.EffectiveCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   cfg.IsSecure(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// getCSRFCookie extracts the raw CSRF cookie payload from the incoming request cookie.
func getCSRFCookie(c *fiber.Ctx, cfg CSRFConfig) string {
	val := c.Cookies(cfg.EffectiveCookieName())
	if val == "" && !cfg.IsSecure() && cfg.CookieName != "" {
		val = c.Cookies(cfg.CookieName)
	}
	return val
}
