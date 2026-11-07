package fiber

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/kilip/kagi"
)

// ErrorResponse represents a uniform JSON error payload.
type ErrorResponse struct {
	Error string `json:"error"`
}

// writeError writes a uniform JSON error response.
func writeError(c *fiber.Ctx, status int, code string) error {
	return c.Status(status).JSON(ErrorResponse{
		Error: code,
	})
}

// mapError translates sentinel errors into standard HTTP status codes and error codes.
func mapError(err error) (int, string) {
	switch {
	case errors.Is(err, kagi.ErrEmailAlreadyExists):
		return fiber.StatusConflict, "email_already_exists"
	case errors.Is(err, kagi.ErrPasswordTooWeak):
		return fiber.StatusBadRequest, "password_too_weak"
	case errors.Is(err, kagi.ErrInvalidCredentials):
		return fiber.StatusUnauthorized, "invalid_credentials"
	case errors.Is(err, kagi.ErrRateLimitExceeded):
		return fiber.StatusTooManyRequests, "rate_limit_exceeded"
	case errors.Is(err, kagi.ErrSessionPending2FA):
		return fiber.StatusForbidden, "session_pending_2fa"
	case errors.Is(err, kagi.ErrInvalidSessionToken):
		return fiber.StatusUnauthorized, "invalid_session"
	case errors.Is(err, kagi.ErrSessionNotFound), errors.Is(err, kagi.ErrSessionExpired):
		return fiber.StatusUnauthorized, "session_not_found"
	default:
		return fiber.StatusInternalServerError, "internal_error"
	}
}
