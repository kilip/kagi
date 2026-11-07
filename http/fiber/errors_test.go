package fiber

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/kilip/kagi"
)

func TestMapError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "email already exists",
			err:        kagi.ErrEmailAlreadyExists,
			wantStatus: fiber.StatusConflict,
			wantCode:   "email_already_exists",
		},
		{
			name:       "wrapped email already exists",
			err:        fmt.Errorf("store error: %w", kagi.ErrEmailAlreadyExists),
			wantStatus: fiber.StatusConflict,
			wantCode:   "email_already_exists",
		},
		{
			name:       "password too weak",
			err:        kagi.ErrPasswordTooWeak,
			wantStatus: fiber.StatusBadRequest,
			wantCode:   "password_too_weak",
		},
		{
			name:       "invalid credentials",
			err:        kagi.ErrInvalidCredentials,
			wantStatus: fiber.StatusUnauthorized,
			wantCode:   "invalid_credentials",
		},
		{
			name:       "rate limit exceeded",
			err:        kagi.ErrRateLimitExceeded,
			wantStatus: fiber.StatusTooManyRequests,
			wantCode:   "rate_limit_exceeded",
		},
		{
			name:       "session pending 2fa",
			err:        kagi.ErrSessionPending2FA,
			wantStatus: fiber.StatusForbidden,
			wantCode:   "session_pending_2fa",
		},
		{
			name:       "invalid session token",
			err:        kagi.ErrInvalidSessionToken,
			wantStatus: fiber.StatusUnauthorized,
			wantCode:   "invalid_session",
		},
		{
			name:       "session not found",
			err:        kagi.ErrSessionNotFound,
			wantStatus: fiber.StatusUnauthorized,
			wantCode:   "session_not_found",
		},
		{
			name:       "session expired",
			err:        kagi.ErrSessionExpired,
			wantStatus: fiber.StatusUnauthorized,
			wantCode:   "session_not_found",
		},
		{
			name:       "unknown error defaults to 500 internal_error",
			err:        errors.New("something totally unexpected"),
			wantStatus: fiber.StatusInternalServerError,
			wantCode:   "internal_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, code := mapError(tt.err)
			if status != tt.wantStatus {
				t.Errorf("mapError() status = %d, want %d", status, tt.wantStatus)
			}
			if code != tt.wantCode {
				t.Errorf("mapError() code = %s, want %s", code, tt.wantCode)
			}
		})
	}
}
