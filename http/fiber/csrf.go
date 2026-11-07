package fiber

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/kilip/kagi"
	"github.com/kilip/kagi/internal/crypto"
)

// CSRFResponse represents the JSON response containing the masked CSRF token.
type CSRFResponse struct {
	CSRFToken string `json:"csrf_token"`
}

// CSRFMiddlewareConfig configures the CSRF protection middleware.
type CSRFMiddlewareConfig struct {
	Filter       func(*fiber.Ctx) bool
	ErrorHandler func(*fiber.Ctx, error) error
}

// CSRFOption applies configuration to CSRFMiddlewareConfig.
type CSRFOption func(*CSRFMiddlewareConfig)

// WithCSRFFilter specifies a filter function to bypass CSRF validation for matching requests.
func WithCSRFFilter(filter func(*fiber.Ctx) bool) CSRFOption {
	return func(c *CSRFMiddlewareConfig) {
		c.Filter = filter
	}
}

// WithCSRFErrorHandler specifies a custom error handler for CSRF validation errors.
func WithCSRFErrorHandler(handler func(*fiber.Ctx, error) error) CSRFOption {
	return func(c *CSRFMiddlewareConfig) {
		c.ErrorHandler = handler
	}
}

// CSRFToken returns a masked CSRF token and sets the CSRF cookie if not present or invalid.
//
//	@Summary		Get CSRF token
//	@Description	Returns a masked CSRF token and sets the CSRF cookie if not present or invalid.
//	@Tags			Authentication
//	@Produce		json
//	@Success		200	{object}	CSRFResponse	"Masked CSRF token"
//	@Failure		500	{object}	ErrorResponse	"Internal server error"
//	@Header			200	{string}	Set-Cookie		"__Host-kagi_csrf=...; Path=/; HttpOnly; Secure; SameSite=Lax"
//	@Router			/csrf [get]
func (h *Handler) CSRFToken(c *fiber.Ctx) error {
	if len(h.csrfKey) == 0 {
		return writeError(c, fiber.StatusInternalServerError, "internal_error")
	}

	var rawToken []byte
	cookieVal := getCSRFCookie(c, h.cfg.CSRF)
	if cookieVal != "" {
		if raw, err := crypto.ValidateCSRFCookie(cookieVal, h.csrfKey); err == nil && len(raw) == crypto.CSRFTokenBytes {
			rawToken = raw
		}
	}

	if rawToken == nil {
		raw, newCookieVal, err := crypto.CreateCSRFCookie(h.csrfKey)
		if err != nil {
			return writeError(c, fiber.StatusInternalServerError, "internal_error")
		}
		rawToken = raw
		setCSRFCookie(c, h.cfg.CSRF, newCookieVal)
	}

	maskedToken, err := crypto.MaskCSRFToken(rawToken)
	if err != nil {
		return writeError(c, fiber.StatusInternalServerError, "internal_error")
	}

	return c.Status(fiber.StatusOK).JSON(CSRFResponse{
		CSRFToken: maskedToken,
	})
}

// rotateCSRFCookie rotates the CSRF cookie on authentication boundaries (e.g. sign-in, sign-up, sign-out).
func (h *Handler) rotateCSRFCookie(c *fiber.Ctx) {
	if h.cfg.CSRF.Disabled || len(h.csrfKey) == 0 {
		return
	}
	_, cookieVal, err := crypto.CreateCSRFCookie(h.csrfKey)
	if err != nil {
		return
	}
	setCSRFCookie(c, h.cfg.CSRF, cookieVal)
}

func mapCryptoCSRFError(err error) error {
	switch {
	case errors.Is(err, crypto.ErrCSRFTokenMissing):
		return kagi.ErrCSRFTokenMissing
	case errors.Is(err, crypto.ErrCSRFTokenInvalid):
		return kagi.ErrCSRFTokenInvalid
	case errors.Is(err, crypto.ErrCSRFTokenMismatch):
		return kagi.ErrCSRFTokenMismatch
	default:
		return err
	}
}

func createCSRFMiddleware(csrfKey []byte, cfg CSRFConfig, midCfg CSRFMiddlewareConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if cfg.Disabled {
			return c.Next()
		}

		switch c.Method() {
		case fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions, fiber.MethodTrace:
			return c.Next()
		}

		if midCfg.Filter != nil && midCfg.Filter(c) {
			return c.Next()
		}

		cookieVal := getCSRFCookie(c, cfg)
		if cookieVal == "" {
			if midCfg.ErrorHandler != nil {
				return midCfg.ErrorHandler(c, kagi.ErrCSRFTokenMissing)
			}
			return writeError(c, fiber.StatusForbidden, "csrf_token_missing")
		}

		headerName := cfg.HeaderName
		if headerName == "" {
			headerName = "X-CSRF-Token"
		}
		formFieldName := cfg.FormFieldName
		if formFieldName == "" {
			formFieldName = "_csrf"
		}

		clientToken := c.Get(headerName)
		if clientToken == "" {
			clientToken = c.Get("X-Kagi-CSRF-Token")
		}
		if clientToken == "" {
			clientToken = c.FormValue(formFieldName)
		}

		if clientToken == "" {
			if midCfg.ErrorHandler != nil {
				return midCfg.ErrorHandler(c, kagi.ErrCSRFTokenMissing)
			}
			return writeError(c, fiber.StatusForbidden, "csrf_token_missing")
		}

		if err := crypto.ValidateCSRF(cookieVal, clientToken, csrfKey); err != nil {
			mappedErr := mapCryptoCSRFError(err)
			if midCfg.ErrorHandler != nil {
				return midCfg.ErrorHandler(c, mappedErr)
			}
			status, code := mapError(mappedErr)
			return writeError(c, status, code)
		}

		return c.Next()
	}
}

// CSRF returns a Fiber middleware enforcing CSRF token validation on mutating requests.
func (h *Handler) CSRF(opts ...CSRFOption) fiber.Handler {
	var midCfg CSRFMiddlewareConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&midCfg)
		}
	}
	return createCSRFMiddleware(h.csrfKey, h.cfg.CSRF, midCfg)
}

// NewCSRF creates a standalone Fiber middleware enforcing CSRF token validation on mutating requests.
func NewCSRF(auth *kagi.Kagi, cfg Config, opts ...CSRFOption) fiber.Handler {
	var midCfg CSRFMiddlewareConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&midCfg)
		}
	}

	var csrfKey []byte
	if !cfg.CSRF.Disabled {
		masterSecret := cfg.CSRF.SecretKey
		if len(masterSecret) == 0 && auth != nil {
			masterSecret = []byte(auth.Secret())
		}
		if len(masterSecret) >= 32 {
			if derived, err := crypto.DeriveCSRFKey(masterSecret); err == nil {
				csrfKey = derived
			}
		}
	}

	return createCSRFMiddleware(csrfKey, cfg.CSRF, midCfg)
}
