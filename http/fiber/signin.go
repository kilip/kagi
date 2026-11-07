package fiber

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kilip/kagi"
)

// SignInRequest defines the request payload for authenticating with email and password credentials.
type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse represents the response returned upon successful authentication.
type AuthResponse struct {
	User    *kagi.User    `json:"user"`
	Session *kagi.Session `json:"session"`
}

// SignIn authenticates a user with email and password credentials.
//
//	@Summary		Sign in with credentials
//	@Description	Authenticates user credentials and establishes a session delivered via HttpOnly cookie.
//	@Tags			Authentication
//	@Accept			json
//	@Produce		json
//	@Param			request	body		SignInRequest	true	"User credentials"
//	@Success		200		{object}	AuthResponse	"Successfully authenticated"
//	@Failure		400		{object}	ErrorResponse	"Invalid request payload"
//	@Failure		401		{object}	ErrorResponse	"Invalid credentials"
//	@Failure		429		{object}	ErrorResponse	"Rate limit exceeded"
//	@Failure		500		{object}	ErrorResponse	"Internal server error"
//	@Header			200		{string}	Set-Cookie		"kagi_session=...; Path=/; HttpOnly; Secure; SameSite=Lax"
//	@Router			/sign-in [post]
func (h *Handler) SignIn(c *fiber.Ctx) error {
	var req SignInRequest
	if err := c.BodyParser(&req); err != nil {
		return writeError(c, fiber.StatusBadRequest, "invalid_request")
	}

	if h.auth == nil || h.auth.Credentials == nil {
		return writeError(c, fiber.StatusInternalServerError, "internal_error")
	}

	result, err := h.auth.Credentials.SignIn(c.UserContext(), kagi.SignInInput{
		Email:     req.Email,
		Password:  req.Password,
		IPAddress: c.IP(),
		UserAgent: c.Get("User-Agent"),
	})
	if err != nil {
		status, code := mapError(err)
		return writeError(c, status, code)
	}

	if result.Session != nil && !result.Session.Pending2FA {
		setSessionCookie(c, h.cfg.Cookie, result.RawToken, result.Session.ExpiresAt)
	}

	return c.Status(fiber.StatusOK).JSON(AuthResponse{
		User:    result.User,
		Session: result.Session,
	})
}
