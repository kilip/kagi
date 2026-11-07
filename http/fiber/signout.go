package fiber

import "github.com/gofiber/fiber/v2"

// SignOutResponse defines the response payload for a successful sign-out.
type SignOutResponse struct {
	Message string `json:"message"`
}

// SignOut revokes the active session and clears the session cookie.
//
//	@Summary		Sign out
//	@Description	Revokes the current session and clears the session cookie.
//	@Tags			Authentication
//	@Produce		json
//	@Success		200	{object}	SignOutResponse	"Successfully signed out"
//	@Failure		500	{object}	ErrorResponse	"Internal server error"
//	@Header			200	{string}	Set-Cookie		"kagi_session=; Path=/; Max-Age=-1; HttpOnly; Secure; SameSite=Lax"
//	@Router			/sign-out [post]
func (h *Handler) SignOut(c *fiber.Ctx) error {
	if h.auth == nil || h.auth.Sessions == nil {
		return writeError(c, fiber.StatusInternalServerError, "internal_error")
	}

	token := getSessionToken(c, h.cfg.Cookie)
	if token != "" {
		_ = h.auth.Sessions.SignOut(c.UserContext(), token)
	}

	clearSessionCookie(c, h.cfg.Cookie)

	return c.Status(fiber.StatusOK).JSON(SignOutResponse{
		Message: "signed out",
	})
}
