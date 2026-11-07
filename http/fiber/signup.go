package fiber

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kilip/kagi"
)

// SignUpRequest defines the request payload for registering a new user with email and password credentials.
type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"`
}

// SignUp registers a new user with credentials.
//
//	@Summary		Register a new user
//	@Description	Registers a new user account with email and password credentials.
//	@Tags			Authentication
//	@Accept			json
//	@Produce		json
//	@Param			request	body		SignUpRequest	true	"Sign up credentials"
//	@Success		201		{object}	kagi.User		"User successfully registered"
//	@Failure		400		{object}	ErrorResponse	"Invalid request payload or weak password"
//	@Failure		409		{object}	ErrorResponse	"Email already registered"
//	@Failure		500		{object}	ErrorResponse	"Internal server error"
//	@Router			/sign-up [post]
func (h *Handler) SignUp(c *fiber.Ctx) error {
	var req SignUpRequest
	if err := c.BodyParser(&req); err != nil {
		return writeError(c, fiber.StatusBadRequest, "invalid_request")
	}

	if h.auth == nil || h.auth.Credentials == nil {
		return writeError(c, fiber.StatusInternalServerError, "internal_error")
	}

	user, err := h.auth.Credentials.SignUp(c.UserContext(), kagi.SignUpInput{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
	})
	if err != nil {
		status, code := mapError(err)
		return writeError(c, status, code)
	}

	return c.Status(fiber.StatusCreated).JSON(user)
}
