package fiber

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kilip/kagi"
)

// Handler handles Kagi authentication endpoints for Fiber.
type Handler struct {
	auth   *kagi.Kagi
	cfg    Config
	router fiber.Router
	group  fiber.Router
}

// Register mounts Kagi authentication endpoints on the provided Fiber router.
func Register(router fiber.Router, auth *kagi.Kagi, opts ...Option) *Handler {
	cfg := DefaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	// Ensure cookie secure flag reflects InsecureDevMode
	if cfg.Cookie.InsecureDevMode {
		cfg.Cookie.Secure = false
	}

	var group fiber.Router = router
	if cfg.Prefix != "" {
		group = router.Group(cfg.Prefix)
	}

	h := &Handler{
		auth:   auth,
		cfg:    cfg,
		router: router,
		group:  group,
	}
	h.registerRoutes()
	return h
}

// Config returns the handler configuration.
func (h *Handler) Config() Config {
	return h.cfg
}

// Auth returns the underlying Kagi coordinator.
func (h *Handler) Auth() *kagi.Kagi {
	return h.auth
}

// Group returns the mounted Fiber router group.
func (h *Handler) Group() fiber.Router {
	return h.group
}

func (h *Handler) registerRoutes() {
	h.group.Post("/sign-up", h.SignUp)
}
