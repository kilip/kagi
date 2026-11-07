package fiber

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/kilip/kagi"
)

type contextKey int

const (
	sessionCtxKey contextKey = iota
	userIDCtxKey
	userCtxKey
)

const (
	// LocalsSessionKey is the Fiber locals key for storing the *kagi.Session.
	LocalsSessionKey = "kagi_session"
	// LocalsUserIDKey is the Fiber locals key for storing the user ID string.
	LocalsUserIDKey = "kagi_user_id"
	// LocalsUserKey is the Fiber locals key for storing the *kagi.User.
	LocalsUserKey = "kagi_user"
)

// MiddlewareConfig configures the session middleware.
type MiddlewareConfig struct {
	Optional     bool
	FetchUser    bool
	ErrorHandler func(*fiber.Ctx, error) error
	Filter       func(*fiber.Ctx) bool
	Cookie       CookieConfig
}

// MiddlewareOption applies configuration to MiddlewareConfig.
type MiddlewareOption func(*MiddlewareConfig)

// WithMiddlewareOptional sets whether the session is optional.
func WithMiddlewareOptional(optional bool) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.Optional = optional
	}
}

// WithMiddlewareFetchUser sets whether to fetch the user entity from UserStore.
func WithMiddlewareFetchUser(fetchUser bool) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.FetchUser = fetchUser
	}
}

// WithMiddlewareErrorHandler sets a custom error handler callback.
func WithMiddlewareErrorHandler(fn func(*fiber.Ctx, error) error) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.ErrorHandler = fn
	}
}

// WithMiddlewareFilter sets a filter callback that bypasses middleware when returning true.
func WithMiddlewareFilter(fn func(*fiber.Ctx) bool) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.Filter = fn
	}
}

// WithMiddlewareCookie sets the cookie configuration used to extract and re-issue session cookies.
func WithMiddlewareCookie(cfg CookieConfig) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.Cookie = cfg
	}
}

// SessionFromCtx retrieves the authenticated *kagi.Session from Fiber locals or request context.
func SessionFromCtx(c *fiber.Ctx) *kagi.Session {
	if c == nil {
		return nil
	}
	if sess, ok := c.Locals(LocalsSessionKey).(*kagi.Session); ok && sess != nil {
		return sess
	}
	return SessionFromContext(c.UserContext())
}

// SessionFromContext retrieves the authenticated *kagi.Session from a standard context.Context.
func SessionFromContext(ctx context.Context) *kagi.Session {
	if ctx == nil {
		return nil
	}
	if sess, ok := ctx.Value(sessionCtxKey).(*kagi.Session); ok && sess != nil {
		return sess
	}
	return nil
}

// UserIDFromCtx retrieves the authenticated user ID string from Fiber locals, request context, or session.
func UserIDFromCtx(c *fiber.Ctx) string {
	if c == nil {
		return ""
	}
	if id, ok := c.Locals(LocalsUserIDKey).(string); ok && id != "" {
		return id
	}
	if id := UserIDFromContext(c.UserContext()); id != "" {
		return id
	}
	if sess := SessionFromCtx(c); sess != nil {
		return sess.UserID
	}
	return ""
}

// UserIDFromContext retrieves the authenticated user ID string from a standard context.Context or session in context.
func UserIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(userIDCtxKey).(string); ok && id != "" {
		return id
	}
	if sess := SessionFromContext(ctx); sess != nil {
		return sess.UserID
	}
	return ""
}

// UserFromCtx retrieves the authenticated *kagi.User entity from Fiber locals or request context.
func UserFromCtx(c *fiber.Ctx) *kagi.User {
	if c == nil {
		return nil
	}
	if user, ok := c.Locals(LocalsUserKey).(*kagi.User); ok && user != nil {
		return user
	}
	return UserFromContext(c.UserContext())
}

// UserFromContext retrieves the authenticated *kagi.User entity from a standard context.Context.
func UserFromContext(ctx context.Context) *kagi.User {
	if ctx == nil {
		return nil
	}
	if user, ok := ctx.Value(userCtxKey).(*kagi.User); ok && user != nil {
		return user
	}
	return nil
}

// RequireAuth returns a Fiber middleware enforcing authentication.
func (h *Handler) RequireAuth(opts ...MiddlewareOption) fiber.Handler {
	var (
		auth *kagi.Kagi
		cfg  Config
	)
	if h != nil {
		auth = h.auth
		cfg = h.cfg
	}
	return NewRequireAuth(auth, cfg, opts...)
}

// Session returns a Fiber middleware providing optional session extraction and validation.
func (h *Handler) Session(opts ...MiddlewareOption) fiber.Handler {
	var (
		auth *kagi.Kagi
		cfg  Config
	)
	if h != nil {
		auth = h.auth
		cfg = h.cfg
	}
	return NewSessionMiddleware(auth, cfg, opts...)
}

// NewRequireAuth creates a Fiber middleware requiring authentication.
func NewRequireAuth(auth *kagi.Kagi, cfg Config, opts ...MiddlewareOption) fiber.Handler {
	midCfg := newMiddlewareConfig(cfg, false, opts...)
	return createMiddleware(auth, midCfg)
}

// NewSessionMiddleware creates a Fiber middleware that extracts and validates sessions optionally.
func NewSessionMiddleware(auth *kagi.Kagi, cfg Config, opts ...MiddlewareOption) fiber.Handler {
	midCfg := newMiddlewareConfig(cfg, true, opts...)
	return createMiddleware(auth, midCfg)
}

func newMiddlewareConfig(cfg Config, defaultOptional bool, opts ...MiddlewareOption) MiddlewareConfig {
	cookieCfg := cfg.Cookie
	if cookieCfg.Name == "" && !cookieCfg.InsecureDevMode {
		cookieCfg = DefaultCookieConfig()
	}
	if cookieCfg.InsecureDevMode {
		cookieCfg.Secure = false
	}

	midCfg := MiddlewareConfig{
		Optional: defaultOptional,
		Cookie:   cookieCfg,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(&midCfg)
		}
	}

	if midCfg.Cookie.Name == "" && !midCfg.Cookie.InsecureDevMode {
		midCfg.Cookie.Name = "__Host-kagi_session"
	}
	if midCfg.Cookie.Path == "" {
		midCfg.Cookie.Path = "/"
	}
	if midCfg.Cookie.InsecureDevMode {
		midCfg.Cookie.Secure = false
	}

	return midCfg
}

func createMiddleware(auth *kagi.Kagi, cfg MiddlewareConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. If cfg.Filter != nil && cfg.Filter(c): call c.Next().
		if cfg.Filter != nil && cfg.Filter(c) {
			return c.Next()
		}

		// 2. Read cookie token via getSessionToken(c, cfg.Cookie).
		token := getSessionToken(c, cfg.Cookie)

		// 3. If token is empty:
		if token == "" {
			if cfg.Optional {
				return c.Next()
			}
			if cfg.ErrorHandler != nil {
				return cfg.ErrorHandler(c, kagi.ErrSessionNotFound)
			}
			return writeError(c, fiber.StatusUnauthorized, "session_not_found")
		}

		// 4. If len(token) != 43:
		if len(token) != 43 {
			if cfg.Optional {
				return c.Next()
			}
			if cfg.ErrorHandler != nil {
				return cfg.ErrorHandler(c, kagi.ErrInvalidSessionToken)
			}
			return writeError(c, fiber.StatusUnauthorized, "invalid_session")
		}

		// 5. Call auth.Sessions.Validate(c.UserContext(), token).
		if auth == nil || auth.Sessions == nil {
			if cfg.Optional {
				return c.Next()
			}
			if cfg.ErrorHandler != nil {
				return cfg.ErrorHandler(c, errors.New("uninitialized auth service"))
			}
			return writeError(c, fiber.StatusInternalServerError, "internal_error")
		}

		sess, renewed, err := auth.Sessions.Validate(c.UserContext(), token)

		// 6. If err != nil:
		if err != nil {
			if errors.Is(err, kagi.ErrSessionPending2FA) {
				if cfg.ErrorHandler != nil {
					return cfg.ErrorHandler(c, err)
				}
				return writeError(c, fiber.StatusForbidden, "session_pending_2fa")
			}
			if cfg.Optional {
				return c.Next()
			}
			if cfg.ErrorHandler != nil {
				return cfg.ErrorHandler(c, err)
			}
			if errors.Is(err, kagi.ErrSessionNotFound) || errors.Is(err, kagi.ErrSessionExpired) || errors.Is(err, kagi.ErrInvalidSessionToken) {
				status, code := mapError(err)
				return writeError(c, status, code)
			}
			return writeError(c, fiber.StatusInternalServerError, "internal_error")
		}

		// 7. If renewed == true:
		if renewed && sess != nil {
			setSessionCookie(c, cfg.Cookie, token, sess.ExpiresAt)
		}

		// 8. Context population:
		ctx := c.UserContext()
		if ctx == nil {
			ctx = context.Background()
		}
		ctx = context.WithValue(ctx, sessionCtxKey, sess)
		ctx = context.WithValue(ctx, userIDCtxKey, sess.UserID)
		c.Locals(LocalsSessionKey, sess)
		c.Locals(LocalsUserIDKey, sess.UserID)

		if cfg.FetchUser && auth != nil && auth.UserStore() != nil {
			user, userErr := auth.UserStore().GetByID(ctx, sess.UserID)
			if userErr == nil && user != nil {
				ctx = context.WithValue(ctx, userCtxKey, user)
				c.Locals(LocalsUserKey, user)
			}
		}

		c.SetUserContext(ctx)
		return c.Next()
	}
}
