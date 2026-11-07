package fiber

import "github.com/gofiber/fiber/v2"

// CookieConfig configures session cookies issued by Kagi Fiber handlers.
type CookieConfig struct {
	Name            string
	Path            string
	Domain          string
	Secure          bool
	HTTPOnly        bool
	SameSite        string
	InsecureDevMode bool
}

// DefaultCookieConfig returns secure production-ready session cookie defaults (ADR-0003, ADR-0014, ADR-0015).
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Name:            "__Host-kagi_session",
		Path:            "/",
		Domain:          "",
		Secure:          true,
		HTTPOnly:        true,
		SameSite:        fiber.CookieSameSiteLaxMode,
		InsecureDevMode: false,
	}
}

// CookieName returns the effective cookie name.
// When InsecureDevMode is true, the "__Host-" prefix is omitted because browsers reject
// "__Host-" prefixed cookies sent over non-HTTPS connections.
func (c CookieConfig) CookieName() string {
	if c.InsecureDevMode {
		return "kagi_session"
	}
	return c.Name
}

// IsSecure returns whether the cookie should have the Secure attribute set.
// When InsecureDevMode is true, Secure is always false.
func (c CookieConfig) IsSecure() bool {
	if c.InsecureDevMode {
		return false
	}
	return c.Secure
}

// Config configures the Fiber HTTP mounting and handlers for Kagi.
type Config struct {
	Prefix string
	Cookie CookieConfig
}

// DefaultConfig returns default Fiber handler configuration.
func DefaultConfig() Config {
	return Config{
		Prefix: "",
		Cookie: DefaultCookieConfig(),
	}
}

// Option configures Kagi Fiber handler options.
type Option func(*Config)

// WithPrefix sets the URL prefix / router group under which Kagi endpoints are mounted.
func WithPrefix(prefix string) Option {
	return func(c *Config) {
		c.Prefix = prefix
	}
}

// WithCookieConfig sets custom session cookie configuration.
func WithCookieConfig(cfg CookieConfig) Option {
	return func(c *Config) {
		c.Cookie = cfg
	}
}

// WithInsecureDevMode enables or disables insecure development mode for session cookies.
// When enabled, session cookies omit the "__Host-" prefix and the Secure attribute.
func WithInsecureDevMode(enabled bool) Option {
	return func(c *Config) {
		c.Cookie.InsecureDevMode = enabled
		if enabled {
			c.Cookie.Secure = false
		}
	}
}
