package fiber

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

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

// CSRFConfig configures Cross-Site Request Forgery (CSRF) protection for Kagi Fiber handlers (ADR-0015).
type CSRFConfig struct {
	SecretKey     []byte        // Master key used with HKDF to derive CSRF signing key
	CookieName    string        // Default: "__Host-kagi_csrf" ("kagi_csrf" if !Secure)
	HeaderName    string        // Default: "X-CSRF-Token"
	FormFieldName string        // Default: "_csrf"
	CookieMaxAge  time.Duration // Default: 24 * time.Hour
	Secure        bool          // Default: true (false only in non-TLS dev)
	Disabled      bool          // Allows disabling CSRF (useful for tests or non-browser clients)
}

// DefaultCSRFConfig returns secure production-ready CSRF defaults (ADR-0015).
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		SecretKey:     nil,
		CookieName:    "__Host-kagi_csrf",
		HeaderName:    "X-CSRF-Token",
		FormFieldName: "_csrf",
		CookieMaxAge:  24 * time.Hour,
		Secure:        true,
		Disabled:      false,
	}
}

// EffectiveCookieName returns the effective CSRF cookie name.
// When Secure is false (e.g. InsecureDevMode), the "__Host-" prefix is omitted
// because browsers reject "__Host-" prefixed cookies sent over non-HTTPS connections.
func (c CSRFConfig) EffectiveCookieName() string {
	name := c.CookieName
	if name == "" {
		name = "__Host-kagi_csrf"
	}
	if !c.IsSecure() && strings.HasPrefix(name, "__Host-") {
		return strings.TrimPrefix(name, "__Host-")
	}
	return name
}

// IsSecure returns whether the CSRF cookie should have the Secure attribute set.
func (c CSRFConfig) IsSecure() bool {
	return c.Secure
}

// Config configures the Fiber HTTP mounting and handlers for Kagi.
type Config struct {
	Prefix string
	Cookie CookieConfig
	CSRF   CSRFConfig
}

// DefaultConfig returns default Fiber handler configuration.
func DefaultConfig() Config {
	return Config{
		Prefix: "",
		Cookie: DefaultCookieConfig(),
		CSRF:   DefaultCSRFConfig(),
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
		c.CSRF.Secure = !enabled
	}
}

// WithCSRFConfig sets custom CSRF configuration.
func WithCSRFConfig(cfg CSRFConfig) Option {
	return func(c *Config) {
		c.CSRF = cfg
	}
}

// WithCSRFDisabled enables or disables CSRF protection.
func WithCSRFDisabled(disabled bool) Option {
	return func(c *Config) {
		c.CSRF.Disabled = disabled
	}
}
