package fiber_test

import (
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/kilip/kagi"
	pkgfiber "github.com/kilip/kagi/http/fiber"
)

func TestCookieConfig(t *testing.T) {
	cfg := pkgfiber.DefaultCookieConfig()

	if cfg.Name != "__Host-kagi_session" {
		t.Errorf("expected default cookie name __Host-kagi_session, got %s", cfg.Name)
	}
	if cfg.Path != "/" {
		t.Errorf("expected default path /, got %s", cfg.Path)
	}
	if cfg.Domain != "" {
		t.Errorf("expected default domain empty, got %s", cfg.Domain)
	}
	if !cfg.Secure {
		t.Errorf("expected default secure true, got false")
	}
	if !cfg.HTTPOnly {
		t.Errorf("expected default httponly true, got false")
	}
	if cfg.SameSite != fiber.CookieSameSiteLaxMode {
		t.Errorf("expected default sameSite Lax, got %s", cfg.SameSite)
	}
	if cfg.InsecureDevMode {
		t.Errorf("expected default insecureDevMode false, got true")
	}

	if cfg.CookieName() != "__Host-kagi_session" {
		t.Errorf("expected CookieName() to return __Host-kagi_session, got %s", cfg.CookieName())
	}

	devCfg := cfg
	devCfg.InsecureDevMode = true
	if devCfg.CookieName() != "kagi_session" {
		t.Errorf("expected dev mode CookieName() to return kagi_session, got %s", devCfg.CookieName())
	}
	if devCfg.IsSecure() {
		t.Errorf("expected dev mode IsSecure() to be false")
	}
}

func TestRegister(t *testing.T) {
	app := fiber.New()

	h := pkgfiber.Register(app, nil,
		pkgfiber.WithPrefix("/api/v1/auth"),
		pkgfiber.WithInsecureDevMode(true),
	)

	if h == nil {
		t.Fatal("expected handler to not be nil")
	}
	if h.Config().Prefix != "/api/v1/auth" {
		t.Errorf("expected prefix /api/v1/auth, got %s", h.Config().Prefix)
	}
	if !h.Config().Cookie.InsecureDevMode {
		t.Errorf("expected InsecureDevMode to be true")
	}
	if h.Config().Cookie.Secure {
		t.Errorf("expected Secure to be false when InsecureDevMode is enabled")
	}
	if h.Group() == nil {
		t.Errorf("expected group router to not be nil")
	}
	if h.Auth() != nil {
		t.Errorf("expected auth to be nil as passed")
	}
}

func TestRegisterDefault(t *testing.T) {
	app := fiber.New()
	var auth kagi.Kagi

	h := pkgfiber.Register(app, &auth)
	if h.Config().Prefix != "" {
		t.Errorf("expected default prefix empty, got %s", h.Config().Prefix)
	}
	if h.Group() != app {
		t.Errorf("expected group to be app when prefix is empty")
	}
	if h.Auth() != &auth {
		t.Errorf("expected auth to match")
	}
}
