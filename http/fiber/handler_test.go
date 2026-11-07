package fiber_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/kilip/kagi"
	"github.com/kilip/kagi/adapter/memory"
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

func fastPasswordConfig() kagi.PasswordConfig {
	return kagi.PasswordConfig{
		MinLength:   8,
		MaxLength:   72,
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func setupTestApp(t *testing.T, opts ...pkgfiber.Option) (*fiber.App, *kagi.Kagi) {
	t.Helper()
	stores := memory.New()
	auth, err := kagi.New(kagi.Config{
		UserStore:         stores.User,
		AccountStore:      stores.Account,
		SessionStore:      stores.Session,
		VerificationStore: stores.Verification,
		RateLimitStore:    stores.RateLimit,
		Secret:            "test-secret-at-least-32-bytes-long-123456",
		Password:          fastPasswordConfig(),
	})
	if err != nil {
		t.Fatalf("kagi.New failed: %v", err)
	}

	app := fiber.New()
	pkgfiber.Register(app, auth, opts...)
	return app, auth
}

func TestSignUp(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, auth *kagi.Kagi)
		payload    string
		wantStatus int
		checkBody  func(t *testing.T, body []byte)
	}{
		{
			name:       "happy path 201 created",
			payload:    `{"email":"newuser@example.com","password":"ValidPassword123!","name":"New User"}`,
			wantStatus: http.StatusCreated,
			checkBody: func(t *testing.T, body []byte) {
				var u kagi.User
				if err := json.Unmarshal(body, &u); err != nil {
					t.Fatalf("failed to parse response body as user: %v", err)
				}
				if u.Email != "newuser@example.com" {
					t.Errorf("expected email %q, got %q", "newuser@example.com", u.Email)
				}
				if u.Name != "New User" {
					t.Errorf("expected name %q, got %q", "New User", u.Name)
				}
				if u.ID == "" {
					t.Errorf("expected non-empty user ID")
				}
			},
		},
		{
			name: "duplicate email returns 409 conflict",
			setup: func(t *testing.T, auth *kagi.Kagi) {
				_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
					Email:    "existing@example.com",
					Password: "ValidPassword123!",
					Name:     "Existing User",
				})
				if err != nil {
					t.Fatalf("failed to pre-seed user: %v", err)
				}
			},
			payload:    `{"email":"existing@example.com","password":"ValidPassword123!","name":"Another User"}`,
			wantStatus: http.StatusConflict,
			checkBody: func(t *testing.T, body []byte) {
				var resp pkgfiber.ErrorResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to parse error response: %v", err)
				}
				if resp.Error != "email_already_exists" {
					t.Errorf("expected error %q, got %q", "email_already_exists", resp.Error)
				}
			},
		},
		{
			name:       "weak/short password returns 400 bad request",
			payload:    `{"email":"weakpass@example.com","password":"short"}`,
			wantStatus: http.StatusBadRequest,
			checkBody: func(t *testing.T, body []byte) {
				var resp pkgfiber.ErrorResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to parse error response: %v", err)
				}
				if resp.Error != "password_too_weak" {
					t.Errorf("expected error %q, got %q", "password_too_weak", resp.Error)
				}
			},
		},
		{
			name:       "malformed json body returns 400 bad request",
			payload:    `{"email": "broken"`,
			wantStatus: http.StatusBadRequest,
			checkBody: func(t *testing.T, body []byte) {
				var resp pkgfiber.ErrorResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to parse error response: %v", err)
				}
				if resp.Error != "invalid_request" {
					t.Errorf("expected error %q, got %q", "invalid_request", resp.Error)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, auth := setupTestApp(t)
			if tt.setup != nil {
				tt.setup(t, auth)
			}

			req := httptest.NewRequest(http.MethodPost, "/sign-up", bytes.NewBufferString(tt.payload))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("unexpected app.Test error: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			if tt.checkBody != nil {
				tt.checkBody(t, body)
			}
		})
	}
}

func TestSignUpWithPrefix(t *testing.T) {
	app, _ := setupTestApp(t, pkgfiber.WithPrefix("/auth"))

	payload := `{"email":"prefix@example.com","password":"ValidPassword123!","name":"Prefix User"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sign-up", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected app.Test error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}
}
