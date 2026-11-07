package fiber_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	app, auth, _ := setupTestAppWithStores(t, nil, opts...)
	return app, auth
}

func setupTestAppWithStores(t *testing.T, kagiConfigFn func(*kagi.Config), opts ...pkgfiber.Option) (*fiber.App, *kagi.Kagi, *memory.Stores) {
	t.Helper()
	stores := memory.New()
	cfg := kagi.Config{
		UserStore:         stores.User,
		AccountStore:      stores.Account,
		SessionStore:      stores.Session,
		VerificationStore: stores.Verification,
		RateLimitStore:    stores.RateLimit,
		Secret:            "test-secret-at-least-32-bytes-long-123456",
		Password:          fastPasswordConfig(),
	}
	if kagiConfigFn != nil {
		kagiConfigFn(&cfg)
	}
	auth, err := kagi.New(cfg)
	if err != nil {
		t.Fatalf("kagi.New failed: %v", err)
	}

	app := fiber.New()
	pkgfiber.Register(app, auth, opts...)
	return app, auth, stores
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

func TestSignIn(t *testing.T) {
	t.Run("happy path 200 with session cookie assertion", func(t *testing.T) {
		app, auth := setupTestApp(t)

		_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
			Email:    "signin@example.com",
			Password: "ValidPassword123!",
		})
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		payload := `{"email":"signin@example.com","password":"ValidPassword123!"}`
		req := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected app.Test error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var authResp pkgfiber.AuthResponse
		if err := json.Unmarshal(body, &authResp); err != nil {
			t.Fatalf("failed to unmarshal AuthResponse: %v", err)
		}

		if authResp.User == nil || authResp.User.Email != "signin@example.com" {
			t.Errorf("expected user email signin@example.com, got %v", authResp.User)
		}
		if authResp.Session == nil {
			t.Fatalf("expected non-nil session in response")
		}

		// Verify token_hash is masked from JSON
		if strings.Contains(string(body), "token_hash") {
			t.Errorf("expected token_hash to be masked from JSON response, but it was found in body: %s", string(body))
		}

		// Assert cookie attributes
		var sessionCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "__Host-kagi_session" {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Fatalf("expected __Host-kagi_session cookie to be set")
		}

		if !sessionCookie.HttpOnly {
			t.Errorf("expected cookie HttpOnly to be true")
		}
		if !sessionCookie.Secure {
			t.Errorf("expected cookie Secure to be true")
		}
		if sessionCookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("expected cookie SameSite to be Lax, got %v", sessionCookie.SameSite)
		}
		if len(sessionCookie.Value) != 43 {
			t.Errorf("expected raw token length 43, got %d (%s)", len(sessionCookie.Value), sessionCookie.Value)
		}

		// Check raw Set-Cookie header string
		setCookieHeader := resp.Header.Get("Set-Cookie")
		if !strings.Contains(setCookieHeader, "HttpOnly") {
			t.Errorf("expected Set-Cookie to contain HttpOnly, got: %s", setCookieHeader)
		}
		if !strings.Contains(strings.ToLower(setCookieHeader), "secure") {
			t.Errorf("expected Set-Cookie to contain Secure, got: %s", setCookieHeader)
		}
		if !strings.Contains(setCookieHeader, "SameSite=Lax") {
			t.Errorf("expected Set-Cookie to contain SameSite=Lax, got: %s", setCookieHeader)
		}

		// Ensure rawToken was NOT leaked in JSON response body
		if strings.Contains(string(body), sessionCookie.Value) {
			t.Errorf("raw session token leaked in response body: %s", string(body))
		}
	})

	t.Run("wrong password returns 401 invalid_credentials", func(t *testing.T) {
		app, auth := setupTestApp(t)

		_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
			Email:    "wrongpw@example.com",
			Password: "ValidPassword123!",
		})
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		payload := `{"email":"wrongpw@example.com","password":"IncorrectPassword123!"}`
		req := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected app.Test error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var errResp pkgfiber.ErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			t.Fatalf("failed to unmarshal ErrorResponse: %v", err)
		}
		if errResp.Error != "invalid_credentials" {
			t.Errorf("expected error 'invalid_credentials', got %q", errResp.Error)
		}

		for _, c := range resp.Cookies() {
			if c.Name == "__Host-kagi_session" {
				t.Errorf("unexpected session cookie on failed sign in")
			}
		}
	})

	t.Run("non-existent user returns 401 invalid_credentials", func(t *testing.T) {
		app, _ := setupTestApp(t)

		payload := `{"email":"nonexistent@example.com","password":"ValidPassword123!"}`
		req := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected app.Test error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var errResp pkgfiber.ErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			t.Fatalf("failed to unmarshal ErrorResponse: %v", err)
		}
		if errResp.Error != "invalid_credentials" {
			t.Errorf("expected error 'invalid_credentials', got %q", errResp.Error)
		}
	})

	t.Run("malformed body returns 400 invalid_request", func(t *testing.T) {
		app, _ := setupTestApp(t)

		req := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString("{invalid-json"))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected app.Test error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var errResp pkgfiber.ErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			t.Fatalf("failed to unmarshal ErrorResponse: %v", err)
		}
		if errResp.Error != "invalid_request" {
			t.Errorf("expected error 'invalid_request', got %q", errResp.Error)
		}
	})

	t.Run("rate limit exceeded returns 429 rate_limit_exceeded", func(t *testing.T) {
		app, auth, _ := setupTestAppWithStores(t, func(cfg *kagi.Config) {
			cfg.RateLimit = kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{Limit: 2, Window: 15 * time.Minute},
				SignInIP:    kagi.LimitRule{Limit: 10, Window: 15 * time.Minute},
			}
		})

		_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
			Email:    "ratelimit@example.com",
			Password: "ValidPassword123!",
		})
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		payload := `{"email":"ratelimit@example.com","password":"WrongPassword123!"}`

		// Attempt 1: 401
		req1 := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(payload))
		req1.Header.Set("Content-Type", "application/json")
		resp1, err := app.Test(req1)
		if err != nil {
			t.Fatalf("unexpected error on attempt 1: %v", err)
		}
		resp1.Body.Close()
		if resp1.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected attempt 1 status 401, got %d", resp1.StatusCode)
		}

		// Attempt 2: 401
		req2 := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(payload))
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := app.Test(req2)
		if err != nil {
			t.Fatalf("unexpected error on attempt 2: %v", err)
		}
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected attempt 2 status 401, got %d", resp2.StatusCode)
		}

		// Attempt 3: 429 Rate Limit Exceeded
		req3 := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(payload))
		req3.Header.Set("Content-Type", "application/json")
		resp3, err := app.Test(req3)
		if err != nil {
			t.Fatalf("unexpected error on attempt 3: %v", err)
		}
		defer resp3.Body.Close()

		if resp3.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("expected attempt 3 status %d, got %d", http.StatusTooManyRequests, resp3.StatusCode)
		}

		body, err := io.ReadAll(resp3.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var errResp pkgfiber.ErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			t.Fatalf("failed to unmarshal ErrorResponse: %v", err)
		}
		if errResp.Error != "rate_limit_exceeded" {
			t.Errorf("expected error 'rate_limit_exceeded', got %q", errResp.Error)
		}
	})
}

func TestSignOut(t *testing.T) {
	t.Run("happy path revokes session in store and clears cookie", func(t *testing.T) {
		app, auth := setupTestApp(t)

		_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
			Email:    "signout@example.com",
			Password: "ValidPassword123!",
		})
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		signInPayload := `{"email":"signout@example.com","password":"ValidPassword123!"}`
		signInReq := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(signInPayload))
		signInReq.Header.Set("Content-Type", "application/json")

		signInResp, err := app.Test(signInReq)
		if err != nil {
			t.Fatalf("sign in failed: %v", err)
		}
		defer signInResp.Body.Close()

		var rawToken string
		for _, c := range signInResp.Cookies() {
			if c.Name == "__Host-kagi_session" {
				rawToken = c.Value
				break
			}
		}
		if rawToken == "" {
			t.Fatalf("failed to obtain session token from sign in cookie")
		}

		session, _, err := auth.Sessions.Validate(context.Background(), rawToken)
		if err != nil || session == nil {
			t.Fatalf("expected valid session before sign out, err: %v", err)
		}

		signOutReq := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
		signOutReq.AddCookie(&http.Cookie{
			Name:  "__Host-kagi_session",
			Value: rawToken,
		})

		signOutResp, err := app.Test(signOutReq)
		if err != nil {
			t.Fatalf("unexpected app.Test error on sign out: %v", err)
		}
		defer signOutResp.Body.Close()

		if signOutResp.StatusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, signOutResp.StatusCode)
		}

		body, err := io.ReadAll(signOutResp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var respData pkgfiber.SignOutResponse
		if err := json.Unmarshal(body, &respData); err != nil {
			t.Fatalf("failed to unmarshal SignOutResponse: %v", err)
		}
		if respData.Message != "signed out" {
			t.Errorf("expected message 'signed out', got %q", respData.Message)
		}

		setCookieHeader := signOutResp.Header.Get("Set-Cookie")
		if !strings.Contains(strings.ToLower(setCookieHeader), "expires=") && !strings.Contains(strings.ToLower(setCookieHeader), "max-age") {
			t.Errorf("expected Set-Cookie to contain expires or max-age, got: %s", setCookieHeader)
		}

		var clearedCookie *http.Cookie
		for _, c := range signOutResp.Cookies() {
			if c.Name == "__Host-kagi_session" {
				clearedCookie = c
				break
			}
		}
		if clearedCookie == nil {
			t.Fatalf("expected cleared cookie __Host-kagi_session in response")
		}
		if clearedCookie.Value != "" {
			t.Errorf("expected cleared cookie value to be empty, got %q", clearedCookie.Value)
		}
		if !clearedCookie.Expires.Before(time.Now()) {
			t.Errorf("expected cleared cookie to have past expiration, got %v", clearedCookie.Expires)
		}

		_, _, err = auth.Sessions.Validate(context.Background(), rawToken)
		if err == nil {
			t.Errorf("expected session to be revoked in store, but Validate succeeded")
		}
	})

	t.Run("idempotent sign out with absent cookie returns 200 and clears cookie", func(t *testing.T) {
		app, _ := setupTestApp(t)

		req := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected app.Test error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		var respData pkgfiber.SignOutResponse
		if err := json.Unmarshal(body, &respData); err != nil {
			t.Fatalf("failed to unmarshal SignOutResponse: %v", err)
		}
		if respData.Message != "signed out" {
			t.Errorf("expected message 'signed out', got %q", respData.Message)
		}

		setCookieHeader := resp.Header.Get("Set-Cookie")
		if !strings.Contains(strings.ToLower(setCookieHeader), "expires=") && !strings.Contains(strings.ToLower(setCookieHeader), "max-age") {
			t.Errorf("expected Set-Cookie to contain expires or max-age, got: %s", setCookieHeader)
		}
	})

	t.Run("sign out with expired or invalid token cookie returns 200 and clears cookie", func(t *testing.T) {
		app, _ := setupTestApp(t)

		req := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-kagi_session",
			Value: "invalid-or-nonexistent-token",
		})

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected app.Test error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}

		setCookieHeader := resp.Header.Get("Set-Cookie")
		if !strings.Contains(strings.ToLower(setCookieHeader), "expires=") && !strings.Contains(strings.ToLower(setCookieHeader), "max-age") {
			t.Errorf("expected Set-Cookie to contain expires or max-age, got: %s", setCookieHeader)
		}
	})
}

func TestInsecureDevMode(t *testing.T) {
	app, auth := setupTestApp(t, pkgfiber.WithInsecureDevMode(true))

	_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "devmode@example.com",
		Password: "ValidPassword123!",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	payload := `{"email":"devmode@example.com","password":"ValidPassword123!"}`
	req := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected app.Test error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	var devCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "kagi_session" {
			devCookie = c
			break
		}
		if c.Name == "__Host-kagi_session" {
			t.Errorf("unexpected __Host- prefix in insecure dev mode")
		}
	}

	if devCookie == nil {
		t.Fatalf("expected cookie named 'kagi_session' in insecure dev mode")
	}
	if devCookie.Secure {
		t.Errorf("expected cookie Secure to be false in insecure dev mode")
	}

	rawSetCookie := resp.Header.Get("Set-Cookie")
	if strings.Contains(rawSetCookie, "Secure") {
		t.Errorf("expected Set-Cookie not to contain Secure in dev mode, got: %s", rawSetCookie)
	}
}

func TestInsecureDevModeCookie(t *testing.T) {
	TestInsecureDevMode(t)
}
