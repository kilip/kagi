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
	"github.com/kilip/kagi/internal/clock"
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

func setupTestAppWithClock(t *testing.T, kagiConfigFn func(*kagi.Config), opts ...pkgfiber.Option) (*fiber.App, *kagi.Kagi, *memory.Stores, *clock.FakeClock) {
	t.Helper()
	opts = append([]pkgfiber.Option{pkgfiber.WithCSRFDisabled(true)}, opts...)
	fakeClk := clock.NewFake(time.Now().UTC())
	stores := memory.New(memory.WithClock(fakeClk))
	cfg := kagi.Config{
		UserStore:         stores.User,
		AccountStore:      stores.Account,
		SessionStore:      stores.Session,
		VerificationStore: stores.Verification,
		RateLimitStore:    stores.RateLimit,
		Secret:            "test-secret-at-least-32-bytes-long-123456",
		Password:          fastPasswordConfig(),
		Clock:             fakeClk,
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
	return app, auth, stores, fakeClk
}

func setupTestAppWithStores(t *testing.T, kagiConfigFn func(*kagi.Config), opts ...pkgfiber.Option) (*fiber.App, *kagi.Kagi, *memory.Stores) {
	t.Helper()
	app, auth, stores, _ := setupTestAppWithClock(t, kagiConfigFn, opts...)
	return app, auth, stores
}

func setupTestApp(t *testing.T, opts ...pkgfiber.Option) (*fiber.App, *kagi.Kagi) {
	t.Helper()
	app, auth, _ := setupTestAppWithStores(t, nil, opts...)
	return app, auth
}

// TestAuthLifecycle verifies the complete auth lifecycle flow:
// Sign up -> Sign in -> Extract session cookie -> Verify session in store -> Sign out -> Verify cookie expired and session deleted in store -> Second sign out (idempotent).
func TestAuthLifecycle(t *testing.T) {
	app, auth, stores, fakeClk := setupTestAppWithClock(t, nil)

	// Step 1: Sign up a new user -> 201 Created
	signUpPayload := `{"email":"lifecycle@example.com","password":"ValidPassword123!","name":"Lifecycle User"}`
	signUpReq := httptest.NewRequest(http.MethodPost, "/sign-up", bytes.NewBufferString(signUpPayload))
	signUpReq.Header.Set("Content-Type", "application/json")

	signUpResp, err := app.Test(signUpReq)
	if err != nil {
		t.Fatalf("sign up request failed: %v", err)
	}
	defer signUpResp.Body.Close()

	if signUpResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected sign up status %d, got %d", http.StatusCreated, signUpResp.StatusCode)
	}

	var createdUser kagi.User
	if err := json.NewDecoder(signUpResp.Body).Decode(&createdUser); err != nil {
		t.Fatalf("failed to decode sign up response: %v", err)
	}
	if createdUser.Email != "lifecycle@example.com" {
		t.Errorf("expected user email 'lifecycle@example.com', got %q", createdUser.Email)
	}
	if createdUser.Name != "Lifecycle User" {
		t.Errorf("expected user name 'Lifecycle User', got %q", createdUser.Name)
	}
	if createdUser.ID == "" {
		t.Fatalf("expected non-empty user ID")
	}

	// Verify user exists in UserStore
	storedUser, err := stores.User.GetByEmail(context.Background(), "lifecycle@example.com")
	if err != nil || storedUser == nil {
		t.Fatalf("expected user to exist in store: %v", err)
	}
	if storedUser.ID != createdUser.ID {
		t.Errorf("stored user ID %s != created user ID %s", storedUser.ID, createdUser.ID)
	}

	// Step 2: Sign in -> 200 OK + Set-Cookie
	signInPayload := `{"email":"lifecycle@example.com","password":"ValidPassword123!"}`
	signInReq := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(signInPayload))
	signInReq.Header.Set("Content-Type", "application/json")

	signInResp, err := app.Test(signInReq)
	if err != nil {
		t.Fatalf("sign in request failed: %v", err)
	}
	defer signInResp.Body.Close()

	if signInResp.StatusCode != http.StatusOK {
		t.Fatalf("expected sign in status %d, got %d", http.StatusOK, signInResp.StatusCode)
	}

	signInBody, err := io.ReadAll(signInResp.Body)
	if err != nil {
		t.Fatalf("failed to read sign in body: %v", err)
	}

	var authResp pkgfiber.AuthResponse
	if err := json.Unmarshal(signInBody, &authResp); err != nil {
		t.Fatalf("failed to decode auth response: %v", err)
	}
	if authResp.User == nil || authResp.User.ID != createdUser.ID {
		t.Errorf("expected user ID %s in auth response, got %v", createdUser.ID, authResp.User)
	}
	if authResp.Session == nil {
		t.Fatalf("expected non-nil session in auth response")
	}

	// Verify token_hash is masked from JSON response
	if strings.Contains(string(signInBody), "token_hash") {
		t.Errorf("token_hash leaked in response body: %s", string(signInBody))
	}

	// Step 3: Extract session cookie and verify security attributes
	var sessionCookie *http.Cookie
	for _, c := range signInResp.Cookies() {
		if c.Name == "__Host-kagi_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected __Host-kagi_session cookie to be present")
	}
	if !sessionCookie.HttpOnly {
		t.Errorf("expected session cookie HttpOnly to be true")
	}
	if !sessionCookie.Secure {
		t.Errorf("expected session cookie Secure to be true")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected session cookie SameSite to be Lax, got %v", sessionCookie.SameSite)
	}
	if sessionCookie.Path != "/" {
		t.Errorf("expected session cookie Path to be '/', got %q", sessionCookie.Path)
	}
	if sessionCookie.Domain != "" {
		t.Errorf("expected empty Domain for __Host- cookie, got %q", sessionCookie.Domain)
	}
	if sessionCookie.MaxAge <= 0 {
		t.Errorf("expected positive MaxAge, got %d", sessionCookie.MaxAge)
	}
	if len(sessionCookie.Value) != 43 {
		t.Errorf("expected session token length 43, got %d", len(sessionCookie.Value))
	}
	if strings.Contains(string(signInBody), sessionCookie.Value) {
		t.Errorf("raw session token leaked in JSON body")
	}

	rawToken := sessionCookie.Value

	// Step 4: Verify session in store
	sess, _, err := auth.Sessions.Validate(context.Background(), rawToken)
	if err != nil || sess == nil {
		t.Fatalf("session validation in store failed: %v", err)
	}
	if sess.UserID != createdUser.ID {
		t.Errorf("expected session user ID %s, got %s", createdUser.ID, sess.UserID)
	}

	// Advance clock slightly and verify session remains valid
	fakeClk.Advance(2 * time.Hour)
	sess, _, err = auth.Sessions.Validate(context.Background(), rawToken)
	if err != nil || sess == nil {
		t.Fatalf("session should remain valid after 2 hours: %v", err)
	}

	// Step 5: Sign out with cookie -> 200 OK + Set-Cookie expired
	signOutReq := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
	signOutReq.AddCookie(&http.Cookie{
		Name:  "__Host-kagi_session",
		Value: rawToken,
	})

	signOutResp, err := app.Test(signOutReq)
	if err != nil {
		t.Fatalf("sign out request failed: %v", err)
	}
	defer signOutResp.Body.Close()

	if signOutResp.StatusCode != http.StatusOK {
		t.Fatalf("expected sign out status %d, got %d", http.StatusOK, signOutResp.StatusCode)
	}

	var signOutRespData pkgfiber.SignOutResponse
	if err := json.NewDecoder(signOutResp.Body).Decode(&signOutRespData); err != nil {
		t.Fatalf("failed to decode sign out response: %v", err)
	}
	if signOutRespData.Message != "signed out" {
		t.Errorf("expected message 'signed out', got %q", signOutRespData.Message)
	}

	// Step 6: Verify cookie expired and session deleted in store
	var clearedCookie *http.Cookie
	for _, c := range signOutResp.Cookies() {
		if c.Name == "__Host-kagi_session" {
			clearedCookie = c
			break
		}
	}
	if clearedCookie == nil {
		t.Fatalf("expected cleared __Host-kagi_session cookie in response")
	}
	if clearedCookie.Value != "" {
		t.Errorf("expected cleared cookie value to be empty, got %q", clearedCookie.Value)
	}
	if clearedCookie.MaxAge > 0 {
		t.Errorf("expected cleared cookie MaxAge <= 0, got %d", clearedCookie.MaxAge)
	}
	if !clearedCookie.Expires.Before(time.Now()) {
		t.Errorf("expected cleared cookie Expires in the past, got %v", clearedCookie.Expires)
	}

	// Session is deleted / invalid in store
	_, _, err = auth.Sessions.Validate(context.Background(), rawToken)
	if err == nil {
		t.Errorf("expected session to be revoked in store, but Validate succeeded")
	}

	// Step 7: Second sign out (idempotent)
	// With the expired cookie
	idempotentReq1 := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
	idempotentReq1.AddCookie(&http.Cookie{
		Name:  "__Host-kagi_session",
		Value: rawToken,
	})
	idempotentResp1, err := app.Test(idempotentReq1)
	if err != nil {
		t.Fatalf("idempotent sign out 1 failed: %v", err)
	}
	defer idempotentResp1.Body.Close()

	if idempotentResp1.StatusCode != http.StatusOK {
		t.Fatalf("expected idempotent sign out 1 status 200, got %d", idempotentResp1.StatusCode)
	}

	// Without any cookie
	idempotentReq2 := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
	idempotentResp2, err := app.Test(idempotentReq2)
	if err != nil {
		t.Fatalf("idempotent sign out 2 failed: %v", err)
	}
	defer idempotentResp2.Body.Close()

	if idempotentResp2.StatusCode != http.StatusOK {
		t.Fatalf("expected idempotent sign out 2 status 200, got %d", idempotentResp2.StatusCode)
	}
}

// TestSignUp_TableDriven tests /sign-up edge cases and boundary conditions.
func TestSignUp_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, auth *kagi.Kagi)
		payload     string
		wantStatus  int
		wantCode    string
		checkUser   func(t *testing.T, body []byte)
		skipCodeChk bool
	}{
		{
			name:       "valid registration",
			payload:    `{"email":"newuser@example.com","password":"ValidPassword123!","name":"New User"}`,
			wantStatus: http.StatusCreated,
			checkUser: func(t *testing.T, body []byte) {
				var u kagi.User
				if err := json.Unmarshal(body, &u); err != nil {
					t.Fatalf("failed to decode response as user: %v", err)
				}
				if u.Email != "newuser@example.com" {
					t.Errorf("expected email 'newuser@example.com', got %q", u.Email)
				}
				if u.Name != "New User" {
					t.Errorf("expected name 'New User', got %q", u.Name)
				}
				if u.ID == "" {
					t.Errorf("expected non-empty user ID")
				}
			},
			skipCodeChk: true,
		},
		{
			name: "duplicate email",
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
			wantCode:   "email_already_exists",
		},
		{
			name:       `invalid email format "invalid-email"`,
			payload:    `{"email":"invalid-email","password":"ValidPassword123!"}`,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_credentials",
		},
		{
			name:       `invalid email format "@missing.com"`,
			payload:    `{"email":"@missing.com","password":"ValidPassword123!"}`,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_credentials",
		},
		{
			name:       `invalid email format "missing@"`,
			payload:    `{"email":"missing@","password":"ValidPassword123!"}`,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_credentials",
		},
		{
			name:       `invalid email format "notanemail"`,
			payload:    `{"email":"notanemail","password":"ValidPassword123!"}`,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_credentials",
		},
		{
			name:       `invalid email format "missing@domain"`,
			payload:    `{"email":"missing@domain","password":"ValidPassword123!"}`,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_credentials",
		},
		{
			name:       "password too short (< 8 chars)",
			payload:    `{"email":"shortpw@example.com","password":"short"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "password_too_weak",
		},
		{
			name:       "password too long (> 72 chars)",
			payload:    `{"email":"longpw@example.com","password":"` + strings.Repeat("A", 73) + `"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "password_too_weak",
		},
		{
			name:       "empty body string",
			payload:    "",
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "empty JSON object {}",
			payload:    `{}`,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_credentials",
		},
		{
			name:       "malformed JSON",
			payload:    `{"email": "broken"`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "extra fields in JSON ignored gracefully",
			payload:    `{"email":"extrafields@example.com","password":"ValidPassword123!","name":"Extra","unknown_prop":123,"role":"admin"}`,
			wantStatus: http.StatusCreated,
			checkUser: func(t *testing.T, body []byte) {
				var u kagi.User
				if err := json.Unmarshal(body, &u); err != nil {
					t.Fatalf("failed to decode response as user: %v", err)
				}
				if u.Email != "extrafields@example.com" {
					t.Errorf("expected email 'extrafields@example.com', got %q", u.Email)
				}
				if u.Name != "Extra" {
					t.Errorf("expected name 'Extra', got %q", u.Name)
				}
			},
			skipCodeChk: true,
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

			if !tt.skipCodeChk && tt.wantCode != "" {
				var errResp pkgfiber.ErrorResponse
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("failed to parse error response: %v", err)
				}
				if errResp.Error != tt.wantCode {
					t.Errorf("expected error %q, got %q", tt.wantCode, errResp.Error)
				}
			}

			if tt.checkUser != nil {
				tt.checkUser(t, body)
			}
		})
	}
}

// TestSignUp preserves backward-compatible invocation of sign-up tests.
func TestSignUp(t *testing.T) {
	TestSignUp_TableDriven(t)
}

// TestSignIn_TableDriven tests /sign-in edge cases and boundary conditions.
func TestSignIn_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, auth *kagi.Kagi)
		kagiCfg     func(cfg *kagi.Config)
		remoteAddr  string
		payload     string
		wantStatus  int
		wantCode    string
		checkResp   func(t *testing.T, resp *http.Response, body []byte)
		skipCodeChk bool
	}{
		{
			name: "valid credentials",
			setup: func(t *testing.T, auth *kagi.Kagi) {
				_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
					Email:    "signin@example.com",
					Password: "ValidPassword123!",
					Name:     "Sign In User",
				})
				if err != nil {
					t.Fatalf("failed to pre-seed user: %v", err)
				}
			},
			payload:    `{"email":"signin@example.com","password":"ValidPassword123!"}`,
			wantStatus: http.StatusOK,
			checkResp: func(t *testing.T, resp *http.Response, body []byte) {
				var authResp pkgfiber.AuthResponse
				if err := json.Unmarshal(body, &authResp); err != nil {
					t.Fatalf("failed to unmarshal AuthResponse: %v", err)
				}
				if authResp.User == nil || authResp.User.Email != "signin@example.com" {
					t.Errorf("expected user email 'signin@example.com', got %v", authResp.User)
				}
				if authResp.Session == nil {
					t.Fatalf("expected non-nil session in response")
				}
				if strings.Contains(string(body), "token_hash") {
					t.Errorf("token_hash leaked in JSON response: %s", string(body))
				}

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
				if len(sessionCookie.Value) != 43 {
					t.Errorf("expected token length 43, got %d", len(sessionCookie.Value))
				}
				if strings.Contains(string(body), sessionCookie.Value) {
					t.Errorf("raw session token leaked in JSON response body")
				}
			},
			skipCodeChk: true,
		},
		{
			name: "incorrect password",
			setup: func(t *testing.T, auth *kagi.Kagi) {
				_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
					Email:    "wrongpw@example.com",
					Password: "ValidPassword123!",
				})
				if err != nil {
					t.Fatalf("failed to pre-seed user: %v", err)
				}
			},
			payload:    `{"email":"wrongpw@example.com","password":"IncorrectPassword123!"}`,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_credentials",
			checkResp: func(t *testing.T, resp *http.Response, _ []byte) {
				for _, c := range resp.Cookies() {
					if c.Name == "__Host-kagi_session" {
						t.Errorf("unexpected cookie on failed sign in")
					}
				}
			},
		},
		{
			name:       "unknown email / non-existent user",
			payload:    `{"email":"nonexistent@example.com","password":"ValidPassword123!"}`,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_credentials",
			checkResp: func(t *testing.T, resp *http.Response, _ []byte) {
				for _, c := range resp.Cookies() {
					if c.Name == "__Host-kagi_session" {
						t.Errorf("unexpected cookie on failed sign in")
					}
				}
			},
		},
		{
			name:       "malformed JSON",
			payload:    `{"email": "broken"`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "empty body string",
			payload:    "",
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "empty JSON object {}",
			payload:    `{}`,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, auth, _ := setupTestAppWithStores(t, tt.kagiCfg)
			if tt.setup != nil {
				tt.setup(t, auth)
			}

			req := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}

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

			if !tt.skipCodeChk && tt.wantCode != "" {
				var errResp pkgfiber.ErrorResponse
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("failed to parse error response: %v", err)
				}
				if errResp.Error != tt.wantCode {
					t.Errorf("expected error %q, got %q", tt.wantCode, errResp.Error)
				}
			}

			if tt.checkResp != nil {
				tt.checkResp(t, resp, body)
			}
		})
	}

	// Rate limit exceeded tests
	t.Run("rate limit exceeded on email", func(t *testing.T) {
		app, auth, _ := setupTestAppWithStores(t, func(cfg *kagi.Config) {
			cfg.RateLimit = kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{Limit: 2, Window: 15 * time.Minute},
				SignInIP:    kagi.LimitRule{Limit: 10, Window: 15 * time.Minute},
			}
		})

		_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
			Email:    "ratelimit-email@example.com",
			Password: "ValidPassword123!",
		})
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		payload := `{"email":"ratelimit-email@example.com","password":"WrongPassword123!"}`

		// Attempt 1 from IP1 -> 401
		req1 := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(payload))
		req1.Header.Set("Content-Type", "application/json")
		req1.RemoteAddr = "198.51.100.1:1234"
		resp1, err := app.Test(req1)
		if err != nil {
			t.Fatalf("attempt 1 error: %v", err)
		}
		resp1.Body.Close()
		if resp1.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected attempt 1 status 401, got %d", resp1.StatusCode)
		}

		// Attempt 2 from IP2 -> 401
		req2 := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(payload))
		req2.Header.Set("Content-Type", "application/json")
		req2.RemoteAddr = "198.51.100.2:1234"
		resp2, err := app.Test(req2)
		if err != nil {
			t.Fatalf("attempt 2 error: %v", err)
		}
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected attempt 2 status 401, got %d", resp2.StatusCode)
		}

		// Attempt 3 from IP3 -> 429 Too Many Requests (Email limit reached)
		req3 := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(payload))
		req3.Header.Set("Content-Type", "application/json")
		req3.RemoteAddr = "198.51.100.3:1234"
		resp3, err := app.Test(req3)
		if err != nil {
			t.Fatalf("attempt 3 error: %v", err)
		}
		defer resp3.Body.Close()

		if resp3.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("expected attempt 3 status %d, got %d", http.StatusTooManyRequests, resp3.StatusCode)
		}

		body, err := io.ReadAll(resp3.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		var errResp pkgfiber.ErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			t.Fatalf("failed to unmarshal ErrorResponse: %v", err)
		}
		if errResp.Error != "rate_limit_exceeded" {
			t.Errorf("expected error 'rate_limit_exceeded', got %q", errResp.Error)
		}
	})

	t.Run("rate limit exceeded on IP", func(t *testing.T) {
		app, auth, _ := setupTestAppWithStores(t, func(cfg *kagi.Config) {
			cfg.RateLimit = kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{Limit: 10, Window: 15 * time.Minute},
				SignInIP:    kagi.LimitRule{Limit: 2, Window: 15 * time.Minute},
			}
		})

		_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
			Email:    "ratelimit-ip@example.com",
			Password: "ValidPassword123!",
		})
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		ipAddr := "198.51.100.99:1234"

		// Attempt 1 from IP -> 401
		req1 := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(`{"email":"ratelimit-ip@example.com","password":"WrongPassword123!"}`))
		req1.Header.Set("Content-Type", "application/json")
		req1.RemoteAddr = ipAddr
		resp1, err := app.Test(req1)
		if err != nil {
			t.Fatalf("attempt 1 error: %v", err)
		}
		resp1.Body.Close()
		if resp1.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected attempt 1 status 401, got %d", resp1.StatusCode)
		}

		// Attempt 2 from same IP (different email) -> 401
		req2 := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(`{"email":"different@example.com","password":"WrongPassword123!"}`))
		req2.Header.Set("Content-Type", "application/json")
		req2.RemoteAddr = ipAddr
		resp2, err := app.Test(req2)
		if err != nil {
			t.Fatalf("attempt 2 error: %v", err)
		}
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected attempt 2 status 401, got %d", resp2.StatusCode)
		}

		// Attempt 3 from same IP -> 429 Too Many Requests (IP limit reached)
		req3 := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(`{"email":"another@example.com","password":"WrongPassword123!"}`))
		req3.Header.Set("Content-Type", "application/json")
		req3.RemoteAddr = ipAddr
		resp3, err := app.Test(req3)
		if err != nil {
			t.Fatalf("attempt 3 error: %v", err)
		}
		defer resp3.Body.Close()

		if resp3.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("expected attempt 3 status %d, got %d", http.StatusTooManyRequests, resp3.StatusCode)
		}

		body, err := io.ReadAll(resp3.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
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

// TestSignIn preserves backward-compatible invocation of sign-in tests.
func TestSignIn(t *testing.T) {
	TestSignIn_TableDriven(t)
}

// TestSignOut tests the sign-out endpoint including session revocation and cookie clearing.
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

// TestCookieSecurity asserts all security attributes of the session Set-Cookie header.
func TestCookieSecurity(t *testing.T) {
	app, auth := setupTestApp(t)

	_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "cookiesecurity@example.com",
		Password: "ValidPassword123!",
	})
	if err != nil {
		t.Fatalf("sign up failed: %v", err)
	}

	signInReq := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(`{"email":"cookiesecurity@example.com","password":"ValidPassword123!"}`))
	signInReq.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(signInReq)
	if err != nil {
		t.Fatalf("sign in failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	setCookieHeader := resp.Header.Get("Set-Cookie")
	if setCookieHeader == "" {
		t.Fatalf("expected Set-Cookie header to be set")
	}

	// 1. Verify raw Set-Cookie header attributes
	if !strings.Contains(setCookieHeader, "__Host-kagi_session=") {
		t.Errorf("expected Set-Cookie to start with '__Host-kagi_session=', got: %s", setCookieHeader)
	}
	if !strings.Contains(strings.ToLower(setCookieHeader), "httponly") {
		t.Errorf("expected Set-Cookie to contain HttpOnly, got: %s", setCookieHeader)
	}
	if !strings.Contains(strings.ToLower(setCookieHeader), "secure") {
		t.Errorf("expected Set-Cookie to contain Secure, got: %s", setCookieHeader)
	}
	if !strings.Contains(strings.ToLower(setCookieHeader), "samesite=lax") {
		t.Errorf("expected Set-Cookie to contain SameSite=Lax, got: %s", setCookieHeader)
	}
	if !strings.Contains(strings.ToLower(setCookieHeader), "path=/") {
		t.Errorf("expected Set-Cookie to contain Path=/, got: %s", setCookieHeader)
	}
	// RFC 6265bis: __Host- prefix MUST NOT have a Domain attribute
	if strings.Contains(strings.ToLower(setCookieHeader), "domain=") {
		t.Errorf("RFC 6265bis violation: __Host- cookie must not have a Domain attribute, got: %s", setCookieHeader)
	}
	if !strings.Contains(strings.ToLower(setCookieHeader), "max-age=") {
		t.Errorf("expected Set-Cookie to contain Max-Age, got: %s", setCookieHeader)
	}
	// 2. Verify parsed http.Cookie attributes
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-kagi_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected parsed __Host-kagi_session cookie")
	}
	if !sessionCookie.HttpOnly {
		t.Errorf("expected cookie.HttpOnly == true")
	}
	if !sessionCookie.Secure {
		t.Errorf("expected cookie.Secure == true")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected cookie.SameSite == Lax, got %v", sessionCookie.SameSite)
	}
	if sessionCookie.Path != "/" {
		t.Errorf("expected cookie.Path == '/', got %q", sessionCookie.Path)
	}
	if sessionCookie.Domain != "" {
		t.Errorf("expected empty cookie.Domain for __Host- cookie, got %q", sessionCookie.Domain)
	}
	if sessionCookie.MaxAge <= 0 {
		t.Errorf("expected positive cookie.MaxAge, got %d", sessionCookie.MaxAge)
	}
}

// TestInsecureDevMode verifies WithInsecureDevMode(true) switches cookie name to kagi_session and Secure to false.
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
	if strings.Contains(rawSetCookie, "__Host-") {
		t.Errorf("expected Set-Cookie not to contain __Host- in dev mode, got: %s", rawSetCookie)
	}

	// Verify sign out in insecure dev mode also clears "kagi_session" without Secure
	signOutReq := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
	signOutReq.AddCookie(&http.Cookie{
		Name:  "kagi_session",
		Value: devCookie.Value,
	})
	signOutResp, err := app.Test(signOutReq)
	if err != nil {
		t.Fatalf("sign out failed: %v", err)
	}
	defer signOutResp.Body.Close()

	if signOutResp.StatusCode != http.StatusOK {
		t.Fatalf("expected sign out status 200, got %d", signOutResp.StatusCode)
	}

	var clearedDevCookie *http.Cookie
	for _, c := range signOutResp.Cookies() {
		if c.Name == "kagi_session" {
			clearedDevCookie = c
			break
		}
	}
	if clearedDevCookie == nil {
		t.Fatalf("expected cleared cookie 'kagi_session' in dev mode sign out")
	}
	if clearedDevCookie.Secure {
		t.Errorf("expected cleared cookie Secure to be false in dev mode")
	}
	if clearedDevCookie.MaxAge > 0 {
		t.Errorf("expected cleared cookie MaxAge <= 0, got %d", clearedDevCookie.MaxAge)
	}
}

// TestInsecureDevModeCookie is an alias for TestInsecureDevMode.
func TestInsecureDevModeCookie(t *testing.T) {
	TestInsecureDevMode(t)
}

// TestWithPrefix verifies mounting handlers under custom prefixes like /api/v1/auth.
func TestWithPrefix(t *testing.T) {
	prefix := "/api/v1/auth"
	app, auth := setupTestApp(t, pkgfiber.WithPrefix(prefix))

	// 1. Sign up under custom prefix
	signUpPayload := `{"email":"prefixed@example.com","password":"ValidPassword123!","name":"Prefix User"}`
	signUpReq := httptest.NewRequest(http.MethodPost, prefix+"/sign-up", bytes.NewBufferString(signUpPayload))
	signUpReq.Header.Set("Content-Type", "application/json")

	signUpResp, err := app.Test(signUpReq)
	if err != nil {
		t.Fatalf("sign up error: %v", err)
	}
	defer signUpResp.Body.Close()

	if signUpResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected sign up status %d, got %d", http.StatusCreated, signUpResp.StatusCode)
	}

	// 2. Sign in under custom prefix
	signInPayload := `{"email":"prefixed@example.com","password":"ValidPassword123!"}`
	signInReq := httptest.NewRequest(http.MethodPost, prefix+"/sign-in", bytes.NewBufferString(signInPayload))
	signInReq.Header.Set("Content-Type", "application/json")

	signInResp, err := app.Test(signInReq)
	if err != nil {
		t.Fatalf("sign in error: %v", err)
	}
	defer signInResp.Body.Close()

	if signInResp.StatusCode != http.StatusOK {
		t.Fatalf("expected sign in status %d, got %d", http.StatusOK, signInResp.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, c := range signInResp.Cookies() {
		if c.Name == "__Host-kagi_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected session cookie on prefixed sign-in")
	}

	// 3. Sign out under custom prefix
	signOutReq := httptest.NewRequest(http.MethodPost, prefix+"/sign-out", nil)
	signOutReq.AddCookie(sessionCookie)

	signOutResp, err := app.Test(signOutReq)
	if err != nil {
		t.Fatalf("sign out error: %v", err)
	}
	defer signOutResp.Body.Close()

	if signOutResp.StatusCode != http.StatusOK {
		t.Fatalf("expected sign out status %d, got %d", http.StatusOK, signOutResp.StatusCode)
	}

	// 4. Verify unprefixed endpoints return 404 Not Found
	unprefixedEndpoints := []string{"/sign-up", "/sign-in", "/sign-out"}
	for _, ep := range unprefixedEndpoints {
		req := httptest.NewRequest(http.MethodPost, ep, bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error requesting %s: %v", ep, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 Not Found for unprefixed endpoint %s, got %d", ep, resp.StatusCode)
		}
	}

	_ = auth
}

// TestRoutePrefixes is an alias for TestWithPrefix.
func TestRoutePrefixes(t *testing.T) {
	TestWithPrefix(t)
}

// TestSignUpWithPrefix verifies prefix behavior on sign-up specifically.
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

// TestClockSessionExpiry verifies session expiration using deterministic clock advancement.
func TestClockSessionExpiry(t *testing.T) {
	app, auth, _, fakeClk := setupTestAppWithClock(t, nil)

	_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "clockexp@example.com",
		Password: "ValidPassword123!",
	})
	if err != nil {
		t.Fatalf("sign up failed: %v", err)
	}

	signInReq := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(`{"email":"clockexp@example.com","password":"ValidPassword123!"}`))
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
		t.Fatalf("session cookie not found")
	}

	// Validate session immediately -> OK
	sess, _, err := auth.Sessions.Validate(context.Background(), rawToken)
	if err != nil || sess == nil {
		t.Fatalf("expected valid session, got err: %v", err)
	}

	// Advance clock beyond default IdleTimeout (7 days + 1 hour)
	fakeClk.Advance(7*24*time.Hour + time.Hour)

	// Validate session after expiration -> ErrSessionNotFound
	_, _, err = auth.Sessions.Validate(context.Background(), rawToken)
	if err == nil {
		t.Fatalf("expected session to be expired after advancing clock, but Validate succeeded")
	}

	// Sign out with the expired cookie -> still 200 OK and cleared cookie (idempotent)
	signOutReq := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
	signOutReq.AddCookie(&http.Cookie{
		Name:  "__Host-kagi_session",
		Value: rawToken,
	})
	signOutResp, err := app.Test(signOutReq)
	if err != nil {
		t.Fatalf("sign out failed: %v", err)
	}
	defer signOutResp.Body.Close()

	if signOutResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 on sign-out with expired token, got %d", signOutResp.StatusCode)
	}
}
