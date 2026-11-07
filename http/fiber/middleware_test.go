package fiber_test

import (
	"context"
	"encoding/json"
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
	"github.com/kilip/kagi/internal/crypto"
)

func createTestSession(t *testing.T, stores *memory.Stores, clk clock.Clock, userID string, pending2FA bool, ttl time.Duration) (string, *kagi.Session) {
	t.Helper()
	rawToken, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("failed to generate session token: %v", err)
	}

	tokenHash := crypto.HashToken(rawToken)
	now := clk.Now().UTC()
	sess := &kagi.Session{
		UserID:     userID,
		TokenHash:  tokenHash,
		ExpiresAt:  now.Add(ttl),
		Pending2FA: pending2FA,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := stores.Session.Create(context.Background(), sess); err != nil {
		t.Fatalf("failed to insert session: %v", err)
	}

	return rawToken, sess
}
func createTestSessionWithCreatedAt(t *testing.T, stores *memory.Stores, clk clock.Clock, userID string, pending2FA bool, createdAt time.Time, expiresAt time.Time) (string, *kagi.Session) {
	t.Helper()
	rawToken, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("failed to generate session token: %v", err)
	}

	tokenHash := crypto.HashToken(rawToken)
	now := clk.Now().UTC()
	sess := &kagi.Session{
		UserID:     userID,
		TokenHash:  tokenHash,
		ExpiresAt:  expiresAt,
		Pending2FA: pending2FA,
		CreatedAt:  createdAt,
		UpdatedAt:  now,
	}

	if err := stores.Session.Create(context.Background(), sess); err != nil {
		t.Fatalf("failed to insert session: %v", err)
	}

	return rawToken, sess
}

func TestRequireAuth_TableDriven(t *testing.T) {
	t.Parallel()

	type testSetup struct {
		name       string
		setupToken func(t *testing.T, stores *memory.Stores, clk *clock.FakeClock) (cookieValue string, hasCookie bool)
		wantStatus int
		wantCode   string
	}

	tests := []testSetup{
		{
			name: "missing cookie",
			setupToken: func(t *testing.T, stores *memory.Stores, clk *clock.FakeClock) (string, bool) {
				return "", false
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "session_not_found",
		},
		{
			name: "malformed token - too short",
			setupToken: func(t *testing.T, stores *memory.Stores, clk *clock.FakeClock) (string, bool) {
				return "short-token", true
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_session",
		},
		{
			name: "malformed token - too long",
			setupToken: func(t *testing.T, stores *memory.Stores, clk *clock.FakeClock) (string, bool) {
				return "this-token-is-way-too-long-and-exceeds-43-chars-by-far", true
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_session",
		},
		{
			name: "non-existent token hash",
			setupToken: func(t *testing.T, stores *memory.Stores, clk *clock.FakeClock) (string, bool) {
				token, err := crypto.GenerateSessionToken()
				if err != nil {
					t.Fatalf("failed to generate token: %v", err)
				}
				return token, true
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "session_not_found",
		},
		{
			name: "expired session",
			setupToken: func(t *testing.T, stores *memory.Stores, clk *clock.FakeClock) (string, bool) {
				token, _ := createTestSession(t, stores, clk, "user-expired", false, 1*time.Hour)
				clk.Advance(2 * time.Hour)
				return token, true
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "session_not_found",
		},
		{
			name: "pending 2FA session rejected with 403",
			setupToken: func(t *testing.T, stores *memory.Stores, clk *clock.FakeClock) (string, bool) {
				token, _ := createTestSession(t, stores, clk, "user-2fa", true, 10*time.Minute)
				return token, true
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "session_pending_2fa",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app, auth, stores, fakeClk := setupTestAppWithClock(t, nil)
			handler := pkgfiber.Register(app, auth)

			app.Get("/protected", handler.RequireAuth(), func(c *fiber.Ctx) error {
				return c.SendString("ok")
			})

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			cookieVal, hasCookie := tc.setupToken(t, stores, fakeClk)
			if hasCookie {
				req.AddCookie(&http.Cookie{
					Name:  "__Host-kagi_session",
					Value: cookieVal,
				})
			}

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, resp.StatusCode)
			}

			var errResp pkgfiber.ErrorResponse
			if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if errResp.Error != tc.wantCode {
				t.Errorf("expected error code %q, got %q", tc.wantCode, errResp.Error)
			}
		})
	}
}

func TestRequireAuth_MissingCookie(t *testing.T) {
	t.Parallel()

	app, auth, _ := setupTestAppWithStores(t, nil)
	handler := pkgfiber.Register(app, auth)

	app.Get("/protected", handler.RequireAuth(), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.StatusCode)
	}

	var errResp pkgfiber.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if errResp.Error != "session_not_found" {
		t.Errorf("expected error code 'session_not_found', got %q", errResp.Error)
	}
}

func TestRequireAuth_Pending2FA(t *testing.T) {
	t.Parallel()

	app, auth, stores, fakeClk := setupTestAppWithClock(t, nil)
	handler := pkgfiber.Register(app, auth)

	app.Get("/protected", handler.RequireAuth(), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	token, _ := createTestSession(t, stores, fakeClk, "user-2fa", true, 10*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "__Host-kagi_session",
		Value: token,
	})

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d", resp.StatusCode)
	}

	var errResp pkgfiber.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if errResp.Error != "session_pending_2fa" {
		t.Errorf("expected error code 'session_pending_2fa', got %q", errResp.Error)
	}
}

func TestRequireAuth_SuccessAndContextAccessors(t *testing.T) {
	t.Parallel()

	app, auth, stores, fakeClk := setupTestAppWithClock(t, nil)
	handler := pkgfiber.Register(app, auth)

	token, sess := createTestSession(t, stores, fakeClk, "user-valid-123", false, 24*time.Hour)

	var (
		capturedSessLocals  *kagi.Session
		capturedSessCtx     *kagi.Session
		capturedUserIDLoc   string
		capturedUserIDCtx   string
		capturedUserIDFiber string
	)

	app.Get("/protected", handler.RequireAuth(), func(c *fiber.Ctx) error {
		capturedSessLocals = pkgfiber.SessionFromCtx(c)
		capturedSessCtx = pkgfiber.SessionFromContext(c.UserContext())
		capturedUserIDLoc = pkgfiber.UserIDFromCtx(c)
		capturedUserIDCtx = pkgfiber.UserIDFromContext(c.UserContext())
		capturedUserIDFiber = c.Locals(pkgfiber.LocalsUserIDKey).(string)
		return c.SendString("ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "__Host-kagi_session",
		Value: token,
	})

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	if capturedSessLocals == nil || capturedSessLocals.ID != sess.ID {
		t.Errorf("SessionFromCtx failed: got %+v, want ID %s", capturedSessLocals, sess.ID)
	}
	if capturedSessCtx == nil || capturedSessCtx.ID != sess.ID {
		t.Errorf("SessionFromContext failed: got %+v, want ID %s", capturedSessCtx, sess.ID)
	}
	if capturedUserIDLoc != "user-valid-123" {
		t.Errorf("UserIDFromCtx mismatch: got %q, want user-valid-123", capturedUserIDLoc)
	}
	if capturedUserIDCtx != "user-valid-123" {
		t.Errorf("UserIDFromContext mismatch: got %q, want user-valid-123", capturedUserIDCtx)
	}
	if capturedUserIDFiber != "user-valid-123" {
		t.Errorf("LocalsUserIDKey mismatch: got %q, want user-valid-123", capturedUserIDFiber)
	}
}

func TestSession_Optional(t *testing.T) {
	t.Parallel()

	app, auth, stores, fakeClk := setupTestAppWithClock(t, nil)
	handler := pkgfiber.Register(app, auth)

	var (
		capturedSess   *kagi.Session
		capturedUserID string
	)

	app.Get("/optional", handler.Session(), func(c *fiber.Ctx) error {
		capturedSess = pkgfiber.SessionFromCtx(c)
		capturedUserID = pkgfiber.UserIDFromCtx(c)
		return c.SendString("ok")
	})

	t.Run("no cookie allows guest access", func(t *testing.T) {
		capturedSess = nil
		capturedUserID = ""

		req := httptest.NewRequest(http.MethodGet, "/optional", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		if capturedSess != nil {
			t.Errorf("expected nil session, got %+v", capturedSess)
		}
		if capturedUserID != "" {
			t.Errorf("expected empty user ID, got %q", capturedUserID)
		}
	})

	t.Run("invalid length cookie allows guest access", func(t *testing.T) {
		capturedSess = nil
		capturedUserID = ""

		req := httptest.NewRequest(http.MethodGet, "/optional", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-kagi_session",
			Value: "short",
		})
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		if capturedSess != nil {
			t.Errorf("expected nil session, got %+v", capturedSess)
		}
	})

	t.Run("non-existent session allows guest access", func(t *testing.T) {
		capturedSess = nil
		capturedUserID = ""

		dummyToken, _ := crypto.GenerateSessionToken()
		req := httptest.NewRequest(http.MethodGet, "/optional", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-kagi_session",
			Value: dummyToken,
		})
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		if capturedSess != nil {
			t.Errorf("expected nil session, got %+v", capturedSess)
		}
	})

	t.Run("valid session populates session in optional mode", func(t *testing.T) {
		capturedSess = nil
		capturedUserID = ""

		token, sess := createTestSession(t, stores, fakeClk, "user-opt-1", false, 24*time.Hour)
		req := httptest.NewRequest(http.MethodGet, "/optional", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-kagi_session",
			Value: token,
		})
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		if capturedSess == nil || capturedSess.ID != sess.ID {
			t.Errorf("expected populated session, got %+v", capturedSess)
		}
		if capturedUserID != "user-opt-1" {
			t.Errorf("expected user ID user-opt-1, got %q", capturedUserID)
		}
	})

	t.Run("pending 2FA session rejected with 403 even in optional mode", func(t *testing.T) {
		token2FA, _ := createTestSession(t, stores, fakeClk, "user-2fa-opt", true, 10*time.Minute)
		req := httptest.NewRequest(http.MethodGet, "/optional", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-kagi_session",
			Value: token2FA,
		})
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected status 403 Forbidden, got %d", resp.StatusCode)
		}

		var errResp pkgfiber.ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if errResp.Error != "session_pending_2fa" {
			t.Errorf("expected error code 'session_pending_2fa', got %q", errResp.Error)
		}
	})
}

func TestMiddleware_SlidingRenewal(t *testing.T) {
	t.Parallel()

	app, auth, stores, fakeClk := setupTestAppWithClock(t, nil)
	handler := pkgfiber.Register(app, auth)

	app.Get("/profile", handler.RequireAuth(), func(c *fiber.Ctx) error {
		return c.SendString("profile")
	})

	// 1. Initial 7-day session
	token, _ := createTestSession(t, stores, fakeClk, "user-renew", false, 7*24*time.Hour)

	// 2. Advance clock past renewal threshold: 4 days elapsed out of 7 days (remaining = 3 days <= 3.5 days threshold)
	fakeClk.Advance(4 * 24 * time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.AddCookie(&http.Cookie{
		Name:  "__Host-kagi_session",
		Value: token,
	})

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var renewedCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-kagi_session" {
			renewedCookie = c
			break
		}
	}
	if renewedCookie == nil {
		t.Fatalf("expected renewed Set-Cookie header on sliding renewal")
	}
	if renewedCookie.Value != token {
		t.Errorf("expected cookie token %q, got %q", token, renewedCookie.Value)
	}
	// Before renewal, remaining time was 3 days. After renewal, MaxAge should be ~7 days.
	if renewedCookie.MaxAge <= int((3 * 24 * time.Hour).Seconds()) {
		t.Errorf("expected renewed MaxAge to be extended past remaining 3 days, got %d", renewedCookie.MaxAge)
	}
	rawSetCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(strings.ToLower(rawSetCookie), "expires=") && !strings.Contains(strings.ToLower(rawSetCookie), "max-age=") {
		t.Errorf("expected Set-Cookie header to contain expires or max-age, got: %s", rawSetCookie)
	}
}
func TestMiddleware_AbsoluteTimeoutCeiling(t *testing.T) {
	t.Parallel()

	app, auth, stores, fakeClk := setupTestAppWithClock(t, nil)
	handler := pkgfiber.Register(app, auth)

	app.Get("/profile-ceiling", handler.RequireAuth(), func(c *fiber.Ctx) error {
		return c.SendString("profile-ceiling")
	})

	// Default session config: IdleTimeout = 7 days, AbsoluteTimeout = 30 days.
	// Consider a session created 29 days ago relative to now.
	// Hard absolute ceiling is CreatedAt + 30 days = now + 1 day (24 hours).
	now := fakeClk.Now().UTC()
	createdAt := now.Add(-29 * 24 * time.Hour)
	absCeiling := createdAt.Add(30 * 24 * time.Hour) // exactly now + 24 hours

	// Current remaining time is 12 hours (<= 3.5 days renewal threshold).
	currentExpires := now.Add(12 * time.Hour)

	token, _ := createTestSessionWithCreatedAt(t, stores, fakeClk, "user-ceiling", false, createdAt, currentExpires)

	req := httptest.NewRequest(http.MethodGet, "/profile-ceiling", nil)
	req.AddCookie(&http.Cookie{
		Name:  "__Host-kagi_session",
		Value: token,
	})

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var renewedCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-kagi_session" {
			renewedCookie = c
			break
		}
	}
	if renewedCookie == nil {
		t.Fatalf("expected renewed Set-Cookie header on sliding renewal near ceiling")
	}

	// Normal renewal without ceiling would extend ExpiresAt to now + 7 days (604800s).
	// But with ceiling, newExpiresAt is capped at createdAt + 30 days = now + 24 hours (86400s).
	expectedMaxAgeCeiling := int((24 * time.Hour).Seconds())
	if renewedCookie.MaxAge > expectedMaxAgeCeiling {
		t.Errorf("expected MaxAge <= %d (capped at AbsoluteTimeout ceiling), got %d", expectedMaxAgeCeiling, renewedCookie.MaxAge)
	}
	if !renewedCookie.Expires.IsZero() && renewedCookie.Expires.After(absCeiling) {
		t.Errorf("expected Expires (%v) not to exceed AbsoluteTimeout ceiling (%v)", renewedCookie.Expires, absCeiling)
	}
}

func TestMiddleware_InsecureDevMode(t *testing.T) {
	t.Parallel()

	app, auth, stores, fakeClk := setupTestAppWithClock(t, nil, pkgfiber.WithInsecureDevMode(true))
	handler := pkgfiber.Register(app, auth, pkgfiber.WithInsecureDevMode(true))

	app.Get("/dev-protected", handler.RequireAuth(), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	// Create session needing renewal
	token, _ := createTestSession(t, stores, fakeClk, "user-dev", false, 2*24*time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/dev-protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "kagi_session",
		Value: token,
	})

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "kagi_session" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatalf("expected kagi_session cookie in response")
	}
	if cookie.Secure {
		t.Errorf("expected Secure=false in InsecureDevMode")
	}
}

func TestMiddleware_FetchUser(t *testing.T) {
	t.Parallel()

	app, auth, stores, fakeClk := setupTestAppWithClock(t, nil)
	handler := pkgfiber.Register(app, auth)

	// Create a user in UserStore
	user := &kagi.User{
		Email:         "middleware-user@example.com",
		EmailVerified: true,
	}
	if err := stores.User.Create(context.Background(), user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	token, _ := createTestSession(t, stores, fakeClk, user.ID, false, 24*time.Hour)

	t.Run("FetchUser=true fetches user entity", func(t *testing.T) {
		var (
			capturedUserCtx   *kagi.User
			capturedUserFiber *kagi.User
		)

		app.Get("/fetch-user-yes", handler.RequireAuth(pkgfiber.WithMiddlewareFetchUser(true)), func(c *fiber.Ctx) error {
			capturedUserFiber = pkgfiber.UserFromCtx(c)
			capturedUserCtx = pkgfiber.UserFromContext(c.UserContext())
			return c.SendString("ok")
		})

		req := httptest.NewRequest(http.MethodGet, "/fetch-user-yes", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-kagi_session",
			Value: token,
		})

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}

		if capturedUserFiber == nil || capturedUserFiber.ID != user.ID {
			t.Fatalf("expected UserFromCtx to return user ID %s, got %+v", user.ID, capturedUserFiber)
		}
		if capturedUserCtx == nil || capturedUserCtx.ID != user.ID {
			t.Fatalf("expected UserFromContext to return user ID %s, got %+v", user.ID, capturedUserCtx)
		}
		if capturedUserFiber.Email != "middleware-user@example.com" {
			t.Errorf("expected email middleware-user@example.com, got %s", capturedUserFiber.Email)
		}
	})

	t.Run("FetchUser=false does not fetch user entity", func(t *testing.T) {
		var capturedUser *kagi.User

		app.Get("/fetch-user-no", handler.RequireAuth(pkgfiber.WithMiddlewareFetchUser(false)), func(c *fiber.Ctx) error {
			capturedUser = pkgfiber.UserFromCtx(c)
			return c.SendString("ok")
		})

		req := httptest.NewRequest(http.MethodGet, "/fetch-user-no", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-kagi_session",
			Value: token,
		})

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}

		if capturedUser != nil {
			t.Errorf("expected UserFromCtx to be nil when FetchUser=false, got %+v", capturedUser)
		}
	})
}

func TestMiddleware_Filter(t *testing.T) {
	t.Parallel()

	app, auth, _ := setupTestAppWithStores(t, nil)
	handler := pkgfiber.Register(app, auth)

	filter := func(c *fiber.Ctx) bool {
		return c.Path() == "/filtered"
	}

	app.Get("/filtered", handler.RequireAuth(pkgfiber.WithMiddlewareFilter(filter)), func(c *fiber.Ctx) error {
		return c.SendString("filtered-pass")
	})

	req := httptest.NewRequest(http.MethodGet, "/filtered", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 when filtered, got %d", resp.StatusCode)
	}
}

func TestMiddleware_ErrorHandler(t *testing.T) {
	t.Parallel()

	app, auth, _ := setupTestAppWithStores(t, nil)
	handler := pkgfiber.Register(app, auth)

	customErrHandler := func(c *fiber.Ctx, err error) error {
		return c.Status(http.StatusTeapot).JSON(fiber.Map{
			"custom_error": err.Error(),
		})
	}

	app.Get("/custom-error", handler.RequireAuth(pkgfiber.WithMiddlewareErrorHandler(customErrHandler)), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/custom-error", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("expected status 418 Teapot, got %d", resp.StatusCode)
	}

	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if data["custom_error"] != kagi.ErrSessionNotFound.Error() {
		t.Errorf("expected custom error %q, got %q", kagi.ErrSessionNotFound.Error(), data["custom_error"])
	}
}

func TestStandaloneConstructors(t *testing.T) {
	t.Parallel()

	app, auth, stores, fakeClk := setupTestAppWithClock(t, nil)
	cfg := pkgfiber.DefaultConfig()

	reqAuthMiddleware := pkgfiber.NewRequireAuth(auth, cfg)
	sessionMiddleware := pkgfiber.NewSessionMiddleware(auth, cfg)

	token, _ := createTestSession(t, stores, fakeClk, "user-standalone", false, 24*time.Hour)

	app.Get("/standalone-require", reqAuthMiddleware, func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})
	app.Get("/standalone-session", sessionMiddleware, func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	t.Run("standalone require auth rejects missing cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/standalone-require", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("standalone require auth accepts valid cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/standalone-require", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-kagi_session",
			Value: token,
		})
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("standalone session accepts missing cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/standalone-session", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	})
}

func TestDirectContextAccessors(t *testing.T) {
	t.Parallel()

	// Test nil inputs
	if pkgfiber.SessionFromCtx(nil) != nil {
		t.Errorf("expected nil for SessionFromCtx(nil)")
	}
	if pkgfiber.SessionFromContext(nil) != nil {
		t.Errorf("expected nil for SessionFromContext(nil)")
	}
	if pkgfiber.UserIDFromCtx(nil) != "" {
		t.Errorf("expected empty string for UserIDFromCtx(nil)")
	}
	if pkgfiber.UserIDFromContext(nil) != "" {
		t.Errorf("expected empty string for UserIDFromContext(nil)")
	}
	if pkgfiber.UserFromCtx(nil) != nil {
		t.Errorf("expected nil for UserFromCtx(nil)")
	}
	if pkgfiber.UserFromContext(nil) != nil {
		t.Errorf("expected nil for UserFromContext(nil)")
	}

	// Test UserID fallback to Session
	app := fiber.New()
	app.Get("/test-fallback", func(c *fiber.Ctx) error {
		// Set session in locals without setting userID in locals
		sess := &kagi.Session{ID: "s1", UserID: "user-from-session"}
		c.Locals(pkgfiber.LocalsSessionKey, sess)

		userID := pkgfiber.UserIDFromCtx(c)
		if userID != "user-from-session" {
			t.Errorf("expected user-from-session from UserIDFromCtx, got %q", userID)
		}
		return c.SendString(userID)
	})

	req := httptest.NewRequest(http.MethodGet, "/test-fallback", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test failed: %v", err)
	}
	resp.Body.Close()
}
