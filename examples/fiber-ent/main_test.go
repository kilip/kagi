package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kilip/kagi"
)

func TestFullAuthLifecycle(t *testing.T) {
	dbURL := fmt.Sprintf("file:test_%d?mode=memory&cache=shared&_fk=1", time.Now().UnixNano())
	cfg := Config{
		DatabaseURL: dbURL,
		Secret:      "test-secret-at-least-32-bytes-long-super-secret",
		Port:        "3000",
	}

	app, client, _, err := SetupApp(cfg)
	if err != nil {
		t.Fatalf("SetupApp failed: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})

	// 1. GET /auth/csrf to get CSRF token and kagi_csrf cookie.
	csrfReq := httptest.NewRequest(http.MethodGet, "/auth/csrf", nil)
	csrfResp, err := app.Test(csrfReq)
	if err != nil {
		t.Fatalf("GET /auth/csrf failed: %v", err)
	}
	defer csrfResp.Body.Close()

	if csrfResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 for GET /auth/csrf, got %d", csrfResp.StatusCode)
	}

	var csrfBody struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(csrfResp.Body).Decode(&csrfBody); err != nil {
		t.Fatalf("failed to decode CSRF response: %v", err)
	}
	if csrfBody.CSRFToken == "" {
		t.Fatal("expected non-empty csrf_token")
	}

	csrfCookie := findCookie(csrfResp.Cookies(), "kagi_csrf")
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatal("expected non-empty kagi_csrf cookie in Set-Cookie")
	}

	// 2. POST /auth/sign-up with email, password, name, X-CSRF-Token, and kagi_csrf cookie -> expect 201 Created and user in response.
	signUpPayload := map[string]string{
		"email":    "lifecycle@example.com",
		"password": "ValidPassword123!",
		"name":     "Lifecycle User",
	}
	signUpBytes, err := json.Marshal(signUpPayload)
	if err != nil {
		t.Fatalf("failed to marshal sign-up payload: %v", err)
	}

	signUpReq := httptest.NewRequest(http.MethodPost, "/auth/sign-up", bytes.NewReader(signUpBytes))
	signUpReq.Header.Set("Content-Type", "application/json")
	signUpReq.Header.Set("X-CSRF-Token", csrfBody.CSRFToken)
	signUpReq.AddCookie(csrfCookie)

	signUpResp, err := app.Test(signUpReq)
	if err != nil {
		t.Fatalf("POST /auth/sign-up failed: %v", err)
	}
	defer signUpResp.Body.Close()

	if signUpResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201 for POST /auth/sign-up, got %d", signUpResp.StatusCode)
	}

	var createdUser kagi.User
	if err := json.NewDecoder(signUpResp.Body).Decode(&createdUser); err != nil {
		t.Fatalf("failed to decode sign-up response: %v", err)
	}
	if createdUser.ID == "" {
		t.Error("expected non-empty user ID in sign-up response")
	}
	if createdUser.Email != "lifecycle@example.com" {
		t.Errorf("expected email 'lifecycle@example.com', got %q", createdUser.Email)
	}
	if createdUser.Name != "Lifecycle User" {
		t.Errorf("expected name 'Lifecycle User', got %q", createdUser.Name)
	}

	// 3. POST /auth/sign-in with email, password, X-CSRF-Token, and kagi_csrf cookie -> expect 200 OK, response with user and session, and kagi_session cookie in Set-Cookie.
	signInPayload := map[string]string{
		"email":    "lifecycle@example.com",
		"password": "ValidPassword123!",
	}
	signInBytes, err := json.Marshal(signInPayload)
	if err != nil {
		t.Fatalf("failed to marshal sign-in payload: %v", err)
	}

	signInReq := httptest.NewRequest(http.MethodPost, "/auth/sign-in", bytes.NewReader(signInBytes))
	signInReq.Header.Set("Content-Type", "application/json")
	signInReq.Header.Set("X-CSRF-Token", csrfBody.CSRFToken)
	signInReq.AddCookie(csrfCookie)

	signInResp, err := app.Test(signInReq)
	if err != nil {
		t.Fatalf("POST /auth/sign-in failed: %v", err)
	}
	defer signInResp.Body.Close()

	if signInResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 for POST /auth/sign-in, got %d", signInResp.StatusCode)
	}

	var authResp struct {
		User    *kagi.User    `json:"user"`
		Session *kagi.Session `json:"session"`
	}
	if err := json.NewDecoder(signInResp.Body).Decode(&authResp); err != nil {
		t.Fatalf("failed to decode sign-in response: %v", err)
	}
	if authResp.User == nil || authResp.User.ID != createdUser.ID {
		t.Errorf("expected user ID %s in sign-in response, got %v", createdUser.ID, authResp.User)
	}
	if authResp.Session == nil || authResp.Session.ID == "" {
		t.Fatal("expected non-nil session with ID in sign-in response")
	}

	sessionCookie := findCookie(signInResp.Cookies(), "kagi_session")
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("expected non-empty kagi_session cookie in Set-Cookie")
	}

	// 4. GET /me with kagi_session cookie -> expect 200 OK with authenticated user and session data.
	meReq := httptest.NewRequest(http.MethodGet, "/me", nil)
	meReq.AddCookie(sessionCookie)

	meResp, err := app.Test(meReq)
	if err != nil {
		t.Fatalf("GET /me with cookie failed: %v", err)
	}
	defer meResp.Body.Close()

	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 for GET /me with cookie, got %d", meResp.StatusCode)
	}

	var meRespBody struct {
		User    *kagi.User    `json:"user"`
		Session *kagi.Session `json:"session"`
	}
	if err := json.NewDecoder(meResp.Body).Decode(&meRespBody); err != nil {
		t.Fatalf("failed to decode /me response: %v", err)
	}
	if meRespBody.User == nil || meRespBody.User.ID != createdUser.ID {
		t.Errorf("expected user ID %s in /me response, got %v", createdUser.ID, meRespBody.User)
	}
	if meRespBody.Session == nil || meRespBody.Session.ID != authResp.Session.ID {
		t.Errorf("expected session ID %s in /me response, got %v", authResp.Session.ID, meRespBody.Session)
	}

	// 5. GET /me without cookie -> expect 401 Unauthorized.
	unauthReq := httptest.NewRequest(http.MethodGet, "/me", nil)
	unauthResp, err := app.Test(unauthReq)
	if err != nil {
		t.Fatalf("GET /me without cookie failed: %v", err)
	}
	defer unauthResp.Body.Close()

	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for GET /me without cookie, got %d", unauthResp.StatusCode)
	}

	// 6. POST /auth/sign-out with kagi_session cookie, kagi_csrf cookie, and X-CSRF-Token -> expect 200 OK and kagi_session cleared.
	signOutReq := httptest.NewRequest(http.MethodPost, "/auth/sign-out", nil)
	signOutReq.Header.Set("X-CSRF-Token", csrfBody.CSRFToken)
	signOutReq.AddCookie(csrfCookie)
	signOutReq.AddCookie(sessionCookie)

	signOutResp, err := app.Test(signOutReq)
	if err != nil {
		t.Fatalf("POST /auth/sign-out failed: %v", err)
	}
	defer signOutResp.Body.Close()

	if signOutResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 for POST /auth/sign-out, got %d", signOutResp.StatusCode)
	}

	clearedSessionCookie := findCookie(signOutResp.Cookies(), "kagi_session")
	if clearedSessionCookie == nil {
		t.Fatal("expected kagi_session in Set-Cookie on sign-out")
	}
	if clearedSessionCookie.Value != "" && clearedSessionCookie.MaxAge >= 0 && !clearedSessionCookie.Expires.Before(time.Now()) {
		t.Errorf("expected kagi_session cookie to be cleared, got value %q, MaxAge %d, Expires %v",
			clearedSessionCookie.Value, clearedSessionCookie.MaxAge, clearedSessionCookie.Expires)
	}

	// 7. GET /me with the revoked kagi_session cookie -> expect 401 Unauthorized.
	revokedReq := httptest.NewRequest(http.MethodGet, "/me", nil)
	revokedReq.AddCookie(sessionCookie)

	revokedResp, err := app.Test(revokedReq)
	if err != nil {
		t.Fatalf("GET /me with revoked cookie failed: %v", err)
	}
	defer revokedResp.Body.Close()

	if revokedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for GET /me with revoked cookie, got %d", revokedResp.StatusCode)
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
