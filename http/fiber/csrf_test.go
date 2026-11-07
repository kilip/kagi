package fiber_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kilip/kagi"
	pkgfiber "github.com/kilip/kagi/http/fiber"
	"github.com/kilip/kagi/internal/crypto"
)

func TestCSRFConfig(t *testing.T) {
	cfg := pkgfiber.DefaultCSRFConfig()

	if cfg.CookieName != "__Host-kagi_csrf" {
		t.Errorf("expected default cookie name __Host-kagi_csrf, got %s", cfg.CookieName)
	}
	if cfg.HeaderName != "X-CSRF-Token" {
		t.Errorf("expected default header name X-CSRF-Token, got %s", cfg.HeaderName)
	}
	if cfg.FormFieldName != "_csrf" {
		t.Errorf("expected default form field name _csrf, got %s", cfg.FormFieldName)
	}
	if cfg.CookieMaxAge != 24*time.Hour {
		t.Errorf("expected default cookie max age 24h, got %v", cfg.CookieMaxAge)
	}
	if !cfg.Secure {
		t.Errorf("expected default secure true, got false")
	}
	if cfg.Disabled {
		t.Errorf("expected default disabled false, got true")
	}
	if cfg.EffectiveCookieName() != "__Host-kagi_csrf" {
		t.Errorf("expected EffectiveCookieName() to return __Host-kagi_csrf, got %s", cfg.EffectiveCookieName())
	}
	if !cfg.IsSecure() {
		t.Errorf("expected IsSecure() to be true")
	}

	// Dev mode: Secure=false strips __Host- prefix
	devCfg := cfg
	devCfg.Secure = false
	if devCfg.EffectiveCookieName() != "kagi_csrf" {
		t.Errorf("expected dev mode EffectiveCookieName() to return kagi_csrf, got %s", devCfg.EffectiveCookieName())
	}
	if devCfg.IsSecure() {
		t.Errorf("expected dev mode IsSecure() to be false")
	}

	// Custom cookie name without __Host- stays untouched even when Secure=false
	customCfg := pkgfiber.CSRFConfig{
		CookieName: "custom_csrf",
		Secure:     false,
	}
	if customCfg.EffectiveCookieName() != "custom_csrf" {
		t.Errorf("expected custom_csrf, got %s", customCfg.EffectiveCookieName())
	}

	// Empty CookieName defaults to __Host-kagi_csrf or kagi_csrf
	emptyCfg := pkgfiber.CSRFConfig{Secure: true}
	if emptyCfg.EffectiveCookieName() != "__Host-kagi_csrf" {
		t.Errorf("expected __Host-kagi_csrf, got %s", emptyCfg.EffectiveCookieName())
	}
	emptyDevCfg := pkgfiber.CSRFConfig{Secure: false}
	if emptyDevCfg.EffectiveCookieName() != "kagi_csrf" {
		t.Errorf("expected kagi_csrf, got %s", emptyDevCfg.EffectiveCookieName())
	}
}

func TestWithCSRFOptions(t *testing.T) {
	app := fiber.New()
	customCfg := pkgfiber.CSRFConfig{
		CookieName:    "my_csrf",
		HeaderName:    "X-My-CSRF",
		FormFieldName: "csrf_field",
		CookieMaxAge:  12 * time.Hour,
		Secure:        false,
		Disabled:      true,
	}

	h := pkgfiber.Register(app, nil,
		pkgfiber.WithCSRFConfig(customCfg),
	)

	if h.Config().CSRF.CookieName != "my_csrf" {
		t.Errorf("expected my_csrf, got %s", h.Config().CSRF.CookieName)
	}
	if h.Config().CSRF.HeaderName != "X-My-CSRF" {
		t.Errorf("expected X-My-CSRF, got %s", h.Config().CSRF.HeaderName)
	}
	if h.Config().CSRF.FormFieldName != "csrf_field" {
		t.Errorf("expected csrf_field, got %s", h.Config().CSRF.FormFieldName)
	}
	if h.Config().CSRF.CookieMaxAge != 12*time.Hour {
		t.Errorf("expected 12h, got %v", h.Config().CSRF.CookieMaxAge)
	}
	if h.Config().CSRF.Secure {
		t.Errorf("expected Secure false")
	}
	if !h.Config().CSRF.Disabled {
		t.Errorf("expected Disabled true")
	}

	// Test WithInsecureDevMode affects both session and CSRF cookies
	appDev := fiber.New()
	hDev := pkgfiber.Register(appDev, nil, pkgfiber.WithInsecureDevMode(true))
	if hDev.Config().Cookie.Secure {
		t.Errorf("expected Cookie.Secure false")
	}
	if hDev.Config().CSRF.Secure {
		t.Errorf("expected CSRF.Secure false")
	}
	if hDev.Config().CSRF.EffectiveCookieName() != "kagi_csrf" {
		t.Errorf("expected kagi_csrf, got %s", hDev.Config().CSRF.EffectiveCookieName())
	}

	// Test WithCSRFDisabled
	appDisabled := fiber.New()
	hDisabled := pkgfiber.Register(appDisabled, nil, pkgfiber.WithCSRFDisabled(true))
	if !hDisabled.Config().CSRF.Disabled {
		t.Errorf("expected CSRF.Disabled true")
	}
}

func TestCSRFTokenEndpoint(t *testing.T) {
	app, _ := setupTestApp(t, pkgfiber.WithCSRFDisabled(false))

	t.Run("GET /csrf initializes cookie and returns masked token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		var body pkgfiber.CSRFResponse
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if body.CSRFToken == "" {
			t.Fatal("expected non-empty csrf_token in response")
		}

		var csrfCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "__Host-kagi_csrf" {
				csrfCookie = c
				break
			}
		}
		if csrfCookie == nil {
			t.Fatal("expected __Host-kagi_csrf cookie to be set")
		}
		if csrfCookie.Value == "" {
			t.Fatal("expected non-empty cookie value")
		}
		if !csrfCookie.HttpOnly {
			t.Errorf("expected HttpOnly cookie")
		}
		if !csrfCookie.Secure {
			t.Errorf("expected Secure cookie")
		}
		if csrfCookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("expected SameSite Lax, got %v", csrfCookie.SameSite)
		}
		if csrfCookie.Path != "/" {
			t.Errorf("expected Path /, got %s", csrfCookie.Path)
		}

		// Verify client token and cookie token are cryptographically valid together
		csrfKey, _ := crypto.DeriveCSRFKey([]byte("test-secret-at-least-32-bytes-long-123456"))
		if err := crypto.ValidateCSRF(csrfCookie.Value, body.CSRFToken, csrfKey); err != nil {
			t.Fatalf("ValidateCSRF failed: %v", err)
		}
	})

	t.Run("GET /csrf with existing valid cookie reuses raw token with new mask", func(t *testing.T) {
		// First call
		req1 := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		resp1, err := app.Test(req1)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		var body1 pkgfiber.CSRFResponse
		_ = json.NewDecoder(resp1.Body).Decode(&body1)
		resp1.Body.Close()

		var cookie1 *http.Cookie
		for _, c := range resp1.Cookies() {
			if c.Name == "__Host-kagi_csrf" {
				cookie1 = c
				break
			}
		}
		if cookie1 == nil {
			t.Fatal("expected cookie from first call")
		}

		// Second call sending existing cookie
		req2 := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		req2.AddCookie(cookie1)
		resp2, err := app.Test(req2)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		defer resp2.Body.Close()

		var body2 pkgfiber.CSRFResponse
		_ = json.NewDecoder(resp2.Body).Decode(&body2)

		// Second call masked token should be different string (due to fresh random XOR mask)
		if body1.CSRFToken == body2.CSRFToken {
			t.Errorf("expected masked token to differ across requests due to BREACH mitigation mask")
		}

		// But both tokens should validate against the same cookie!
		csrfKey, _ := crypto.DeriveCSRFKey([]byte("test-secret-at-least-32-bytes-long-123456"))
		if err := crypto.ValidateCSRF(cookie1.Value, body2.CSRFToken, csrfKey); err != nil {
			t.Fatalf("second masked token failed validation with original cookie: %v", err)
		}

		// And no new Set-Cookie should be returned when existing cookie is valid
		for _, c := range resp2.Cookies() {
			if c.Name == "__Host-kagi_csrf" {
				t.Errorf("unexpected Set-Cookie when valid cookie was provided")
			}
		}
	})

	t.Run("BREACH mitigation: multiple GET /csrf calls with same cookie yield different masked strings that all validate", func(t *testing.T) {
		// Get initial cookie and token
		initReq := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		initResp, err := app.Test(initReq)
		if err != nil {
			t.Fatalf("initial GET /csrf failed: %v", err)
		}
		defer initResp.Body.Close()

		var initCookie *http.Cookie
		for _, c := range initResp.Cookies() {
			if c.Name == "__Host-kagi_csrf" {
				initCookie = c
				break
			}
		}
		if initCookie == nil {
			t.Fatal("expected __Host-kagi_csrf cookie")
		}

		csrfKey, _ := crypto.DeriveCSRFKey([]byte("test-secret-at-least-32-bytes-long-123456"))
		tokens := make(map[string]bool)
		const iterations = 5

		for i := range iterations {
			req := httptest.NewRequest(http.MethodGet, "/csrf", nil)
			req.AddCookie(initCookie)
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("iteration %d failed: %v", i, err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("iteration %d returned status %d", i, resp.StatusCode)
			}

			var body pkgfiber.CSRFResponse
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("iteration %d failed to decode: %v", i, err)
			}
			resp.Body.Close()

			if tokens[body.CSRFToken] {
				t.Fatalf("iteration %d produced duplicate masked token: %s", i, body.CSRFToken)
			}
			tokens[body.CSRFToken] = true

			// Verify each masked token validates with the original cookie
			if err := crypto.ValidateCSRF(initCookie.Value, body.CSRFToken, csrfKey); err != nil {
				t.Fatalf("iteration %d token failed validation against original cookie: %v", i, err)
			}
		}
	})

	t.Run("GET /csrf with invalid cookie generates new cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-kagi_csrf",
			Value: "invalid-cookie-payload",
		})
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		var newCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "__Host-kagi_csrf" {
				newCookie = c
				break
			}
		}
		if newCookie == nil {
			t.Fatal("expected new __Host-kagi_csrf cookie to be set")
		}
		if newCookie.Value == "invalid-cookie-payload" {
			t.Fatal("expected cookie to be regenerated")
		}
	})

	t.Run("GET /csrf with InsecureDevMode: true generates kagi_csrf with Secure=false", func(t *testing.T) {
		devApp, _, _, _ := setupTestAppWithClock(t, nil,
			pkgfiber.WithCSRFDisabled(false),
			pkgfiber.WithInsecureDevMode(true),
		)

		req := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		resp, err := devApp.Test(req)
		if err != nil {
			t.Fatalf("GET /csrf in dev mode failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		var devCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "kagi_csrf" {
				devCookie = c
				break
			}
			if c.Name == "__Host-kagi_csrf" {
				t.Errorf("unexpected __Host- prefix in insecure dev mode")
			}
		}
		if devCookie == nil {
			t.Fatal("expected kagi_csrf cookie in insecure dev mode")
		}
		if devCookie.Secure {
			t.Errorf("expected Secure=false in insecure dev mode")
		}

		rawSetCookie := resp.Header.Get("Set-Cookie")
		if strings.Contains(rawSetCookie, "Secure") {
			t.Errorf("expected Set-Cookie not to contain Secure in dev mode, got: %s", rawSetCookie)
		}
	})
}

func TestCSRFMiddlewareMutatingEndpoints(t *testing.T) {
	app, auth, _, _ := setupTestAppWithClock(t, nil, pkgfiber.WithCSRFDisabled(false))

	// Register a test user
	_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "csrfuser@example.com",
		Password: "ValidPassword123!",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// 1. Obtain valid CSRF cookie and token
	csrfReq := httptest.NewRequest(http.MethodGet, "/csrf", nil)
	csrfResp, err := app.Test(csrfReq)
	if err != nil {
		t.Fatalf("GET /csrf failed: %v", err)
	}
	var csrfBody pkgfiber.CSRFResponse
	_ = json.NewDecoder(csrfResp.Body).Decode(&csrfBody)
	csrfResp.Body.Close()

	var csrfCookie *http.Cookie
	for _, c := range csrfResp.Cookies() {
		if c.Name == "__Host-kagi_csrf" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("missing CSRF cookie")
	}

	signInPayload := `{"email":"csrfuser@example.com","password":"ValidPassword123!"}`
	csrfKey, err := crypto.DeriveCSRFKey([]byte("test-secret-at-least-32-bytes-long-123456"))
	if err != nil {
		t.Fatalf("DeriveCSRFKey failed: %v", err)
	}

	// Generate mismatched token from different raw token
	otherKey, _ := crypto.DeriveCSRFKey([]byte("other-secret-at-least-32-bytes-long-123456"))
	otherRaw, _, _ := crypto.CreateCSRFCookie(otherKey)
	otherMasked, _ := crypto.MaskCSRFToken(otherRaw)

	// Generate cookie with invalid/tampered HMAC signature
	validRaw, _, _ := crypto.CreateCSRFCookie(csrfKey)
	fakeSig := make([]byte, 32)
	copy(fakeSig, []byte("invalid-hmac-signature-bytes-32b"))
	tamperedCookiePayload := base64.RawURLEncoding.EncodeToString(append(validRaw, fakeSig...))
	tamperedMasked, _ := crypto.MaskCSRFToken(validRaw)

	t.Run("Rejection scenarios", func(t *testing.T) {
		tests := []struct {
			name           string
			cookie         *http.Cookie
			headerKey      string
			headerVal      string
			expectedStatus int
			expectedError  string
		}{
			{
				name:           "missing CSRF cookie entirely",
				cookie:         nil,
				headerKey:      "X-CSRF-Token",
				headerVal:      csrfBody.CSRFToken,
				expectedStatus: http.StatusForbidden,
				expectedError:  "csrf_token_missing",
			},
			{
				name:           "empty CSRF cookie value",
				cookie:         &http.Cookie{Name: "__Host-kagi_csrf", Value: ""},
				headerKey:      "X-CSRF-Token",
				headerVal:      csrfBody.CSRFToken,
				expectedStatus: http.StatusForbidden,
				expectedError:  "csrf_token_missing",
			},
			{
				name:           "missing CSRF token (neither header nor form)",
				cookie:         csrfCookie,
				headerKey:      "",
				headerVal:      "",
				expectedStatus: http.StatusForbidden,
				expectedError:  "csrf_token_missing",
			},
			{
				name:           "empty CSRF token header",
				cookie:         csrfCookie,
				headerKey:      "X-CSRF-Token",
				headerVal:      "",
				expectedStatus: http.StatusForbidden,
				expectedError:  "csrf_token_missing",
			},
			{
				name:           "tampered cookie with invalid HMAC signature",
				cookie:         &http.Cookie{Name: "__Host-kagi_csrf", Value: tamperedCookiePayload},
				headerKey:      "X-CSRF-Token",
				headerVal:      tamperedMasked,
				expectedStatus: http.StatusForbidden,
				expectedError:  "csrf_token_invalid",
			},
			{
				name:           "malformed base64url cookie value",
				cookie:         &http.Cookie{Name: "__Host-kagi_csrf", Value: "!!!not-valid-base64url???"},
				headerKey:      "X-CSRF-Token",
				headerVal:      csrfBody.CSRFToken,
				expectedStatus: http.StatusForbidden,
				expectedError:  "csrf_token_invalid",
			},
			{
				name:           "truncated cookie value (less than 64 bytes)",
				cookie:         &http.Cookie{Name: "__Host-kagi_csrf", Value: base64.RawURLEncoding.EncodeToString([]byte("short-payload"))},
				headerKey:      "X-CSRF-Token",
				headerVal:      csrfBody.CSRFToken,
				expectedStatus: http.StatusForbidden,
				expectedError:  "csrf_token_invalid",
			},
			{
				name:           "malformed client token (invalid base64url)",
				cookie:         csrfCookie,
				headerKey:      "X-CSRF-Token",
				headerVal:      "!!!not-base64url???",
				expectedStatus: http.StatusForbidden,
				expectedError:  "csrf_token_invalid",
			},
			{
				name:           "truncated client token (decoded len != 64 bytes)",
				cookie:         csrfCookie,
				headerKey:      "X-CSRF-Token",
				headerVal:      base64.RawURLEncoding.EncodeToString([]byte("too-short-masked-token")),
				expectedStatus: http.StatusForbidden,
				expectedError:  "csrf_token_invalid",
			},
			{
				name:           "mismatched client token vs cookie raw token",
				cookie:         csrfCookie,
				headerKey:      "X-CSRF-Token",
				headerVal:      otherMasked,
				expectedStatus: http.StatusForbidden,
				expectedError:  "csrf_token_mismatch",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(signInPayload))
				req.Header.Set("Content-Type", "application/json")
				if tc.headerKey != "" {
					req.Header.Set(tc.headerKey, tc.headerVal)
				}
				if tc.cookie != nil {
					req.AddCookie(tc.cookie)
				}

				resp, err := app.Test(req)
				if err != nil {
					t.Fatalf("app.Test failed: %v", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode != tc.expectedStatus {
					t.Fatalf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
				}

				var errResp pkgfiber.ErrorResponse
				if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}
				if errResp.Error != tc.expectedError {
					t.Errorf("expected error %s, got %s", tc.expectedError, errResp.Error)
				}
			})
		}
	})

	t.Run("Acceptance scenarios", func(t *testing.T) {
		t.Run("POST /sign-in succeeds with valid X-CSRF-Token header", func(t *testing.T) {
			// Fetch fresh token and cookie
			tReq := httptest.NewRequest(http.MethodGet, "/csrf", nil)
			tResp, _ := app.Test(tReq)
			var tBody pkgfiber.CSRFResponse
			_ = json.NewDecoder(tResp.Body).Decode(&tBody)
			var tCookie *http.Cookie
			for _, c := range tResp.Cookies() {
				if c.Name == "__Host-kagi_csrf" {
					tCookie = c
					break
				}
			}
			tResp.Body.Close()

			req := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(signInPayload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", tBody.CSRFToken)
			req.AddCookie(tCookie)

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
			}
		})

		t.Run("POST /sign-in succeeds with valid X-Kagi-CSRF-Token fallback header", func(t *testing.T) {
			// Fetch fresh token and cookie
			tReq := httptest.NewRequest(http.MethodGet, "/csrf", nil)
			tResp, _ := app.Test(tReq)
			var tBody pkgfiber.CSRFResponse
			_ = json.NewDecoder(tResp.Body).Decode(&tBody)
			var tCookie *http.Cookie
			for _, c := range tResp.Cookies() {
				if c.Name == "__Host-kagi_csrf" {
					tCookie = c
					break
				}
			}
			tResp.Body.Close()

			req := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(signInPayload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Kagi-CSRF-Token", tBody.CSRFToken)
			req.AddCookie(tCookie)

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
			}
		})
	})
}

func TestCSRFFormExtraction(t *testing.T) {
	app, _ := setupTestApp(t, pkgfiber.WithCSRFDisabled(false))

	// Get CSRF cookie and token
	cReq := httptest.NewRequest(http.MethodGet, "/csrf", nil)
	cResp, err := app.Test(cReq)
	if err != nil {
		t.Fatalf("GET /csrf failed: %v", err)
	}
	var cBody pkgfiber.CSRFResponse
	_ = json.NewDecoder(cResp.Body).Decode(&cBody)
	var cCookie *http.Cookie
	for _, c := range cResp.Cookies() {
		if c.Name == "__Host-kagi_csrf" {
			cCookie = c
			break
		}
	}
	cResp.Body.Close()

	formData := url.Values{}
	formData.Set("email", "formuser@example.com")
	formData.Set("password", "ValidPassword123!")
	formData.Set("name", "Form User")
	formData.Set("_csrf", cBody.CSRFToken)

	req := httptest.NewRequest(http.MethodPost, "/sign-up", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cCookie)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created via form value extraction, got %d", resp.StatusCode)
	}
}

func TestCSRFTokenRotation(t *testing.T) {
	app, auth := setupTestApp(t, pkgfiber.WithCSRFDisabled(false))

	// Bootstrap CSRF token and cookie
	cReq := httptest.NewRequest(http.MethodGet, "/csrf", nil)
	cResp, _ := app.Test(cReq)
	var cBody pkgfiber.CSRFResponse
	_ = json.NewDecoder(cResp.Body).Decode(&cBody)
	var initialCookie *http.Cookie
	for _, c := range cResp.Cookies() {
		if c.Name == "__Host-kagi_csrf" {
			initialCookie = c
			break
		}
	}
	cResp.Body.Close()

	t.Run("POST /sign-up rotates CSRF cookie", func(t *testing.T) {
		signUpPayload := `{"email":"rotate_up@example.com","password":"ValidPassword123!","name":"Rotate Up"}`
		req := httptest.NewRequest(http.MethodPost, "/sign-up", bytes.NewBufferString(signUpPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", cBody.CSRFToken)
		req.AddCookie(initialCookie)

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d", resp.StatusCode)
		}

		var rotatedCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "__Host-kagi_csrf" {
				rotatedCookie = c
				break
			}
		}
		if rotatedCookie == nil {
			t.Fatal("expected CSRF cookie to be rotated on sign-up")
		}
		if rotatedCookie.Value == initialCookie.Value {
			t.Errorf("expected rotated cookie value to be different from initial cookie")
		}
	})

	t.Run("POST /sign-in rotates CSRF cookie", func(t *testing.T) {
		// Create a user in store
		_, err := auth.Credentials.SignUp(context.Background(), kagi.SignUpInput{
			Email:    "rotate_in@example.com",
			Password: "ValidPassword123!",
		})
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		// Fresh CSRF
		fReq := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		fResp, _ := app.Test(fReq)
		var fBody pkgfiber.CSRFResponse
		_ = json.NewDecoder(fResp.Body).Decode(&fBody)
		var beforeCookie *http.Cookie
		for _, c := range fResp.Cookies() {
			if c.Name == "__Host-kagi_csrf" {
				beforeCookie = c
				break
			}
		}
		fResp.Body.Close()

		signInPayload := `{"email":"rotate_in@example.com","password":"ValidPassword123!"}`
		req := httptest.NewRequest(http.MethodPost, "/sign-in", bytes.NewBufferString(signInPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", fBody.CSRFToken)
		req.AddCookie(beforeCookie)

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		var afterCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "__Host-kagi_csrf" {
				afterCookie = c
				break
			}
		}
		if afterCookie == nil {
			t.Fatal("expected CSRF cookie to be rotated on sign-in")
		}
		if afterCookie.Value == beforeCookie.Value {
			t.Errorf("expected rotated cookie value to differ from before-sign-in cookie")
		}
	})

	t.Run("POST /sign-out rotates CSRF cookie", func(t *testing.T) {
		// Fresh CSRF
		fReq := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		fResp, _ := app.Test(fReq)
		var fBody pkgfiber.CSRFResponse
		_ = json.NewDecoder(fResp.Body).Decode(&fBody)
		var beforeCookie *http.Cookie
		for _, c := range fResp.Cookies() {
			if c.Name == "__Host-kagi_csrf" {
				beforeCookie = c
				break
			}
		}
		fResp.Body.Close()

		req := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
		req.Header.Set("X-CSRF-Token", fBody.CSRFToken)
		req.AddCookie(beforeCookie)

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		var afterCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "__Host-kagi_csrf" {
				afterCookie = c
				break
			}
		}
		if afterCookie == nil {
			t.Fatal("expected CSRF cookie to be rotated on sign-out")
		}
		if afterCookie.Value == beforeCookie.Value {
			t.Errorf("expected rotated cookie value to differ from before-sign-out cookie")
		}
	})
}

func TestStandaloneNewCSRFMiddleware(t *testing.T) {
	masterSecret := "test-secret-at-least-32-bytes-long-123456"
	cfg := pkgfiber.DefaultConfig()
	cfg.CSRF.SecretKey = []byte(masterSecret)
	cfg.CSRF.Secure = false // dev mode for easier testing

	t.Run("WithCSRFFilter bypasses validation", func(t *testing.T) {
		app := fiber.New()
		csrfMid := pkgfiber.NewCSRF(nil, cfg, pkgfiber.WithCSRFFilter(func(c *fiber.Ctx) bool {
			return c.Path() == "/webhook"
		}))

		app.Post("/webhook", csrfMid, func(c *fiber.Ctx) error {
			return c.SendString("webhook ok")
		})
		app.Post("/api", csrfMid, func(c *fiber.Ctx) error {
			return c.SendString("api ok")
		})

		// /webhook should pass without CSRF
		req1 := httptest.NewRequest(http.MethodPost, "/webhook", nil)
		resp1, _ := app.Test(req1)
		if resp1.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for filtered route, got %d", resp1.StatusCode)
		}

		// /api should be rejected
		req2 := httptest.NewRequest(http.MethodPost, "/api", nil)
		resp2, _ := app.Test(req2)
		if resp2.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 for unfiltered route, got %d", resp2.StatusCode)
		}
	})

	t.Run("WithCSRFErrorHandler custom handler", func(t *testing.T) {
		app := fiber.New()
		csrfMid := pkgfiber.NewCSRF(nil, cfg, pkgfiber.WithCSRFErrorHandler(func(c *fiber.Ctx, err error) error {
			return c.Status(http.StatusTeapot).JSON(fiber.Map{
				"custom_error": err.Error(),
			})
		}))

		app.Post("/test", csrfMid, func(c *fiber.Ctx) error {
			return c.SendString("ok")
		})

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		resp, _ := app.Test(req)
		if resp.StatusCode != http.StatusTeapot {
			t.Fatalf("expected 418 Teapot from custom error handler, got %d", resp.StatusCode)
		}
	})

	t.Run("Safe methods exempt from CSRF", func(t *testing.T) {
		app := fiber.New()
		csrfMid := pkgfiber.NewCSRF(nil, cfg)

		app.Get("/safe", csrfMid, func(c *fiber.Ctx) error {
			return c.SendString("get ok")
		})
		app.Head("/safe", csrfMid, func(c *fiber.Ctx) error {
			return c.SendString("head ok")
		})
		app.Options("/safe", csrfMid, func(c *fiber.Ctx) error {
			return c.SendString("options ok")
		})
		app.Trace("/safe", csrfMid, func(c *fiber.Ctx) error {
			return c.SendString("trace ok")
		})

		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, fiber.MethodTrace} {
			req := httptest.NewRequest(method, "/safe", nil)
			resp, _ := app.Test(req)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected %s /safe to be exempt, got status %d", method, resp.StatusCode)
			}
		}
	})

	t.Run("Disabled CSRF allows mutating methods through", func(t *testing.T) {
		disCfg := cfg
		disCfg.CSRF.Disabled = true
		app := fiber.New()
		csrfMid := pkgfiber.NewCSRF(nil, disCfg)

		app.Post("/mutating", csrfMid, func(c *fiber.Ctx) error {
			return c.SendString("mutating ok")
		})

		req := httptest.NewRequest(http.MethodPost, "/mutating", nil)
		resp, _ := app.Test(req)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 when CSRF disabled, got %d", resp.StatusCode)
		}
	})

	t.Run("Handler.CSRF integrates with handler options and enforces CSRF", func(t *testing.T) {
		hApp, auth, _, _ := setupTestAppWithClock(t, nil, pkgfiber.WithCSRFDisabled(false))
		handler := pkgfiber.Register(hApp, auth, pkgfiber.WithCSRFDisabled(false))

		hApp.Post("/custom-protected", handler.CSRF(), func(c *fiber.Ctx) error {
			return c.SendString("protected ok")
		})

		// Request without CSRF token should fail
		req := httptest.NewRequest(http.MethodPost, "/custom-protected", nil)
		resp, _ := hApp.Test(req)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden without CSRF token, got %d", resp.StatusCode)
		}
	})
}
