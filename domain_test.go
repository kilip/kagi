package kagi_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kilip/kagi"
)

func TestDomain_User_JSON(t *testing.T) {
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		user    kagi.User
		wantSub []string
	}{
		{
			name: "populated user serializes all fields",
			user: kagi.User{
				ID:               "usr_01j7abc123",
				Email:            "user@example.com",
				Name:             "Ada Lovelace",
				EmailVerified:    true,
				TwoFactorEnabled: true,
				CreatedAt:        now,
				UpdatedAt:        now,
			},
			wantSub: []string{
				`"id":"usr_01j7abc123"`,
				`"email":"user@example.com"`,
				`"name":"Ada Lovelace"`,
				`"email_verified":true`,
				`"two_factor_enabled":true`,
				`"created_at":"2026-11-06T10:00:00Z"`,
				`"updated_at":"2026-11-06T10:00:00Z"`,
			},
		},
		{
			name: "zero value user serializes defaults",
			user: kagi.User{},
			wantSub: []string{
				`"id":""`,
				`"email":""`,
				`"name":""`,
				`"email_verified":false`,
				`"two_factor_enabled":false`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.user)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			jsonStr := string(data)
			for _, sub := range tt.wantSub {
				if !strings.Contains(jsonStr, sub) {
					t.Errorf("json.Marshal output missing substring %q, got: %s", sub, jsonStr)
				}
			}

			// Verify round-trip unmarshaling
			var unmarshaled kagi.User
			if err := json.Unmarshal(data, &unmarshaled); err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}

			if unmarshaled.ID != tt.user.ID {
				t.Errorf("ID = %q, want %q", unmarshaled.ID, tt.user.ID)
			}
			if unmarshaled.Email != tt.user.Email {
				t.Errorf("Email = %q, want %q", unmarshaled.Email, tt.user.Email)
			}
			if unmarshaled.Name != tt.user.Name {
				t.Errorf("Name = %q, want %q", unmarshaled.Name, tt.user.Name)
			}
			if unmarshaled.EmailVerified != tt.user.EmailVerified {
				t.Errorf("EmailVerified = %v, want %v", unmarshaled.EmailVerified, tt.user.EmailVerified)
			}
			if unmarshaled.TwoFactorEnabled != tt.user.TwoFactorEnabled {
				t.Errorf("TwoFactorEnabled = %v, want %v", unmarshaled.TwoFactorEnabled, tt.user.TwoFactorEnabled)
			}
			if !unmarshaled.CreatedAt.Equal(tt.user.CreatedAt) {
				t.Errorf("CreatedAt = %v, want %v", unmarshaled.CreatedAt, tt.user.CreatedAt)
			}
			if !unmarshaled.UpdatedAt.Equal(tt.user.UpdatedAt) {
				t.Errorf("UpdatedAt = %v, want %v", unmarshaled.UpdatedAt, tt.user.UpdatedAt)
			}
		})
	}
}

func TestDomain_Account_JSONMaskingAndTamperProtection(t *testing.T) {
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)

	tests := []struct {
		name         string
		account      kagi.Account
		forbiddenSub []string
		expectedSub  []string
	}{
		{
			name: "credential account with password hash",
			account: kagi.Account{
				ID:                "acc_cred_123",
				UserID:            "usr_01j7abc123",
				Provider:          "credential",
				ProviderAccountID: "user@example.com",
				PasswordHash:      "$argon2id$v=19$m=65536,t=3,p=4$somehashvalue",
				CreatedAt:         now,
				UpdatedAt:         now,
			},
			forbiddenSub: []string{
				"password_hash",
				"PasswordHash",
				"somehashvalue",
				"access_token",
				"refresh_token",
				"token_expires_at",
			},
			expectedSub: []string{
				`"id":"acc_cred_123"`,
				`"user_id":"usr_01j7abc123"`,
				`"provider":"credential"`,
				`"provider_account_id":"user@example.com"`,
			},
		},
		{
			name: "oauth account with tokens and expiration",
			account: kagi.Account{
				ID:                "acc_oauth_456",
				UserID:            "usr_01j7abc123",
				Provider:          "google",
				ProviderAccountID: "google-uid-789",
				AccessToken:       "ya29.sensitive-oauth-access-token",
				RefreshToken:      "1//sensitive-oauth-refresh-token",
				TokenExpiresAt:    &expiresAt,
				CreatedAt:         now,
				UpdatedAt:         now,
			},
			forbiddenSub: []string{
				"access_token",
				"AccessToken",
				"ya29.sensitive-oauth-access-token",
				"refresh_token",
				"RefreshToken",
				"sensitive-oauth-refresh-token",
				"token_expires_at",
				"TokenExpiresAt",
				"password_hash",
			},
			expectedSub: []string{
				`"id":"acc_oauth_456"`,
				`"user_id":"usr_01j7abc123"`,
				`"provider":"google"`,
				`"provider_account_id":"google-uid-789"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.account)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			jsonStr := string(data)
			for _, forbidden := range tt.forbiddenSub {
				if strings.Contains(jsonStr, forbidden) {
					t.Errorf("json.Marshal output leaked sensitive string %q in: %s", forbidden, jsonStr)
				}
			}

			for _, expected := range tt.expectedSub {
				if !strings.Contains(jsonStr, expected) {
					t.Errorf("json.Marshal output missing expected string %q in: %s", expected, jsonStr)
				}
			}
		})
	}

	t.Run("deserialization anti-tamper ignores injected secrets", func(t *testing.T) {
		tamperedJSON := `{
			"id": "acc_tamper_789",
			"user_id": "usr_01j7abc123",
			"provider": "credential",
			"provider_account_id": "hacker@example.com",
			"password_hash": "$argon2id$injected_password_hash",
			"PasswordHash": "$argon2id$injected_password_hash_pascal",
			"access_token": "injected_access_token",
			"AccessToken": "injected_access_token_pascal",
			"refresh_token": "injected_refresh_token",
			"RefreshToken": "injected_refresh_token_pascal",
			"token_expires_at": "2026-11-06T12:00:00Z",
			"TokenExpiresAt": "2026-11-06T12:00:00Z"
		}`

		var acc kagi.Account
		if err := json.Unmarshal([]byte(tamperedJSON), &acc); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		if acc.ID != "acc_tamper_789" {
			t.Errorf("ID = %q, want acc_tamper_789", acc.ID)
		}
		if acc.UserID != "usr_01j7abc123" {
			t.Errorf("UserID = %q, want usr_01j7abc123", acc.UserID)
		}
		if acc.Provider != "credential" {
			t.Errorf("Provider = %q, want credential", acc.Provider)
		}
		if acc.ProviderAccountID != "hacker@example.com" {
			t.Errorf("ProviderAccountID = %q, want hacker@example.com", acc.ProviderAccountID)
		}

		// Critical anti-tamper assertions: sensitive fields must remain zero values
		if acc.PasswordHash != "" {
			t.Errorf("PasswordHash was populated during unmarshaling: %q", acc.PasswordHash)
		}
		if acc.AccessToken != "" {
			t.Errorf("AccessToken was populated during unmarshaling: %q", acc.AccessToken)
		}
		if acc.RefreshToken != "" {
			t.Errorf("RefreshToken was populated during unmarshaling: %q", acc.RefreshToken)
		}
		if acc.TokenExpiresAt != nil {
			t.Errorf("TokenExpiresAt was populated during unmarshaling: %v", acc.TokenExpiresAt)
		}
	})
}

func TestDomain_Session_JSONMaskingAndTamperProtection(t *testing.T) {
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	expiresAt := now.Add(7 * 24 * time.Hour)

	tests := []struct {
		name         string
		session      kagi.Session
		forbiddenSub []string
		expectedSub  []string
		omittedSub   []string
	}{
		{
			name: "populated active session",
			session: kagi.Session{
				ID:         "sess_01j7abc999",
				UserID:     "usr_01j7abc123",
				TokenHash:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				ExpiresAt:  expiresAt,
				IPAddress:  "203.0.113.195",
				UserAgent:  "Mozilla/5.0 (X11; Linux x86_64)",
				Pending2FA: false,
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			forbiddenSub: []string{
				"token_hash",
				"TokenHash",
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			expectedSub: []string{
				`"id":"sess_01j7abc999"`,
				`"user_id":"usr_01j7abc123"`,
				`"ip_address":"203.0.113.195"`,
				`"user_agent":"Mozilla/5.0 (X11; Linux x86_64)"`,
				`"pending_2fa":false`,
			},
		},
		{
			name: "session with empty ip and user agent omits keys via omitempty",
			session: kagi.Session{
				ID:         "sess_minimal_001",
				UserID:     "usr_01j7abc123",
				TokenHash:  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				ExpiresAt:  expiresAt,
				IPAddress:  "",
				UserAgent:  "",
				Pending2FA: true,
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			forbiddenSub: []string{
				"token_hash",
				"TokenHash",
				"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			},
			expectedSub: []string{
				`"id":"sess_minimal_001"`,
				`"user_id":"usr_01j7abc123"`,
				`"pending_2fa":true`,
			},
			omittedSub: []string{
				`"ip_address"`,
				`"user_agent"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.session)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			jsonStr := string(data)
			for _, forbidden := range tt.forbiddenSub {
				if strings.Contains(jsonStr, forbidden) {
					t.Errorf("json.Marshal leaked sensitive substring %q in: %s", forbidden, jsonStr)
				}
			}

			for _, expected := range tt.expectedSub {
				if !strings.Contains(jsonStr, expected) {
					t.Errorf("json.Marshal missing expected substring %q in: %s", expected, jsonStr)
				}
			}

			for _, omitted := range tt.omittedSub {
				if strings.Contains(jsonStr, omitted) {
					t.Errorf("json.Marshal should omit %q due to omitempty, but found in: %s", omitted, jsonStr)
				}
			}
		})
	}

	t.Run("deserialization anti-tamper ignores injected token hash", func(t *testing.T) {
		tamperedJSON := `{
			"id": "sess_tamper_001",
			"user_id": "usr_01j7abc123",
			"token_hash": "malicious_injected_token_hash",
			"TokenHash": "malicious_injected_token_hash_pascal",
			"pending_2fa": true
		}`

		var sess kagi.Session
		if err := json.Unmarshal([]byte(tamperedJSON), &sess); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		if sess.ID != "sess_tamper_001" {
			t.Errorf("ID = %q, want sess_tamper_001", sess.ID)
		}
		if sess.UserID != "usr_01j7abc123" {
			t.Errorf("UserID = %q, want usr_01j7abc123", sess.UserID)
		}
		if !sess.Pending2FA {
			t.Errorf("Pending2FA = false, want true")
		}

		// TokenHash must remain empty
		if sess.TokenHash != "" {
			t.Errorf("TokenHash was populated during unmarshaling: %q", sess.TokenHash)
		}
	})
}

func TestDomain_Verification_JSONMaskingAndTamperProtection(t *testing.T) {
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	expiresAt := now.Add(10 * time.Minute)

	tests := []struct {
		name         string
		verification kagi.Verification
		forbiddenSub []string
		expectedSub  []string
	}{
		{
			name: "login otp verification",
			verification: kagi.Verification{
				ID:        "ver_01j7login123",
				Target:    "user@example.com",
				Type:      kagi.VerificationTypeLogin,
				CodeHash:  "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
				ExpiresAt: expiresAt,
				Attempts:  1,
				CreatedAt: now,
				UpdatedAt: now,
			},
			forbiddenSub: []string{
				"code_hash",
				"CodeHash",
				"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
			},
			expectedSub: []string{
				`"id":"ver_01j7login123"`,
				`"target":"user@example.com"`,
				`"type":"login"`,
				`"attempts":1`,
			},
		},
		{
			name: "two factor verification",
			verification: kagi.Verification{
				ID:        "ver_01j7twofactor456",
				Target:    "user@example.com",
				Type:      kagi.VerificationTypeTwoFactor,
				CodeHash:  "twofactorcodehashvalue",
				ExpiresAt: expiresAt,
				Attempts:  0,
				CreatedAt: now,
				UpdatedAt: now,
			},
			forbiddenSub: []string{
				"code_hash",
				"CodeHash",
				"twofactorcodehashvalue",
			},
			expectedSub: []string{
				`"id":"ver_01j7twofactor456"`,
				`"target":"user@example.com"`,
				`"type":"two_factor"`,
				`"attempts":0`,
			},
		},
		{
			name: "email verify verification",
			verification: kagi.Verification{
				ID:        "ver_01j7email789",
				Target:    "newuser@example.com",
				Type:      kagi.VerificationTypeEmailVerify,
				CodeHash:  "emailverifycodehashvalue",
				ExpiresAt: expiresAt,
				Attempts:  0,
				CreatedAt: now,
				UpdatedAt: now,
			},
			forbiddenSub: []string{
				"code_hash",
				"CodeHash",
				"emailverifycodehashvalue",
			},
			expectedSub: []string{
				`"id":"ver_01j7email789"`,
				`"target":"newuser@example.com"`,
				`"type":"email_verify"`,
			},
		},
		{
			name: "password reset verification",
			verification: kagi.Verification{
				ID:        "ver_01j7reset012",
				Target:    "forgot@example.com",
				Type:      kagi.VerificationTypePasswordReset,
				CodeHash:  "passwordresetcodehashvalue",
				ExpiresAt: expiresAt,
				Attempts:  2,
				CreatedAt: now,
				UpdatedAt: now,
			},
			forbiddenSub: []string{
				"code_hash",
				"CodeHash",
				"passwordresetcodehashvalue",
			},
			expectedSub: []string{
				`"id":"ver_01j7reset012"`,
				`"target":"forgot@example.com"`,
				`"type":"password_reset"`,
				`"attempts":2`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.verification)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			jsonStr := string(data)
			for _, forbidden := range tt.forbiddenSub {
				if strings.Contains(jsonStr, forbidden) {
					t.Errorf("json.Marshal leaked sensitive substring %q in: %s", forbidden, jsonStr)
				}
			}

			for _, expected := range tt.expectedSub {
				if !strings.Contains(jsonStr, expected) {
					t.Errorf("json.Marshal missing expected substring %q in: %s", expected, jsonStr)
				}
			}

			var unmarshaled kagi.Verification
			if err := json.Unmarshal(data, &unmarshaled); err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}

			if unmarshaled.ID != tt.verification.ID {
				t.Errorf("ID = %q, want %q", unmarshaled.ID, tt.verification.ID)
			}
			if unmarshaled.Target != tt.verification.Target {
				t.Errorf("Target = %q, want %q", unmarshaled.Target, tt.verification.Target)
			}
			if unmarshaled.Type != tt.verification.Type {
				t.Errorf("Type = %q, want %q", unmarshaled.Type, tt.verification.Type)
			}
			if unmarshaled.Attempts != tt.verification.Attempts {
				t.Errorf("Attempts = %d, want %d", unmarshaled.Attempts, tt.verification.Attempts)
			}
		})
	}

	t.Run("deserialization anti-tamper ignores injected code hash", func(t *testing.T) {
		tamperedJSON := `{
			"id": "ver_tamper_001",
			"target": "target@example.com",
			"type": "login",
			"code_hash": "malicious_injected_code_hash",
			"CodeHash": "malicious_injected_code_hash_pascal",
			"attempts": 3
		}`

		var ver kagi.Verification
		if err := json.Unmarshal([]byte(tamperedJSON), &ver); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		if ver.ID != "ver_tamper_001" {
			t.Errorf("ID = %q, want ver_tamper_001", ver.ID)
		}
		if ver.Target != "target@example.com" {
			t.Errorf("Target = %q, want target@example.com", ver.Target)
		}
		if ver.Type != kagi.VerificationTypeLogin {
			t.Errorf("Type = %q, want login", ver.Type)
		}
		if ver.Attempts != 3 {
			t.Errorf("Attempts = %d, want 3", ver.Attempts)
		}

		// CodeHash must remain empty
		if ver.CodeHash != "" {
			t.Errorf("CodeHash was populated during unmarshaling: %q", ver.CodeHash)
		}
	})
}
