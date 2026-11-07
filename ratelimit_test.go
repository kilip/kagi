package kagi_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/kilip/kagi"
)

func TestRateLimit_DefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := kagi.DefaultRateLimitConfig()

	if cfg.Disabled {
		t.Errorf("expected Disabled to be false, got true")
	}

	const wantEmailLimit = 5
	const wantEmailWindow = 15 * time.Minute
	if cfg.SignInEmail.Limit != wantEmailLimit {
		t.Errorf("SignInEmail.Limit = %d, want %d", cfg.SignInEmail.Limit, wantEmailLimit)
	}
	if cfg.SignInEmail.Window != wantEmailWindow {
		t.Errorf("SignInEmail.Window = %v, want %v", cfg.SignInEmail.Window, wantEmailWindow)
	}

	const wantIPLimit = 30
	const wantIPWindow = 15 * time.Minute
	if cfg.SignInIP.Limit != wantIPLimit {
		t.Errorf("SignInIP.Limit = %d, want %d", cfg.SignInIP.Limit, wantIPLimit)
	}
	if cfg.SignInIP.Window != wantIPWindow {
		t.Errorf("SignInIP.Window = %v, want %v", cfg.SignInIP.Window, wantIPWindow)
	}

	if err := kagi.ValidateRateLimitConfig(cfg); err != nil {
		t.Errorf("ValidateRateLimitConfig(DefaultRateLimitConfig()) returned unexpected error: %v", err)
	}
}

func TestRateLimit_ValidateConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       kagi.RateLimitConfig
		wantErr   bool
		targetErr error
	}{
		{
			name:    "valid default configuration",
			cfg:     kagi.DefaultRateLimitConfig(),
			wantErr: false,
		},
		{
			name: "valid custom configuration",
			cfg: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{
					Limit:  10,
					Window: 5 * time.Minute,
				},
				SignInIP: kagi.LimitRule{
					Limit:  100,
					Window: 10 * time.Minute,
				},
			},
			wantErr: false,
		},
		{
			name: "disabled config ignores invalid rules",
			cfg: kagi.RateLimitConfig{
				Disabled: true,
				SignInEmail: kagi.LimitRule{
					Limit:  -10,
					Window: -5 * time.Minute,
				},
				SignInIP: kagi.LimitRule{
					Limit:  50,
					Window: 0,
				},
			},
			wantErr: false,
		},
		{
			name: "disabled config with zero fields",
			cfg: kagi.RateLimitConfig{
				Disabled: true,
			},
			wantErr: false,
		},
		{
			name: "zero limit with positive window is valid (disabled rule)",
			cfg: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{
					Limit:  0,
					Window: 15 * time.Minute,
				},
				SignInIP: kagi.LimitRule{
					Limit:  0,
					Window: 15 * time.Minute,
				},
			},
			wantErr: false,
		},
		{
			name: "zero limit with zero window is valid (disabled rule)",
			cfg: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{
					Limit:  0,
					Window: 0,
				},
				SignInIP: kagi.LimitRule{
					Limit:  0,
					Window: 0,
				},
			},
			wantErr: false,
		},
		{
			name: "negative SignInEmail limit returns ErrInvalidConfig",
			cfg: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{
					Limit:  -1,
					Window: 15 * time.Minute,
				},
				SignInIP: kagi.LimitRule{
					Limit:  30,
					Window: 15 * time.Minute,
				},
			},
			wantErr:   true,
			targetErr: kagi.ErrInvalidConfig,
		},
		{
			name: "negative SignInIP limit returns ErrInvalidConfig",
			cfg: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{
					Limit:  5,
					Window: 15 * time.Minute,
				},
				SignInIP: kagi.LimitRule{
					Limit:  -1,
					Window: 15 * time.Minute,
				},
			},
			wantErr:   true,
			targetErr: kagi.ErrInvalidConfig,
		},
		{
			name: "negative SignInEmail window returns ErrInvalidConfig",
			cfg: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{
					Limit:  5,
					Window: -1 * time.Minute,
				},
				SignInIP: kagi.LimitRule{
					Limit:  30,
					Window: 15 * time.Minute,
				},
			},
			wantErr:   true,
			targetErr: kagi.ErrInvalidConfig,
		},
		{
			name: "negative SignInIP window returns ErrInvalidConfig",
			cfg: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{
					Limit:  5,
					Window: 15 * time.Minute,
				},
				SignInIP: kagi.LimitRule{
					Limit:  30,
					Window: -10 * time.Second,
				},
			},
			wantErr:   true,
			targetErr: kagi.ErrInvalidConfig,
		},
		{
			name: "positive SignInEmail limit with zero window returns ErrInvalidConfig",
			cfg: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{
					Limit:  5,
					Window: 0,
				},
				SignInIP: kagi.LimitRule{
					Limit:  30,
					Window: 15 * time.Minute,
				},
			},
			wantErr:   true,
			targetErr: kagi.ErrInvalidConfig,
		},
		{
			name: "positive SignInIP limit with zero window returns ErrInvalidConfig",
			cfg: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{
					Limit:  5,
					Window: 15 * time.Minute,
				},
				SignInIP: kagi.LimitRule{
					Limit:  30,
					Window: 0,
				},
			},
			wantErr:   true,
			targetErr: kagi.ErrInvalidConfig,
		},
		{
			name: "zero limit with negative window returns ErrInvalidConfig",
			cfg: kagi.RateLimitConfig{
				SignInEmail: kagi.LimitRule{
					Limit:  0,
					Window: -1 * time.Minute,
				},
				SignInIP: kagi.LimitRule{
					Limit:  30,
					Window: 15 * time.Minute,
				},
			},
			wantErr:   true,
			targetErr: kagi.ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := kagi.ValidateRateLimitConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRateLimitConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.targetErr != nil && !errors.Is(err, tt.targetErr) {
				t.Errorf("ValidateRateLimitConfig() error = %v, want targetErr %v", err, tt.targetErr)
			}
		})
	}
}

func TestRateLimitKeyIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantKey string
	}{
		{
			name:    "standard ipv4",
			input:   "192.168.1.1",
			wantKey: "rl:ip:192.168.1.1",
		},
		{
			name:    "ipv4 with leading and trailing whitespace",
			input:   "  10.0.0.1\t\n",
			wantKey: "rl:ip:10.0.0.1",
		},
		{
			name:    "standard ipv6",
			input:   "2001:db8::1",
			wantKey: "rl:ip:2001:db8::1",
		},
		{
			name:    "empty ip",
			input:   "",
			wantKey: "rl:ip:",
		},
		{
			name:    "whitespace only ip",
			input:   "   ",
			wantKey: "rl:ip:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := kagi.RateLimitKeyIP(tt.input)
			if got != tt.wantKey {
				t.Errorf("RateLimitKeyIP(%q) = %q, want %q", tt.input, got, tt.wantKey)
			}
		})
	}
}

func TestRateLimitKeyAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantKey string
	}{
		{
			name:    "standard lowercase email",
			input:   "user@example.com",
			wantKey: "rl:auth:user@example.com",
		},
		{
			name:    "mixed case email converted to lowercase",
			input:   "User.Name+Tag@EXAMPLE.COM",
			wantKey: "rl:auth:user.name+tag@example.com",
		},
		{
			name:    "email with whitespace trimmed and lowercased",
			input:   "  Bob@Example.COM \r\n",
			wantKey: "rl:auth:bob@example.com",
		},
		{
			name:    "empty email",
			input:   "",
			wantKey: "rl:auth:",
		},
		{
			name:    "whitespace only email",
			input:   "   ",
			wantKey: "rl:auth:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := kagi.RateLimitKeyAuth(tt.input)
			if got != tt.wantKey {
				t.Errorf("RateLimitKeyAuth(%q) = %q, want %q", tt.input, got, tt.wantKey)
			}
		})
	}
}

func TestRateLimitPrefixConstants(t *testing.T) {
	t.Parallel()

	if kagi.RateLimitPrefixIP != "rl:ip:" {
		t.Errorf("RateLimitPrefixIP = %q, want %q", kagi.RateLimitPrefixIP, "rl:ip:")
	}
	if kagi.RateLimitPrefixAuth != "rl:auth:" {
		t.Errorf("RateLimitPrefixAuth = %q, want %q", kagi.RateLimitPrefixAuth, "rl:auth:")
	}
}

func TestRateLimitConfig_JSON(t *testing.T) {
	t.Parallel()

	orig := kagi.DefaultRateLimitConfig()
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var restored kagi.RateLimitConfig
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if restored.Disabled != orig.Disabled {
		t.Errorf("Disabled = %v, want %v", restored.Disabled, orig.Disabled)
	}
	if restored.SignInEmail.Limit != orig.SignInEmail.Limit || restored.SignInEmail.Window != orig.SignInEmail.Window {
		t.Errorf("SignInEmail = %+v, want %+v", restored.SignInEmail, orig.SignInEmail)
	}
	if restored.SignInIP.Limit != orig.SignInIP.Limit || restored.SignInIP.Window != orig.SignInIP.Window {
		t.Errorf("SignInIP = %+v, want %+v", restored.SignInIP, orig.SignInIP)
	}
}
