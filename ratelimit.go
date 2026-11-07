package kagi

import (
	"time"

	"github.com/kilip/kagi/internal/ratelimit"
)

const (
	// RateLimitPrefixIP is the bucket key prefix for IP address rate limiting (ADR-0004).
	RateLimitPrefixIP = ratelimit.PrefixIP

	// RateLimitPrefixAuth is the bucket key prefix for authentication identifier rate limiting (ADR-0004).
	RateLimitPrefixAuth = ratelimit.PrefixAuth
)

// LimitRule defines rate limit parameters for a specific bucket (e.g. per-email or per-IP).
type LimitRule struct {
	// Limit is the maximum allowed requests within Window.
	// A Limit of 0 or negative disables rate limiting for this rule.
	Limit int `json:"limit"`

	// Window is the duration of the fixed rate limiting window.
	Window time.Duration `json:"window"`
}

// RateLimitConfig defines rate limiting policies across Kagi authentication flows (ADR-0004, ADR-0007).
type RateLimitConfig struct {
	// Disabled disables all rate limiting when true.
	Disabled bool `json:"disabled"`

	// SignInEmail defines rate limiting per email address for sign-in attempts (ADR-0004).
	// Default: 5 attempts per 15 minutes (OWASP targeted brute-force protection).
	SignInEmail LimitRule `json:"sign_in_email"`

	// SignInIP defines rate limiting per IP address for sign-in attempts (ADR-0004).
	// Default: 30 attempts per 15 minutes (OWASP credential stuffing / spraying protection across shared gateways).
	SignInIP LimitRule `json:"sign_in_ip"`
}

// DefaultRateLimitConfig returns safe, OWASP-recommended rate limit defaults.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		SignInEmail: LimitRule{
			Limit:  5,
			Window: 15 * time.Minute,
		},
		SignInIP: LimitRule{
			Limit:  30,
			Window: 15 * time.Minute,
		},
	}
}

// ValidateRateLimitConfig validates rate limiting policy rules (ADR-0004, ADR-0007).
// If cfg.Disabled is true, validation succeeds immediately.
// Otherwise, negative limits, negative window durations, and positive limits
// with a zero window duration are rejected with ErrInvalidConfig.
func ValidateRateLimitConfig(cfg RateLimitConfig) error {
	if cfg.Disabled {
		return nil
	}
	if err := validateLimitRule(cfg.SignInEmail); err != nil {
		return err
	}
	if err := validateLimitRule(cfg.SignInIP); err != nil {
		return err
	}
	return nil
}

func validateLimitRule(rule LimitRule) error {
	if rule.Limit < 0 || rule.Window < 0 {
		return ErrInvalidConfig
	}
	if rule.Limit > 0 && rule.Window == 0 {
		return ErrInvalidConfig
	}
	return nil
}

// RateLimitKeyIP formats an IP address into a standardized rate limit bucket key (ADR-0004).
// Leading and trailing whitespace is trimmed.
func RateLimitKeyIP(ip string) string {
	return ratelimit.KeyIP(ip)
}

// RateLimitKeyAuth formats an authentication identifier (e.g. email) into a standardized rate limit bucket key (ADR-0004).
// Leading and trailing whitespace is trimmed, and the string is converted to lowercase for case-insensitive bucketing.
func RateLimitKeyAuth(email string) string {
	return ratelimit.KeyAuth(email)
}
