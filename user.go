package kagi

import "time"

// User represents an authenticated identity in Kagi (ADR-0004).
type User struct {
	// ID is the unique string identifier for the user (ADR-0011).
	ID string `json:"id"`

	// Email is the primary email address of the user.
	Email string `json:"email"`

	// Name is the display name or full name of the user.
	Name string `json:"name"`

	// EmailVerified indicates whether the user's primary email address has been verified.
	EmailVerified bool `json:"email_verified"`

	// TwoFactorEnabled indicates whether two-factor authentication is enforced for this user.
	TwoFactorEnabled bool `json:"two_factor_enabled"`

	// CreatedAt is the timestamp when the user identity was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when the user identity was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}
