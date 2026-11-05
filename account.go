package kagi

import "time"

// Account represents a specific authentication method linked to a User.
// A single User may have multiple Accounts (e.g., password and OAuth providers).
type Account struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	Provider          string     `json:"provider"` // e.g., "credential", "google", "github"
	ProviderAccountID string     `json:"provider_account_id"`
	PasswordHash      string     `json:"-"`
	AccessToken       string     `json:"-"`
	RefreshToken      string     `json:"-"`
	TokenExpiresAt    *time.Time `json:"-"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}
