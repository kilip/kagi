package kagi

import "time"

// Account represents a specific authentication method linked to a User (ADR-0004).
// A single User may have multiple Accounts (e.g., password and OAuth providers).
type Account struct {
	// ID is the unique string identifier for the account record (ADR-0011).
	ID string `json:"id"`

	// UserID is the foreign key identifier linking this account to a User (ADR-0011).
	UserID string `json:"user_id"`

	// Provider identifies the authentication provider (e.g., "credential", "google", "github").
	Provider string `json:"provider"`

	// ProviderAccountID is the unique identifier of the user within the external provider,
	// or the normalized email/username for credential accounts.
	ProviderAccountID string `json:"provider_account_id"`

	// PasswordHash stores the argon2id hashed password for "credential" provider.
	// Empty for OAuth accounts. Masked from JSON serialization for security.
	PasswordHash string `json:"-"`

	// AccessToken is the OAuth access token granted by the provider.
	// Empty for credential accounts. Masked from JSON serialization for security.
	AccessToken string `json:"-"`

	// RefreshToken is the OAuth refresh token granted by the provider, if available.
	// Empty for credential accounts. Masked from JSON serialization for security.
	RefreshToken string `json:"-"`

	// TokenExpiresAt is the expiration timestamp of the OAuth access token.
	// Nil for credential accounts or when no expiration is provided.
	// Masked from JSON serialization for security.
	TokenExpiresAt *time.Time `json:"-"`

	// CreatedAt is the timestamp when this authentication method was linked.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when this account record was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}
