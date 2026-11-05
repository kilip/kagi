package kagi

import (
	"context"
	"time"
)

// OAuthAction indicates whether an OAuth flow is signing in or linking an existing account.
type OAuthAction string

const (
	OAuthActionSignIn OAuthAction = "sign_in"
	OAuthActionLink   OAuthAction = "link"
)

// OAuthUser contains the normalized profile returned by an OAuth provider.
type OAuthUser struct {
	ProviderAccountID string
	Email             string
	EmailVerified     bool
	Name              string
	AccessToken       string
	RefreshToken      string
	TokenExpiresAt    *time.Time
}

// OAuthProvider defines the contract for OAuth 2.0 provider presets (ADR-0008).
type OAuthProvider interface {
	Name() string
	AuthCodeURL(state, codeChallenge string) string
	Exchange(ctx context.Context, code, codeVerifier string) (*OAuthUser, error)
}

// GenerateAuthURLInput specifies parameters for initiating an OAuth 2.0 flow.
type GenerateAuthURLInput struct {
	Provider string      `json:"provider"`
	Action   OAuthAction `json:"action"`
	UserID   string      `json:"user_id,omitempty"` // Bound if Action == OAuthActionLink
}

// OAuthAuthURLResult contains the authorization redirect URL, state, and PKCE verifier.
type OAuthAuthURLResult struct {
	AuthURL      string `json:"auth_url"`
	State        string `json:"state"`         // 43-character base64url random token
	CodeVerifier string `json:"code_verifier"` // 43-character base64url PKCE verifier
}

// OAuthCallbackInput provides the callback parameters and expected state for verification.
type OAuthCallbackInput struct {
	Provider      string      `json:"provider"`
	Code          string      `json:"code"`
	State         string      `json:"state"`
	ExpectedState string      `json:"expected_state"`
	CodeVerifier  string      `json:"code_verifier"`
	Action        OAuthAction `json:"action"`
	UserID        string      `json:"user_id,omitempty"`
	IPAddress     string      `json:"ip_address,omitempty"`
	UserAgent     string      `json:"user_agent,omitempty"`
}

// OAuthService manages OAuth 2.0 authorization URL generation, callbacks, and account unlinking.
type OAuthService struct {
	// unexported fields
}

// GenerateAuthURL builds the provider authorization URL with PKCE (S256) and a cryptographically random state.
func (s *OAuthService) GenerateAuthURL(ctx context.Context, in GenerateAuthURLInput) (*OAuthAuthURLResult, error) {
	return nil, nil
}

// HandleCallback verifies state, exchanges the authorization code using PKCE,
// enforces the ADR-0012 account linking policy, and returns an AuthResult.
func (s *OAuthService) HandleCallback(ctx context.Context, in OAuthCallbackInput) (*AuthResult, error) {
	return nil, nil
}

// Unlink disconnects an OAuth account, ensuring the user's last login method cannot be removed (ADR-0012).
func (s *OAuthService) Unlink(ctx context.Context, userID, provider string) error {
	return nil
}
