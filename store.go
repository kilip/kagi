package kagi

import (
	"context"
	"time"
)

// UserStore defines the storage port for User entities (ADR-0007).
type UserStore interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
}

// AccountStore defines the storage port for Account entities (ADR-0007).
type AccountStore interface {
	Create(ctx context.Context, account *Account) error
	GetByProvider(ctx context.Context, provider, providerAccountID string) (*Account, error)
	ListByUserID(ctx context.Context, userID string) ([]*Account, error)
	Update(ctx context.Context, account *Account) error
	Delete(ctx context.Context, id string) error
	CountByUserID(ctx context.Context, userID string) (int, error)
}

// SessionStore defines the primary storage port for Session entities (ADR-0007, ADR-0014).
// Deletion methods return the affected token_hashes to enable deterministic Redis cache invalidation.
type SessionStore interface {
	Create(ctx context.Context, session *Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	Update(ctx context.Context, session *Session) error
	UpdateTokenHash(ctx context.Context, id, oldTokenHash, newTokenHash string, expiresAt time.Time) error
	DeleteByID(ctx context.Context, id string) (deletedTokenHash string, err error)
	DeleteByTokenHash(ctx context.Context, tokenHash string) error
	DeleteByUserID(ctx context.Context, userID string) (deletedTokenHashes []string, err error)
	DeleteOthersByUserID(ctx context.Context, userID, currentSessionID string) (deletedTokenHashes []string, err error)
	ListByUserID(ctx context.Context, userID string) ([]*Session, error)
	DeleteExpired(ctx context.Context, batchSize int) (int, error)
}

// VerificationStore defines the storage port for OTP and verification tokens (ADR-0007).
type VerificationStore interface {
	Create(ctx context.Context, v *Verification) error
	Get(ctx context.Context, target string, vType VerificationType) (*Verification, error)
	Update(ctx context.Context, v *Verification) error
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context, batchSize int) (int, error)
}

// RateLimitEntry represents a rate limiting counter.
type RateLimitEntry struct {
	Key       string
	Count     int
	ExpiresAt time.Time
}

// RateLimitStore defines the database-backed rate limit port (ADR-0004, ADR-0007).
// Allows Kagi to operate with rate limiting without requiring Redis.
type RateLimitStore interface {
	Increment(ctx context.Context, key string, window time.Duration) (count int, err error)
	DeleteExpired(ctx context.Context, batchSize int) (int, error)
}
