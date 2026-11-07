// Package kagi provides core domain types, storage ports, and authentication services.
//
// # Primary Storage Ports (ADR-0007)
//
// State persistence in Kagi is completely decoupled from concrete storage engines, ORMs,
// and database drivers. The core module interacts with persistence layers solely through
// the primary storage port interfaces defined in this file:
//   - UserStore: Persistence port for User identity entities (ADR-0004, ADR-0011).
//   - AccountStore: Multi-method authentication credentials and OAuth links (ADR-0004, ADR-0012).
//   - SessionStore: Primary storage for opaque session state, token rotation, and revocation (ADR-0004, ADR-0014).
//   - VerificationStore: Ephemeral verification tokens and OTP challenges (ADR-0004, ADR-0005).
//   - RateLimitStore: Database-backed atomic rate limiting for Redis-free deployments (ADR-0004).
//
// All primary stores must implement these interfaces with identical operational semantics
// regardless of the underlying database engine (PostgreSQL, MySQL, SQLite) or adapter
// implementation (ent, gorm, sqlc, in-memory).
//
// # Expiry Contract (ADR-0010)
//
// Correctness of expiration handling NEVER depends on background cleanup routines:
//   - Expiry on Read: All read operations on time-bound entities (SessionStore.GetByTokenHash,
//     VerificationStore.Get) MUST verify that the entity has not expired (WHERE expires_at > now).
//     Expired records are treated as non-existent and must return ErrSessionNotFound (or ErrSessionExpired)
//     and ErrVerificationNotFound respectively.
//   - Idempotent Batched Cleanup: DeleteExpired methods on SessionStore, VerificationStore,
//     and RateLimitStore delete expired records in bounded batches (controlled by batchSize)
//     to prevent long table locks and replication lag.
//
// # Atomicity and Concurrency Contracts (ADR-0014)
//
// Storage adapters must guarantee atomic execution for critical security-sensitive state transitions:
//   - SessionStore.UpdateTokenHash enforces Compare-And-Swap (CAS) semantics on token rotation
//     and 2FA graduation, guaranteeing that concurrent rotation attempts fail safely.
//   - RateLimitStore.Increment enforces atomic fixed-window reset/increment without race conditions.
//
// # Deterministic Cache Invalidation Contract (ADR-0014)
//
// When configured alongside SecondaryStorage (Redis), all session mutations commit to the primary
// SessionStore first, and eviction occurs second. Deletion methods (DeleteByID, DeleteByUserID,
// DeleteOthersByUserID) return the deleted token_hash values to enable deterministic eviction
// from Redis without requiring secondary user index sets.
package kagi

import (
	"context"
	"time"
)

// UserStore defines the primary persistence port for User identity entities (ADR-0004, ADR-0007).
//
// Storage adapters (e.g. ent, gorm, sqlc, in-memory) must convert between the string IDs used in
// the domain model and native database column types (UUID, integer, ULID) per ADR-0011. Adapters
// must also map database-level constraint violations and missing records to domain sentinel errors
// (ErrUserNotFound, ErrEmailAlreadyExists).
//
//go:generate mockgen -destination=mock/user_store.go -package=mock github.com/kilip/kagi UserStore
type UserStore interface {
	// Create inserts a new User identity record into storage.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - user: the User entity to persist. The adapter assigns a generated string ID
	//     to user.ID (ADR-0011) and populates CreatedAt and UpdatedAt with the persistence timestamp.
	//
	// Return values:
	//   - nil on successful insertion.
	//   - ErrEmailAlreadyExists if a user with the same email already exists (unique constraint violation).
	//   - An error wrapping the failure reason if the database operation fails.
	Create(ctx context.Context, user *User) error

	// GetByID retrieves a User entity by its unique string identifier (ADR-0011).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - id: the unique string identifier of the user.
	//
	// Return values:
	//   - (*User, nil) if a user matching id is found.
	//   - (nil, ErrUserNotFound) if no user matches id or if id cannot be parsed to the adapter's native ID type.
	//   - (nil, error) if the database query fails.
	GetByID(ctx context.Context, id string) (*User, error)

	// GetByEmail retrieves a User entity by its normalized primary email address.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - email: the normalized primary email address of the user.
	//
	// Return values:
	//   - (*User, nil) if a user matching email is found.
	//   - (nil, ErrUserNotFound) if no user matches email.
	//   - (nil, error) if the database query fails.
	GetByEmail(ctx context.Context, email string) (*User, error)

	// Update persists modifications to an existing User identity record.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - user: the User entity containing modified fields (Name, Email, EmailVerified, TwoFactorEnabled, UpdatedAt).
	//
	// Return values:
	//   - nil on successful update.
	//   - ErrUserNotFound if no user matches user.ID.
	//   - ErrEmailAlreadyExists if updating the email conflicts with an existing user.
	//   - An error wrapping the failure reason if the database operation fails.
	Update(ctx context.Context, user *User) error

	// Delete permanently removes the User identity record identified by id (ADR-0011).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - id: the unique string identifier of the user to delete.
	//
	// Return values:
	//   - nil on successful deletion.
	//   - ErrUserNotFound if no user matches id.
	//   - An error wrapping the failure reason if the database operation fails.
	Delete(ctx context.Context, id string) error
}

// AccountStore defines the primary persistence port for Account entities representing linked
// authentication methods (ADR-0004, ADR-0007, ADR-0012).
//
// A single User may have multiple linked Accounts (e.g. local credentials with password_hash,
// Google OAuth, GitHub OAuth). Adapters must enforce uniqueness on (provider, provider_account_id)
// and map errors to ErrAccountNotFound or ErrAccountAlreadyExists.
//
//go:generate mockgen -destination=mock/account_store.go -package=mock github.com/kilip/kagi AccountStore
type AccountStore interface {
	// Create persists a new Account authentication method linked to account.UserID.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - account: the Account entity to insert. The adapter assigns a unique string ID
	//     to account.ID (ADR-0011) and populates CreatedAt and UpdatedAt.
	//
	// Return values:
	//   - nil on successful insertion.
	//   - ErrAccountAlreadyExists if an account already exists with the same (provider, provider_account_id).
	//   - An error wrapping the failure reason if the database operation fails.
	Create(ctx context.Context, account *Account) error

	// GetByProvider retrieves the Account matching the given authentication provider and provider-specific account ID.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - provider: provider identifier (e.g. "credential", "google", "github").
	//   - providerAccountID: provider-scoped account identifier (e.g. OAuth subject ID or credential email).
	//
	// Return values:
	//   - (*Account, nil) if a matching account is found.
	//   - (nil, ErrAccountNotFound) if no account matches the provider and providerAccountID pair.
	//   - (nil, error) if the database query fails.
	GetByProvider(ctx context.Context, provider, providerAccountID string) (*Account, error)

	// ListByUserID retrieves all Account authentication methods linked to the given userID (ADR-0012).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - userID: the string identifier of the user whose accounts to list (ADR-0011).
	//
	// Return values:
	//   - ([]*Account, nil) containing all linked accounts (empty slice []*Account{} and nil error if user has no accounts).
	//   - (nil, error) if the database query fails.
	ListByUserID(ctx context.Context, userID string) ([]*Account, error)

	// Update persists modifications to an existing Account record (e.g. password_hash, OAuth tokens, token_expires_at).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - account: the Account entity containing updated fields matching account.ID.
	//
	// Return values:
	//   - nil on successful update.
	//   - ErrAccountNotFound if no account matches account.ID.
	//   - ErrAccountAlreadyExists if updating provider/providerAccountID conflicts with an existing account.
	//   - An error wrapping the failure reason if the database operation fails.
	Update(ctx context.Context, account *Account) error

	// Delete permanently removes the Account record identified by id (ADR-0011).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - id: the unique string identifier of the account to delete.
	//
	// Return values:
	//   - nil on successful deletion.
	//   - ErrAccountNotFound if no account matches id.
	//   - An error wrapping the failure reason if the database operation fails.
	Delete(ctx context.Context, id string) error

	// CountByUserID returns the total number of linked Account authentication methods for userID.
	// Used by core domain services to enforce ADR-0012 (preventing unlinking a user's sole authentication method).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - userID: the string identifier of the user (ADR-0011).
	//
	// Return values:
	//   - (count, nil) where count >= 0 (returns 0, nil when no accounts exist for userID).
	//   - (0, error) if the database query fails.
	CountByUserID(ctx context.Context, userID string) (int, error)
}

// SessionStore defines the primary storage port for Session entities (ADR-0004, ADR-0007, ADR-0010, ADR-0014).
//
// SessionStore provides opaque session state persistence, sliding renewal, atomic token rotation
// via Compare-And-Swap (CAS), and device revocation.
//
// Expiry Contract (ADR-0010):
// Correctness never relies on background cleanup. All read operations (GetByTokenHash, ListByUserID)
// and atomic mutation operations (UpdateTokenHash) must strictly verify that the session has not
// expired (expires_at > now). Expired sessions are treated as non-existent.
//
// Deterministic Cache Invalidation Contract (ADR-0014):
// When configured alongside SecondaryStorage (Redis), all session mutations commit to the primary
// SessionStore first, and eviction occurs second. Deletion methods (DeleteByID, DeleteByUserID,
// DeleteOthersByUserID) return the deleted token_hash values to enable deterministic eviction
// from Redis without requiring secondary user index sets.
//
//go:generate mockgen -destination=mock/session_store.go -package=mock github.com/kilip/kagi SessionStore
type SessionStore interface {
	// Create persists a new Session entity in storage.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - session: the Session entity to insert. Must contain UserID, TokenHash (64-character
	//     lowercase hex SHA-256 digest), ExpiresAt, and Pending2FA. The adapter assigns a unique
	//     string ID to session.ID (ADR-0011) and populates CreatedAt and UpdatedAt.
	//
	// Return values:
	//   - nil on successful creation.
	//   - An error wrapping the failure reason if the database operation fails.
	Create(ctx context.Context, session *Session) error

	// GetByTokenHash retrieves an active session by its SHA-256 token hash (ADR-0014).
	//
	// Expiry Contract (ADR-0010):
	// The underlying query MUST enforce that the session has not expired:
	//   WHERE token_hash = $tokenHash AND expires_at > $now
	//
	// Return values:
	//   - (*Session, nil) if an active, unexpired session matching tokenHash is found.
	//   - (nil, ErrSessionNotFound) or (nil, ErrSessionExpired) if the session is missing or expired (expires_at <= now).
	//   - (nil, error) if the database query fails.
	GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error)

	// Update updates mutable fields of an active session (expires_at on sliding renewal,
	// ip_address, user_agent, updated_at).
	//
	// Semantics & Invariants (ADR-0014):
	// Must preserve the original CreatedAt timestamp to prevent bypassing the absolute session
	// timeout ceiling. Must verify that the session has not expired (expires_at > now).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - session: the Session entity containing updated fields matching session.ID.
	//
	// Return values:
	//   - nil on successful update.
	//   - ErrSessionNotFound if no active, unexpired session exists matching session.ID.
	//   - An error wrapping the failure reason if the database operation fails.
	Update(ctx context.Context, session *Session) error

	// UpdateTokenHash performs an atomic Compare-And-Swap (CAS) update of the session's token hash,
	// extends its expiration timestamp, and resets the 2FA pending flag (ADR-0014).
	//
	// Atomic CAS Contract:
	// The update MUST execute as a single atomic query matching the existing session ID, old token hash,
	// and ensuring the session is still active:
	//   WHERE id = $id AND token_hash = $oldTokenHash AND expires_at > $now
	//
	// Mutations Applied:
	// Upon matching, the adapter atomically updates:
	//   1. token_hash = $newTokenHash
	//   2. expires_at = $expiresAt
	//   3. pending_2fa = false (mandatory 2FA graduation session fixation guard per ADR-0014)
	//   4. updated_at = $now
	// The original created_at timestamp MUST remain untouched to preserve the absolute lifetime ceiling.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - id: unique string identifier of the session record (ADR-0011).
	//   - oldTokenHash: the expected current 64-char hex SHA-256 token hash (CAS guard).
	//   - newTokenHash: the replacement 64-char hex SHA-256 token hash.
	//   - expiresAt: the new expiration timestamp computed from idle/absolute timeouts.
	//
	// Return values:
	//   - nil if the row was atomically matched and updated.
	//   - ErrSessionNotFound if zero rows were updated (indicating session not found, oldTokenHash mismatch,
	//     or session already expired).
	//   - An error wrapping the failure reason if the database operation fails.
	UpdateTokenHash(ctx context.Context, id, oldTokenHash, newTokenHash string, expiresAt time.Time) error

	// DeleteByID deletes an active session identified by its string ID (ADR-0011, ADR-0014).
	//
	// Cache Eviction & Expiry Contract:
	// Returns the deleted session's token_hash to enable immediate eviction from SecondaryStorage (Redis).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - id: unique string identifier of the session to delete.
	//
	// Return values:
	//   - (deletedTokenHash, nil) with the 64-char hex token hash upon successful deletion.
	//   - ("", ErrSessionNotFound) when missing or expired (expires_at <= now).
	//   - ("", error) if the database operation fails.
	DeleteByID(ctx context.Context, id string) (deletedTokenHash string, err error)

	// DeleteByTokenHash deletes an active session identified by its SHA-256 token hash (ADR-0014).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - tokenHash: the 64-character lowercase hex SHA-256 token hash to delete.
	//
	// Return values:
	//   - nil on successful deletion.
	//   - ErrSessionNotFound if no active, unexpired session matches tokenHash.
	//   - An error wrapping the failure reason if the database operation fails.
	DeleteByTokenHash(ctx context.Context, tokenHash string) error

	// DeleteByUserID revokes all sessions belonging to the specified user (ADR-0014).
	// Used on SignOutAll and unauthenticated password reset.
	//
	// Cache Invalidation & Return Semantics:
	// Returns the slice of all deleted token_hash values to enable bulk eviction from SecondaryStorage (Redis).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - userID: the string identifier of the user (ADR-0011).
	//
	// Return values:
	//   - (deletedTokenHashes, nil) containing all revoked token hashes.
	//   - (nil, nil) when no sessions match userID (bulk delete no-op returns nil, nil).
	//   - (nil, error) if the database operation fails.
	DeleteByUserID(ctx context.Context, userID string) (deletedTokenHashes []string, err error)

	// DeleteOthersByUserID revokes all sessions belonging to userID except currentSessionID (ADR-0014).
	// Used during password change, 2FA toggle, account unlinking, or "sign out other devices".
	//
	// Cache Invalidation & Return Semantics:
	// Returns the slice of deleted token_hash values for other sessions to evict them from SecondaryStorage.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - userID: the string identifier of the user (ADR-0011).
	//   - currentSessionID: the session ID to retain untouched.
	//
	// Return values:
	//   - (deletedTokenHashes, nil) containing revoked token hashes.
	//   - (nil, nil) when no other sessions match (bulk delete no-op returns nil, nil).
	//   - (nil, error) if the database operation fails.
	DeleteOthersByUserID(ctx context.Context, userID, currentSessionID string) (deletedTokenHashes []string, err error)

	// ListByUserID retrieves all active, unexpired, non-pending sessions belonging to userID (ADR-0014).
	// Used for device and session management interfaces.
	//
	// Expiry & State Filter (ADR-0010, ADR-0014):
	// The query MUST filter:
	//   WHERE user_id = $userID AND expires_at > $now AND pending_2fa = false
	// Security rule: Token hashes must never be exposed in client-facing contexts.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - userID: the string identifier of the user (ADR-0011).
	//
	// Return values:
	//   - ([]*Session, nil) containing active sessions (empty slice []*Session{} and nil error if none found).
	//   - (nil, error) if the database query fails.
	ListByUserID(ctx context.Context, userID string) ([]*Session, error)

	// DeleteExpired removes expired sessions from storage in bounded batches (ADR-0010).
	//
	// Batched Cleanup Contract:
	// Idempotently deletes rows matching:
	//   WHERE expires_at <= $now
	// limited to at most batchSize rows to avoid long table locks on high-write databases.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - batchSize: maximum number of expired session rows to delete in this execution.
	//
	// Return values:
	//   - (deletedCount, nil) where deletedCount >= 0 is the number of rows removed in this batch (0, nil if none expired).
	//   - (0, error) if the database operation fails.
	DeleteExpired(ctx context.Context, batchSize int) (int, error)
}

// VerificationStore defines the primary storage port for ephemeral OTP codes and verification tokens (ADR-0004, ADR-0005, ADR-0007).
//
// VerificationStore persists hashed verification tokens for passwordless login, two-factor authentication,
// email ownership verification, and password reset.
//
// Expiry Contract (ADR-0010):
// Correctness never depends on background cleanup. Read operations (Get) MUST verify that
// expires_at > now. Expired verification records are treated as non-existent and must return ErrVerificationNotFound.
//
//go:generate mockgen -destination=mock/verification_store.go -package=mock github.com/kilip/kagi VerificationStore
type VerificationStore interface {
	// Create persists a new Verification record in storage (ADR-0005).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - v: the Verification entity to insert. Must contain Target, Type, CodeHash (never plaintext code),
	//     and ExpiresAt. The adapter assigns a string ID to v.ID (ADR-0011) and populates CreatedAt and UpdatedAt.
	//
	// Return values:
	//   - nil on successful creation.
	//   - An error wrapping the failure reason if the database operation fails.
	Create(ctx context.Context, v *Verification) error

	// Get retrieves the active, unexpired Verification record for the given target and type (ADR-0005, ADR-0010).
	//
	// Expiry Contract (ADR-0010):
	// The query MUST verify that the record has not expired:
	//   WHERE target = $target AND type = $vType AND expires_at > $now
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - target: recipient identifier (e.g. email address).
	//   - vType: purpose of the verification challenge (ADR-0005).
	//
	// Return values:
	//   - (*Verification, nil) if an active, unexpired verification record is found.
	//   - (nil, ErrVerificationNotFound) if no record exists or if the record has expired (expires_at <= now).
	//   - (nil, error) if the database query fails.
	Get(ctx context.Context, target string, vType VerificationType) (*Verification, error)

	// Update updates mutable fields of an existing Verification record (e.g. incrementing Attempts or refreshing UpdatedAt).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - v: the Verification entity containing updated values matching v.ID.
	//
	// Return values:
	//   - nil on successful update.
	//   - ErrVerificationNotFound if no active, unexpired verification record matches v.ID.
	//   - An error wrapping the failure reason if the database operation fails.
	Update(ctx context.Context, v *Verification) error

	// Delete permanently removes a Verification record by its string ID after consumption or invalidation (ADR-0011).
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - id: the unique string identifier of the verification record to delete.
	//
	// Return values:
	//   - nil on successful deletion.
	//   - ErrVerificationNotFound if no verification record matches id.
	//   - An error wrapping the failure reason if the database operation fails.
	Delete(ctx context.Context, id string) error

	// DeleteExpired removes expired verification records from storage in bounded batches (ADR-0010).
	//
	// Batched Cleanup Contract:
	// Idempotently deletes rows matching:
	//   WHERE expires_at <= $now
	// limited to at most batchSize rows to prevent database table lock contention.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - batchSize: maximum number of expired verification rows to delete in this execution.
	//
	// Return values:
	//   - (deletedCount, nil) where deletedCount >= 0 is the number of rows removed in this batch (0, nil if none expired).
	//   - (0, error) if the database operation fails.
	DeleteExpired(ctx context.Context, batchSize int) (int, error)
}

// RateLimitEntry represents a rate limiting counter bucket in database-backed storage (ADR-0004, ADR-0010).
type RateLimitEntry struct {
	// Key is the unique identifier for the rate limit counter (e.g. "rl:ip:<ip>", "rl:auth:<email>").
	Key string `json:"key"`

	// Count is the current request count within the active time window.
	Count int `json:"count"`

	// ExpiresAt is the timestamp when the current rate limit window expires (ADR-0010).
	ExpiresAt time.Time `json:"expires_at"`
}

// RateLimitStore defines the database-backed rate limiting port (ADR-0004, ADR-0007).
//
// Enables Kagi to enforce rate limits reliably without requiring Redis (SecondaryStorage).
// Adapters must implement atomic fixed-window upsert semantics.
//
//go:generate mockgen -destination=mock/rate_limit_store.go -package=mock github.com/kilip/kagi RateLimitStore
type RateLimitStore interface {
	// Increment atomically increments the request counter for key within a fixed time window (ADR-0004).
	//
	// Atomic Fixed-Window Semantics:
	// Adapters MUST execute the increment as an atomic upsert operation (e.g., INSERT ... ON CONFLICT DO UPDATE):
	//   1. Reset / initialize when missing:
	//      If no entry exists for key, inserts a new record with count = 1 and expires_at = now + window.
	//   2. Reset when expired (expires_at <= now):
	//      If an entry exists and has expired, resets the record with count = 1 and sets a new expiration window expires_at = now + window.
	//   3. Increment when active (expires_at > now):
	//      If an entry exists and is active, increments count = count + 1 while strictly preserving the existing expires_at timestamp.
	//
	// Atomicity Requirement:
	// The check, increment, or reset must execute as a single atomic operation in the underlying storage engine
	// to prevent race conditions under high concurrent request volume.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - key: the unique rate limiting bucket key.
	//   - window: the duration of the fixed rate limiting window.
	//
	// Return values:
	//   - (count, nil) where count >= 1 is the updated counter value after increment or reset.
	//   - (0, error) if the atomic database operation fails.
	Increment(ctx context.Context, key string, window time.Duration) (count int, err error)

	// DeleteExpired removes expired rate limit counter entries in bounded batches (ADR-0010).
	//
	// Batched Cleanup Contract:
	// Idempotently deletes rows matching:
	//   WHERE expires_at <= $now
	// limited to at most batchSize rows to avoid table locks.
	//
	// Parameters:
	//   - ctx: context for cancellation and timeout control.
	//   - batchSize: maximum number of expired rate limit rows to delete in this execution.
	//
	// Return values:
	//   - (deletedCount, nil) where deletedCount >= 0 is the number of rows removed in this batch (0, nil if none expired).
	//   - (0, error) if the database operation fails.
	DeleteExpired(ctx context.Context, batchSize int) (int, error)
}
