package memory

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/internal/clock"
)

// SessionStore provides an in-memory implementation of kagi.SessionStore.
type SessionStore struct {
	mu           sync.RWMutex
	seq          uint64
	clock        clock.Clock
	sessionsByID map[string]*kagi.Session
	sessionsByTH map[string]*kagi.Session // tokenHash -> session
}

var _ kagi.SessionStore = (*SessionStore)(nil)

// NewSessionStore constructs a new in-memory SessionStore.
func NewSessionStore(opts ...Option) *SessionStore {
	cfg := defaultOptions()
	for _, opt := range opts {
		opt(cfg)
	}
	return &SessionStore{
		clock:        cfg.clock,
		sessionsByID: make(map[string]*kagi.Session),
		sessionsByTH: make(map[string]*kagi.Session),
	}
}

// Create persists a new Session entity in storage.
func (s *SessionStore) Create(ctx context.Context, session *kagi.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if session == nil {
		return kagi.ErrSessionNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id := strconv.FormatUint(atomic.AddUint64(&s.seq, 1), 10)
	now := s.clock.Now().UTC()
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}
	if session.UpdatedAt.IsZero() {
		session.UpdatedAt = now
	}
	session.ID = id

	cloned := cloneSession(session)
	s.sessionsByID[id] = cloned
	s.sessionsByTH[session.TokenHash] = cloned

	return nil
}

// GetByTokenHash retrieves an active session by its SHA-256 token hash.
func (s *SessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (*kagi.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, exists := s.sessionsByTH[tokenHash]
	if !exists {
		return nil, kagi.ErrSessionNotFound
	}

	now := s.clock.Now().UTC()
	if !sess.ExpiresAt.After(now) {
		return nil, kagi.ErrSessionNotFound
	}

	return cloneSession(sess), nil
}

// Update updates mutable fields of an active session.
func (s *SessionStore) Update(ctx context.Context, session *kagi.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if session == nil {
		return kagi.ErrSessionNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.sessionsByID[session.ID]
	if !exists {
		return kagi.ErrSessionNotFound
	}

	now := s.clock.Now().UTC()
	if !existing.ExpiresAt.After(now) {
		return kagi.ErrSessionNotFound
	}

	cloned := cloneSession(session)
	cloned.CreatedAt = existing.CreatedAt // Preserve CreatedAt absolute ceiling guard
	if cloned.UpdatedAt.IsZero() || cloned.UpdatedAt.Equal(existing.UpdatedAt) {
		cloned.UpdatedAt = now
	}

	if existing.TokenHash != cloned.TokenHash {
		delete(s.sessionsByTH, existing.TokenHash)
	}

	s.sessionsByID[cloned.ID] = cloned
	s.sessionsByTH[cloned.TokenHash] = cloned

	return nil
}

// UpdateTokenHash performs an atomic Compare-And-Swap (CAS) update of the session's token hash.
func (s *SessionStore) UpdateTokenHash(ctx context.Context, id, oldTokenHash, newTokenHash string, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.sessionsByID[id]
	if !exists {
		return kagi.ErrSessionNotFound
	}

	if existing.TokenHash != oldTokenHash {
		return kagi.ErrSessionNotFound
	}

	now := s.clock.Now().UTC()
	if !existing.ExpiresAt.After(now) {
		return kagi.ErrSessionNotFound
	}

	delete(s.sessionsByTH, oldTokenHash)

	cloned := cloneSession(existing)
	cloned.TokenHash = newTokenHash
	cloned.ExpiresAt = expiresAt
	cloned.Pending2FA = false // Mandatory 2FA graduation reset (ADR-0014)
	cloned.UpdatedAt = now
	// CreatedAt remains untouched

	s.sessionsByID[id] = cloned
	s.sessionsByTH[newTokenHash] = cloned

	return nil
}

// DeleteByID deletes an active session identified by its string ID.
func (s *SessionStore) DeleteByID(ctx context.Context, id string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.sessionsByID[id]
	if !exists {
		return "", kagi.ErrSessionNotFound
	}

	now := s.clock.Now().UTC()
	if !existing.ExpiresAt.After(now) {
		return "", kagi.ErrSessionNotFound
	}

	th := existing.TokenHash
	delete(s.sessionsByID, id)
	delete(s.sessionsByTH, th)

	return th, nil
}

// DeleteByTokenHash deletes an active session identified by its SHA-256 token hash.
func (s *SessionStore) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.sessionsByTH[tokenHash]
	if !exists {
		return kagi.ErrSessionNotFound
	}

	now := s.clock.Now().UTC()
	if !existing.ExpiresAt.After(now) {
		return kagi.ErrSessionNotFound
	}

	delete(s.sessionsByID, existing.ID)
	delete(s.sessionsByTH, tokenHash)

	return nil
}

// DeleteByUserID revokes all sessions belonging to the specified user.
func (s *SessionStore) DeleteByUserID(ctx context.Context, userID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var deletedHashes []string
	for id, sess := range s.sessionsByID {
		if sess.UserID == userID {
			deletedHashes = append(deletedHashes, sess.TokenHash)
			delete(s.sessionsByTH, sess.TokenHash)
			delete(s.sessionsByID, id)
		}
	}

	if len(deletedHashes) == 0 {
		return nil, nil // Bulk no-op returns nil, nil (ADR-0014)
	}

	return deletedHashes, nil
}

// DeleteOthersByUserID revokes all sessions belonging to userID except currentSessionID.
func (s *SessionStore) DeleteOthersByUserID(ctx context.Context, userID, currentSessionID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var deletedHashes []string
	for id, sess := range s.sessionsByID {
		if sess.UserID == userID && id != currentSessionID {
			deletedHashes = append(deletedHashes, sess.TokenHash)
			delete(s.sessionsByTH, sess.TokenHash)
			delete(s.sessionsByID, id)
		}
	}

	if len(deletedHashes) == 0 {
		return nil, nil // Bulk no-op returns nil, nil (ADR-0014)
	}

	return deletedHashes, nil
}

// ListByUserID retrieves all active, unexpired, non-pending sessions belonging to userID.
func (s *SessionStore) ListByUserID(ctx context.Context, userID string) ([]*kagi.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.clock.Now().UTC()
	result := make([]*kagi.Session, 0)
	for _, sess := range s.sessionsByID {
		// Filter: user_id = $userID AND expires_at > now AND pending_2fa = false (ADR-0014)
		if sess.UserID == userID && sess.ExpiresAt.After(now) && !sess.Pending2FA {
			result = append(result, cloneSession(sess))
		}
	}

	return result, nil
}

// DeleteExpired removes expired sessions from storage in bounded batches.
func (s *SessionStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now().UTC()
	var toDelete []string
	for id, sess := range s.sessionsByID {
		if !sess.ExpiresAt.After(now) {
			toDelete = append(toDelete, id)
			if len(toDelete) >= batchSize {
				break
			}
		}
	}

	for _, id := range toDelete {
		sess := s.sessionsByID[id]
		delete(s.sessionsByTH, sess.TokenHash)
		delete(s.sessionsByID, id)
	}

	return len(toDelete), nil
}

func cloneSession(s *kagi.Session) *kagi.Session {
	if s == nil {
		return nil
	}
	c := *s
	return &c
}
