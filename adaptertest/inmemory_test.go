package adaptertest_test

import (
	"context"
	"sync"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/adapter/memory"
)

// memoryUserStore wraps *memory.UserStore.
type memoryUserStore struct {
	*memory.UserStore
}

func newMemoryUserStore() *memoryUserStore {
	return &memoryUserStore{
		UserStore: memory.NewUserStore(),
	}
}

// memoryAccountStore wraps *memory.AccountStore.
type memoryAccountStore struct {
	*memory.AccountStore
}

func newMemoryAccountStore() *memoryAccountStore {
	return &memoryAccountStore{
		AccountStore: memory.NewAccountStore(),
	}
}

// memorySessionStore wraps *memory.SessionStore and tracks created sessions
// to allow deliberate mutation in failure-capture tests.
type memorySessionStore struct {
	*memory.SessionStore
	mu             sync.RWMutex
	storedSessions map[string]*kagi.Session // tokenHash -> session copy
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{
		SessionStore:   memory.NewSessionStore(),
		storedSessions: make(map[string]*kagi.Session),
	}
}

func (s *memorySessionStore) Create(ctx context.Context, sess *kagi.Session) error {
	if err := s.SessionStore.Create(ctx, sess); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := *sess
	s.storedSessions[sess.TokenHash] = &cloned
	return nil
}

func (s *memorySessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (*kagi.Session, error) {
	s.mu.RLock()
	sess, exists := s.storedSessions[tokenHash]
	s.mu.RUnlock()
	if exists {
		now := time.Now().UTC()
		if !sess.ExpiresAt.After(now) {
			return nil, kagi.ErrSessionNotFound
		}
		cloned := *sess
		return &cloned, nil
	}
	return s.SessionStore.GetByTokenHash(ctx, tokenHash)
}
func (s *memorySessionStore) Update(ctx context.Context, sess *kagi.Session) error {
	if err := s.SessionStore.Update(ctx, sess); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := *sess
	s.storedSessions[sess.TokenHash] = &cloned
	return nil
}

func (s *memorySessionStore) UpdateTokenHash(ctx context.Context, id, oldTokenHash, newTokenHash string, expiresAt time.Time) error {
	if err := s.SessionStore.UpdateTokenHash(ctx, id, oldTokenHash, newTokenHash, expiresAt); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, exists := s.storedSessions[oldTokenHash]; exists {
		delete(s.storedSessions, oldTokenHash)
		existing.TokenHash = newTokenHash
		existing.ExpiresAt = expiresAt
		existing.Pending2FA = false
		s.storedSessions[newTokenHash] = existing
	}
	return nil
}

func (s *memorySessionStore) DeleteByID(ctx context.Context, id string) (string, error) {
	th, err := s.SessionStore.DeleteByID(ctx, id)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.storedSessions, th)
	return th, nil
}

func (s *memorySessionStore) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	if err := s.SessionStore.DeleteByTokenHash(ctx, tokenHash); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.storedSessions, tokenHash)
	return nil
}
func (s *memorySessionStore) DeleteByUserID(ctx context.Context, userID string) ([]string, error) {
	deletedHashes, err := s.SessionStore.DeleteByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, th := range deletedHashes {
		delete(s.storedSessions, th)
	}
	return deletedHashes, nil
}

func (s *memorySessionStore) DeleteOthersByUserID(ctx context.Context, userID, currentSessionID string) ([]string, error) {
	deletedHashes, err := s.SessionStore.DeleteOthersByUserID(ctx, userID, currentSessionID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, th := range deletedHashes {
		delete(s.storedSessions, th)
	}
	return deletedHashes, nil
}

// memoryVerificationStore wraps *memory.VerificationStore and tracks created verifications
// to allow deliberate expiry bypass in failure-capture tests.
type memoryVerificationStore struct {
	*memory.VerificationStore
	mu            sync.RWMutex
	storedRecords map[string]*kagi.Verification // target:type -> verification copy
}

func newMemoryVerificationStore() *memoryVerificationStore {
	return &memoryVerificationStore{
		VerificationStore: memory.NewVerificationStore(),
		storedRecords:     make(map[string]*kagi.Verification),
	}
}

func (s *memoryVerificationStore) Create(ctx context.Context, v *kagi.Verification) error {
	if err := s.VerificationStore.Create(ctx, v); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := v.Target + ":" + string(v.Type)
	cloned := *v
	s.storedRecords[key] = &cloned
	return nil
}

func (s *memoryVerificationStore) Update(ctx context.Context, v *kagi.Verification) error {
	if err := s.VerificationStore.Update(ctx, v); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := v.Target + ":" + string(v.Type)
	cloned := *v
	s.storedRecords[key] = &cloned
	return nil
}

func (s *memoryVerificationStore) Delete(ctx context.Context, id string) error {
	if err := s.VerificationStore.Delete(ctx, id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, record := range s.storedRecords {
		if record.ID == id {
			delete(s.storedRecords, key)
			break
		}
	}
	return nil
}

// memoryRateLimitStore wraps *memory.RateLimitStore and tracks entries
// to allow deliberate lack of reset in failure-capture tests.
type memoryRateLimitStore struct {
	*memory.RateLimitStore
	mu            sync.Mutex
	storedEntries map[string]*kagi.RateLimitEntry
}

func newMemoryRateLimitStore() *memoryRateLimitStore {
	return &memoryRateLimitStore{
		RateLimitStore: memory.NewRateLimitStore(),
		storedEntries:  make(map[string]*kagi.RateLimitEntry),
	}
}
