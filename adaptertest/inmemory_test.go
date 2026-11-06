package adaptertest_test

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kilip/kagi"
)

type memoryUserStore struct {
	mu           sync.RWMutex
	seq          uint64
	usersByID    map[string]*kagi.User
	usersByEmail map[string]*kagi.User
}

func newMemoryUserStore() *memoryUserStore {
	return &memoryUserStore{
		usersByID:    make(map[string]*kagi.User),
		usersByEmail: make(map[string]*kagi.User),
	}
}

func (s *memoryUserStore) Create(ctx context.Context, u *kagi.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.usersByEmail[u.Email]; exists {
		return kagi.ErrEmailAlreadyExists
	}

	id := strconv.FormatUint(atomic.AddUint64(&s.seq, 1), 10)
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = now
	}
	u.ID = id

	cloned := *u
	s.usersByID[id] = &cloned
	s.usersByEmail[u.Email] = &cloned
	return nil
}

func (s *memoryUserStore) GetByID(ctx context.Context, id string) (*kagi.User, error) {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return nil, kagi.ErrUserNotFound
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	u, exists := s.usersByID[id]
	if !exists {
		return nil, kagi.ErrUserNotFound
	}
	cloned := *u
	return &cloned, nil
}

func (s *memoryUserStore) GetByEmail(ctx context.Context, email string) (*kagi.User, error) {
	if email == "" {
		return nil, kagi.ErrUserNotFound
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	u, exists := s.usersByEmail[email]
	if !exists {
		return nil, kagi.ErrUserNotFound
	}
	cloned := *u
	return &cloned, nil
}

func (s *memoryUserStore) Update(ctx context.Context, u *kagi.User) error {
	if _, err := strconv.ParseUint(u.ID, 10, 64); err != nil {
		return kagi.ErrUserNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.usersByID[u.ID]
	if !exists {
		return kagi.ErrUserNotFound
	}

	if u.Email != existing.Email {
		if _, emailTaken := s.usersByEmail[u.Email]; emailTaken {
			return kagi.ErrEmailAlreadyExists
		}
		delete(s.usersByEmail, existing.Email)
	}

	now := time.Now().UTC()
	if u.UpdatedAt.IsZero() || u.UpdatedAt.Equal(existing.UpdatedAt) {
		u.UpdatedAt = now
	}

	cloned := *u
	s.usersByID[u.ID] = &cloned
	s.usersByEmail[u.Email] = &cloned
	return nil
}

func (s *memoryUserStore) Delete(ctx context.Context, id string) error {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return kagi.ErrUserNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.usersByID[id]
	if !exists {
		return kagi.ErrUserNotFound
	}

	delete(s.usersByID, id)
	delete(s.usersByEmail, existing.Email)
	return nil
}

type memoryAccountStore struct {
	mu               sync.RWMutex
	seq              uint64
	accountsByID     map[string]*kagi.Account
	accountsByProv   map[string]*kagi.Account
	accountsByUserID map[string][]*kagi.Account
}

func newMemoryAccountStore() *memoryAccountStore {
	return &memoryAccountStore{
		accountsByID:     make(map[string]*kagi.Account),
		accountsByProv:   make(map[string]*kagi.Account),
		accountsByUserID: make(map[string][]*kagi.Account),
	}
}

func accountKey(provider, providerAccountID string) string {
	return provider + ":" + providerAccountID
}

func (s *memoryAccountStore) Create(ctx context.Context, a *kagi.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := accountKey(a.Provider, a.ProviderAccountID)
	if _, exists := s.accountsByProv[key]; exists {
		return kagi.ErrAccountAlreadyExists
	}

	id := strconv.FormatUint(atomic.AddUint64(&s.seq, 1), 10)
	now := time.Now().UTC()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	if a.UpdatedAt.IsZero() {
		a.UpdatedAt = now
	}
	a.ID = id

	cloned := *a
	s.accountsByID[id] = &cloned
	s.accountsByProv[key] = &cloned
	s.accountsByUserID[a.UserID] = append(s.accountsByUserID[a.UserID], &cloned)
	return nil
}

func (s *memoryAccountStore) GetByProvider(ctx context.Context, provider, providerAccountID string) (*kagi.Account, error) {
	if provider == "" || providerAccountID == "" {
		return nil, kagi.ErrAccountNotFound
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key := accountKey(provider, providerAccountID)
	a, exists := s.accountsByProv[key]
	if !exists {
		return nil, kagi.ErrAccountNotFound
	}
	cloned := *a
	return &cloned, nil
}

func (s *memoryAccountStore) ListByUserID(ctx context.Context, userID string) ([]*kagi.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := s.accountsByUserID[userID]
	if len(list) == 0 {
		return []*kagi.Account{}, nil
	}

	result := make([]*kagi.Account, len(list))
	for i, a := range list {
		cloned := *a
		result[i] = &cloned
	}
	return result, nil
}

func (s *memoryAccountStore) CountByUserID(ctx context.Context, userID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.accountsByUserID[userID]), nil
}

func (s *memoryAccountStore) Update(ctx context.Context, a *kagi.Account) error {
	if _, err := strconv.ParseUint(a.ID, 10, 64); err != nil {
		return kagi.ErrAccountNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.accountsByID[a.ID]
	if !exists {
		return kagi.ErrAccountNotFound
	}

	oldKey := accountKey(existing.Provider, existing.ProviderAccountID)
	newKey := accountKey(a.Provider, a.ProviderAccountID)
	if oldKey != newKey {
		if _, taken := s.accountsByProv[newKey]; taken {
			return kagi.ErrAccountAlreadyExists
		}
		delete(s.accountsByProv, oldKey)
	}

	now := time.Now().UTC()
	if a.UpdatedAt.IsZero() || a.UpdatedAt.Equal(existing.UpdatedAt) {
		a.UpdatedAt = now
	}

	cloned := *a
	s.accountsByID[a.ID] = &cloned
	s.accountsByProv[newKey] = &cloned

	// Update in user list
	userList := s.accountsByUserID[existing.UserID]
	for i, item := range userList {
		if item.ID == a.ID {
			userList[i] = &cloned
			break
		}
	}
	return nil
}

func (s *memoryAccountStore) Delete(ctx context.Context, id string) error {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return kagi.ErrAccountNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.accountsByID[id]
	if !exists {
		return kagi.ErrAccountNotFound
	}

	delete(s.accountsByID, id)
	delete(s.accountsByProv, accountKey(existing.Provider, existing.ProviderAccountID))

	// Remove from user list
	userList := s.accountsByUserID[existing.UserID]
	updated := make([]*kagi.Account, 0, len(userList)-1)
	for _, item := range userList {
		if item.ID != id {
			updated = append(updated, item)
		}
	}
	s.accountsByUserID[existing.UserID] = updated
	return nil
}

// memorySessionStore implements kagi.SessionStore with in-memory persistence.
type memorySessionStore struct {
	mu           sync.RWMutex
	seq          uint64
	sessionsByID map[string]*kagi.Session
	sessionsByTH map[string]*kagi.Session
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{
		sessionsByID: make(map[string]*kagi.Session),
		sessionsByTH: make(map[string]*kagi.Session),
	}
}

func (s *memorySessionStore) Create(ctx context.Context, sess *kagi.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := strconv.FormatUint(atomic.AddUint64(&s.seq, 1), 10)
	now := time.Now().UTC()
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = now
	}
	if sess.UpdatedAt.IsZero() {
		sess.UpdatedAt = now
	}
	sess.ID = id

	cloned := *sess
	s.sessionsByID[id] = &cloned
	s.sessionsByTH[sess.TokenHash] = &cloned
	return nil
}

func (s *memorySessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (*kagi.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, exists := s.sessionsByTH[tokenHash]
	if !exists {
		return nil, kagi.ErrSessionNotFound
	}

	now := time.Now().UTC()
	if !sess.ExpiresAt.After(now) {
		return nil, kagi.ErrSessionNotFound
	}

	cloned := *sess
	return &cloned, nil
}

func (s *memorySessionStore) Update(ctx context.Context, sess *kagi.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.sessionsByID[sess.ID]
	if !exists {
		return kagi.ErrSessionNotFound
	}

	now := time.Now().UTC()
	if !existing.ExpiresAt.After(now) {
		return kagi.ErrSessionNotFound
	}

	cloned := *sess
	cloned.CreatedAt = existing.CreatedAt // Preserve CreatedAt absolute ceiling
	if cloned.UpdatedAt.IsZero() || cloned.UpdatedAt.Equal(existing.UpdatedAt) {
		cloned.UpdatedAt = now
	}

	if existing.TokenHash != cloned.TokenHash {
		delete(s.sessionsByTH, existing.TokenHash)
	}

	s.sessionsByID[cloned.ID] = &cloned
	s.sessionsByTH[cloned.TokenHash] = &cloned
	return nil
}

func (s *memorySessionStore) UpdateTokenHash(ctx context.Context, id, oldTokenHash, newTokenHash string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.sessionsByID[id]
	if !exists {
		return kagi.ErrSessionNotFound
	}

	if existing.TokenHash != oldTokenHash {
		return kagi.ErrSessionNotFound
	}

	now := time.Now().UTC()
	if !existing.ExpiresAt.After(now) {
		return kagi.ErrSessionNotFound
	}

	delete(s.sessionsByTH, oldTokenHash)

	existing.TokenHash = newTokenHash
	existing.ExpiresAt = expiresAt
	existing.Pending2FA = false // Mandatory 2FA graduation reset (ADR-0014)
	existing.UpdatedAt = now
	// CreatedAt remains untouched

	s.sessionsByTH[newTokenHash] = existing
	return nil
}

func (s *memorySessionStore) DeleteByID(ctx context.Context, id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.sessionsByID[id]
	if !exists {
		return "", kagi.ErrSessionNotFound
	}

	now := time.Now().UTC()
	if !existing.ExpiresAt.After(now) {
		return "", kagi.ErrSessionNotFound
	}

	th := existing.TokenHash
	delete(s.sessionsByID, id)
	delete(s.sessionsByTH, th)
	return th, nil
}

func (s *memorySessionStore) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.sessionsByTH[tokenHash]
	if !exists {
		return kagi.ErrSessionNotFound
	}

	now := time.Now().UTC()
	if !existing.ExpiresAt.After(now) {
		return kagi.ErrSessionNotFound
	}

	delete(s.sessionsByID, existing.ID)
	delete(s.sessionsByTH, tokenHash)
	return nil
}

func (s *memorySessionStore) DeleteByUserID(ctx context.Context, userID string) ([]string, error) {
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

func (s *memorySessionStore) DeleteOthersByUserID(ctx context.Context, userID, currentSessionID string) ([]string, error) {
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

func (s *memorySessionStore) ListByUserID(ctx context.Context, userID string) ([]*kagi.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	result := make([]*kagi.Session, 0)
	for _, sess := range s.sessionsByID {
		// Filter: user_id = $userID AND expires_at > now AND pending_2fa = false (ADR-0014)
		if sess.UserID == userID && sess.ExpiresAt.After(now) && !sess.Pending2FA {
			cloned := *sess
			result = append(result, &cloned)
		}
	}

	return result, nil
}

func (s *memorySessionStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
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

// memoryVerificationStore implements kagi.VerificationStore with in-memory persistence.
type memoryVerificationStore struct {
	mu           sync.RWMutex
	seq          uint64
	recordsByID  map[string]*kagi.Verification
	recordsByKey map[string]*kagi.Verification
}

func newMemoryVerificationStore() *memoryVerificationStore {
	return &memoryVerificationStore{
		recordsByID:  make(map[string]*kagi.Verification),
		recordsByKey: make(map[string]*kagi.Verification),
	}
}

func verificationKey(target string, vType kagi.VerificationType) string {
	return target + ":" + string(vType)
}

func (s *memoryVerificationStore) Create(ctx context.Context, v *kagi.Verification) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := strconv.FormatUint(atomic.AddUint64(&s.seq, 1), 10)
	now := time.Now().UTC()
	if v.CreatedAt.IsZero() {
		v.CreatedAt = now
	}
	if v.UpdatedAt.IsZero() {
		v.UpdatedAt = now
	}
	v.ID = id

	cloned := *v
	key := verificationKey(v.Target, v.Type)
	s.recordsByID[id] = &cloned
	s.recordsByKey[key] = &cloned
	return nil
}

func (s *memoryVerificationStore) Get(ctx context.Context, target string, vType kagi.VerificationType) (*kagi.Verification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := verificationKey(target, vType)
	v, exists := s.recordsByKey[key]
	if !exists {
		return nil, kagi.ErrVerificationNotFound
	}

	now := time.Now().UTC()
	if !v.ExpiresAt.After(now) {
		return nil, kagi.ErrVerificationNotFound
	}

	cloned := *v
	return &cloned, nil
}

func (s *memoryVerificationStore) Update(ctx context.Context, v *kagi.Verification) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.recordsByID[v.ID]
	if !exists {
		return kagi.ErrVerificationNotFound
	}

	now := time.Now().UTC()
	if !existing.ExpiresAt.After(now) {
		return kagi.ErrVerificationNotFound
	}

	oldKey := verificationKey(existing.Target, existing.Type)
	newKey := verificationKey(v.Target, v.Type)
	if oldKey != newKey {
		delete(s.recordsByKey, oldKey)
	}

	cloned := *v
	if cloned.UpdatedAt.IsZero() || cloned.UpdatedAt.Equal(existing.UpdatedAt) {
		cloned.UpdatedAt = now
	}

	s.recordsByID[cloned.ID] = &cloned
	s.recordsByKey[newKey] = &cloned
	return nil
}

func (s *memoryVerificationStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.recordsByID[id]
	if !exists {
		return kagi.ErrVerificationNotFound
	}

	delete(s.recordsByID, id)
	delete(s.recordsByKey, verificationKey(existing.Target, existing.Type))
	return nil
}

func (s *memoryVerificationStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var toDelete []string
	for id, v := range s.recordsByID {
		if !v.ExpiresAt.After(now) {
			toDelete = append(toDelete, id)
			if len(toDelete) >= batchSize {
				break
			}
		}
	}

	for _, id := range toDelete {
		v := s.recordsByID[id]
		delete(s.recordsByKey, verificationKey(v.Target, v.Type))
		delete(s.recordsByID, id)
	}

	return len(toDelete), nil
}

type memoryRateLimitStore struct {
	mu      sync.Mutex
	entries map[string]*kagi.RateLimitEntry
}

func newMemoryRateLimitStore() *memoryRateLimitStore {
	return &memoryRateLimitStore{
		entries: make(map[string]*kagi.RateLimitEntry),
	}
}

func (s *memoryRateLimitStore) Increment(ctx context.Context, key string, window time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	entry, exists := s.entries[key]
	if !exists || !entry.ExpiresAt.After(now) {
		// Reset or initialize: count = 1, expires_at = now + window
		s.entries[key] = &kagi.RateLimitEntry{
			Key:       key,
			Count:     1,
			ExpiresAt: now.Add(window),
		}
		return 1, nil
	}

	// Active: increment count, preserve expires_at
	entry.Count++
	return entry.Count, nil
}

func (s *memoryRateLimitStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var toDelete []string
	for key, entry := range s.entries {
		if !entry.ExpiresAt.After(now) {
			toDelete = append(toDelete, key)
			if len(toDelete) >= batchSize {
				break
			}
		}
	}

	for _, key := range toDelete {
		delete(s.entries, key)
	}

	return len(toDelete), nil
}
