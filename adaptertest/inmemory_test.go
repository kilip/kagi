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
