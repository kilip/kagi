package memory

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/internal/clock"
)

// AccountStore provides an in-memory implementation of kagi.AccountStore.
type AccountStore struct {
	mu             sync.RWMutex
	seq            uint64
	clock          clock.Clock
	accountsByID   map[string]*kagi.Account
	accountsByProv map[string]string   // provider:providerAccountID -> id
	accountsByUID  map[string][]string // userID -> slice of account IDs
}

var _ kagi.AccountStore = (*AccountStore)(nil)

// NewAccountStore constructs a new in-memory AccountStore.
func NewAccountStore(opts ...Option) *AccountStore {
	cfg := defaultOptions()
	for _, opt := range opts {
		opt(cfg)
	}
	return &AccountStore{
		clock:          cfg.clock,
		accountsByID:   make(map[string]*kagi.Account),
		accountsByProv: make(map[string]string),
		accountsByUID:  make(map[string][]string),
	}
}

func providerKey(provider, providerAccountID string) string {
	return provider + ":" + providerAccountID
}

// Create persists a new Account authentication method linked to account.UserID.
func (s *AccountStore) Create(ctx context.Context, account *kagi.Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if account == nil {
		return kagi.ErrAccountNotFound
	}

	key := providerKey(account.Provider, account.ProviderAccountID)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.accountsByProv[key]; exists {
		return kagi.ErrAccountAlreadyExists
	}

	now := s.clock.Now().UTC()
	if account.CreatedAt.IsZero() {
		account.CreatedAt = now
	}
	if account.UpdatedAt.IsZero() {
		account.UpdatedAt = now
	}

	newID := strconv.FormatUint(atomic.AddUint64(&s.seq, 1), 10)
	account.ID = newID

	stored := cloneAccount(account)
	s.accountsByID[newID] = stored
	s.accountsByProv[key] = newID
	s.accountsByUID[account.UserID] = append(s.accountsByUID[account.UserID], newID)

	return nil
}

// GetByProvider retrieves the Account matching the given authentication provider and provider-specific account ID.
func (s *AccountStore) GetByProvider(ctx context.Context, provider, providerAccountID string) (*kagi.Account, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	key := providerKey(provider, providerAccountID)

	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.accountsByProv[key]
	if !exists {
		return nil, kagi.ErrAccountNotFound
	}

	acct, exists := s.accountsByID[id]
	if !exists {
		return nil, kagi.ErrAccountNotFound
	}

	return cloneAccount(acct), nil
}

// ListByUserID retrieves all Account authentication methods linked to the given userID.
func (s *AccountStore) ListByUserID(ctx context.Context, userID string) ([]*kagi.Account, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ids, exists := s.accountsByUID[userID]
	if !exists || len(ids) == 0 {
		return []*kagi.Account{}, nil
	}

	result := make([]*kagi.Account, 0, len(ids))
	for _, id := range ids {
		if acct, ok := s.accountsByID[id]; ok {
			result = append(result, cloneAccount(acct))
		}
	}

	return result, nil
}

// CountByUserID returns the total number of linked Account authentication methods for userID.
func (s *AccountStore) CountByUserID(ctx context.Context, userID string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.accountsByUID[userID]), nil
}

// Update persists modifications to an existing Account record.
func (s *AccountStore) Update(ctx context.Context, account *kagi.Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if account == nil {
		return kagi.ErrAccountNotFound
	}
	if _, err := strconv.ParseUint(account.ID, 10, 64); err != nil {
		return kagi.ErrAccountNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.accountsByID[account.ID]
	if !exists {
		return kagi.ErrAccountNotFound
	}

	newKey := providerKey(account.Provider, account.ProviderAccountID)
	oldKey := providerKey(existing.Provider, existing.ProviderAccountID)

	if existingID, provExists := s.accountsByProv[newKey]; provExists && existingID != account.ID {
		return kagi.ErrAccountAlreadyExists
	}

	if oldKey != newKey {
		delete(s.accountsByProv, oldKey)
		s.accountsByProv[newKey] = account.ID
	}

	// If UserID changed, update accountsByUID index
	if existing.UserID != account.UserID {
		s.removeFromUIDIndex(existing.UserID, account.ID)
		s.accountsByUID[account.UserID] = append(s.accountsByUID[account.UserID], account.ID)
	}

	now := s.clock.Now().UTC()
	if account.UpdatedAt.IsZero() || account.UpdatedAt.Equal(existing.UpdatedAt) {
		account.UpdatedAt = now
	}

	stored := cloneAccount(account)
	stored.CreatedAt = existing.CreatedAt
	account.CreatedAt = existing.CreatedAt

	s.accountsByID[account.ID] = stored

	return nil
}

// Delete permanently removes the Account record identified by id.
func (s *AccountStore) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return kagi.ErrAccountNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.accountsByID[id]
	if !exists {
		return kagi.ErrAccountNotFound
	}

	key := providerKey(existing.Provider, existing.ProviderAccountID)
	delete(s.accountsByProv, key)
	delete(s.accountsByID, id)
	s.removeFromUIDIndex(existing.UserID, id)

	return nil
}

func (s *AccountStore) removeFromUIDIndex(userID, accountID string) {
	ids := s.accountsByUID[userID]
	filtered := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != accountID {
			filtered = append(filtered, id)
		}
	}
	if len(filtered) == 0 {
		delete(s.accountsByUID, userID)
	} else {
		s.accountsByUID[userID] = filtered
	}
}

func cloneAccount(a *kagi.Account) *kagi.Account {
	if a == nil {
		return nil
	}
	c := *a
	if a.TokenExpiresAt != nil {
		t := *a.TokenExpiresAt
		c.TokenExpiresAt = &t
	}
	return &c
}
