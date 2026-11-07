package memory

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/internal/clock"
)

// UserStore provides an in-memory implementation of kagi.UserStore.
type UserStore struct {
	mu           sync.RWMutex
	seq          uint64
	clock        clock.Clock
	usersByID    map[string]*kagi.User
	usersByEmail map[string]string // email -> id
}

var _ kagi.UserStore = (*UserStore)(nil)

// NewUserStore constructs a new in-memory UserStore.
func NewUserStore(opts ...Option) *UserStore {
	cfg := defaultOptions()
	for _, opt := range opts {
		opt(cfg)
	}
	return &UserStore{
		clock:        cfg.clock,
		usersByID:    make(map[string]*kagi.User),
		usersByEmail: make(map[string]string),
	}
}

// Create inserts a new User identity record into memory.
func (s *UserStore) Create(ctx context.Context, user *kagi.User) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if user == nil {
		return kagi.ErrUserNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.usersByEmail[user.Email]; exists {
		return kagi.ErrEmailAlreadyExists
	}

	now := s.clock.Now().UTC()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}

	newID := strconv.FormatUint(atomic.AddUint64(&s.seq, 1), 10)
	user.ID = newID

	stored := cloneUser(user)
	s.usersByID[newID] = stored
	s.usersByEmail[user.Email] = newID

	return nil
}

// GetByID retrieves a User entity by its unique string identifier.
func (s *UserStore) GetByID(ctx context.Context, id string) (*kagi.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return nil, kagi.ErrUserNotFound
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.usersByID[id]
	if !exists {
		return nil, kagi.ErrUserNotFound
	}

	return cloneUser(user), nil
}

// GetByEmail retrieves a User entity by its normalized primary email address.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*kagi.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.usersByEmail[email]
	if !exists {
		return nil, kagi.ErrUserNotFound
	}

	user, exists := s.usersByID[id]
	if !exists {
		return nil, kagi.ErrUserNotFound
	}

	return cloneUser(user), nil
}

// Update persists modifications to an existing User identity record.
func (s *UserStore) Update(ctx context.Context, user *kagi.User) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if user == nil {
		return kagi.ErrUserNotFound
	}
	if _, err := strconv.ParseUint(user.ID, 10, 64); err != nil {
		return kagi.ErrUserNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.usersByID[user.ID]
	if !exists {
		return kagi.ErrUserNotFound
	}

	if existingID, emailExists := s.usersByEmail[user.Email]; emailExists && existingID != user.ID {
		return kagi.ErrEmailAlreadyExists
	}

	// Update email mapping if email changed
	if existing.Email != user.Email {
		delete(s.usersByEmail, existing.Email)
		s.usersByEmail[user.Email] = user.ID
	}

	now := s.clock.Now().UTC()
	if user.UpdatedAt.IsZero() || user.UpdatedAt.Equal(existing.UpdatedAt) {
		user.UpdatedAt = now
	}

	stored := cloneUser(user)
	// Preserve CreatedAt from existing record
	stored.CreatedAt = existing.CreatedAt
	user.CreatedAt = existing.CreatedAt

	s.usersByID[user.ID] = stored

	return nil
}

// Delete permanently removes the User identity record identified by id.
func (s *UserStore) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return kagi.ErrUserNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.usersByID[id]
	if !exists {
		return kagi.ErrUserNotFound
	}

	delete(s.usersByEmail, existing.Email)
	delete(s.usersByID, id)

	return nil
}

func cloneUser(u *kagi.User) *kagi.User {
	if u == nil {
		return nil
	}
	c := *u
	return &c
}
