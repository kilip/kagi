package memory

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/internal/clock"
)

// VerificationStore provides an in-memory implementation of kagi.VerificationStore.
type VerificationStore struct {
	mu           sync.RWMutex
	seq          uint64
	clock        clock.Clock
	recordsByID  map[string]*kagi.Verification
	recordsByKey map[string]*kagi.Verification // target:type -> verification
}

var _ kagi.VerificationStore = (*VerificationStore)(nil)

// NewVerificationStore constructs a new in-memory VerificationStore.
func NewVerificationStore(opts ...Option) *VerificationStore {
	cfg := defaultOptions()
	for _, opt := range opts {
		opt(cfg)
	}
	return &VerificationStore{
		clock:        cfg.clock,
		recordsByID:  make(map[string]*kagi.Verification),
		recordsByKey: make(map[string]*kagi.Verification),
	}
}

func verificationKey(target string, vType kagi.VerificationType) string {
	return target + ":" + string(vType)
}

// Create persists a new Verification record in storage.
func (s *VerificationStore) Create(ctx context.Context, v *kagi.Verification) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v == nil {
		return kagi.ErrVerificationNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id := strconv.FormatUint(atomic.AddUint64(&s.seq, 1), 10)
	now := s.clock.Now().UTC()
	if v.CreatedAt.IsZero() {
		v.CreatedAt = now
	}
	if v.UpdatedAt.IsZero() {
		v.UpdatedAt = now
	}
	v.ID = id

	cloned := cloneVerification(v)
	key := verificationKey(v.Target, v.Type)

	// If there's an existing record for target:type, replace it in recordsByID as well
	if existing, exists := s.recordsByKey[key]; exists {
		delete(s.recordsByID, existing.ID)
	}

	s.recordsByID[id] = cloned
	s.recordsByKey[key] = cloned

	return nil
}

// Get retrieves the active, unexpired Verification record for the given target and type.
func (s *VerificationStore) Get(ctx context.Context, target string, vType kagi.VerificationType) (*kagi.Verification, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key := verificationKey(target, vType)
	v, exists := s.recordsByKey[key]
	if !exists {
		return nil, kagi.ErrVerificationNotFound
	}

	now := s.clock.Now().UTC()
	if !v.ExpiresAt.After(now) {
		return nil, kagi.ErrVerificationNotFound
	}

	return cloneVerification(v), nil
}

// Update updates mutable fields of an existing Verification record.
func (s *VerificationStore) Update(ctx context.Context, v *kagi.Verification) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v == nil {
		return kagi.ErrVerificationNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.recordsByID[v.ID]
	if !exists {
		return kagi.ErrVerificationNotFound
	}

	now := s.clock.Now().UTC()
	if !existing.ExpiresAt.After(now) {
		return kagi.ErrVerificationNotFound
	}

	oldKey := verificationKey(existing.Target, existing.Type)
	newKey := verificationKey(v.Target, v.Type)
	if oldKey != newKey {
		delete(s.recordsByKey, oldKey)
	}

	cloned := cloneVerification(v)
	cloned.CreatedAt = existing.CreatedAt // Preserve original CreatedAt
	if cloned.UpdatedAt.IsZero() || cloned.UpdatedAt.Equal(existing.UpdatedAt) {
		cloned.UpdatedAt = now
	}

	s.recordsByID[cloned.ID] = cloned
	s.recordsByKey[newKey] = cloned

	return nil
}

// Delete permanently removes a Verification record by its string ID.
func (s *VerificationStore) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

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

// DeleteExpired removes expired verification records from storage in bounded batches.
func (s *VerificationStore) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now().UTC()
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

func cloneVerification(v *kagi.Verification) *kagi.Verification {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}
