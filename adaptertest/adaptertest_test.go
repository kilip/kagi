package adaptertest_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/adaptertest"
)

type spyTB struct {
	errors   []string
	messages []string
	failed   bool
}

func (s *spyTB) Cleanup(f func()) {}
func (s *spyTB) Error(args ...any) {
	s.failed = true
	s.errors = append(s.errors, fmt.Sprint(args...))
}
func (s *spyTB) Errorf(format string, args ...any) {
	s.failed = true
	s.errors = append(s.errors, fmt.Sprintf(format, args...))
}
func (s *spyTB) Fail() {
	s.failed = true
}
func (s *spyTB) FailNow() {
	s.failed = true
}
func (s *spyTB) Failed() bool {
	return s.failed
}
func (s *spyTB) Fatal(args ...any) {
	s.failed = true
	s.errors = append(s.errors, fmt.Sprint(args...))
}
func (s *spyTB) Fatalf(format string, args ...any) {
	s.failed = true
	s.errors = append(s.errors, fmt.Sprintf(format, args...))
}
func (s *spyTB) Helper() {}
func (s *spyTB) Log(args ...any) {
	s.messages = append(s.messages, fmt.Sprint(args...))
}
func (s *spyTB) Logf(format string, args ...any) {
	s.messages = append(s.messages, fmt.Sprintf(format, args...))
}
func (s *spyTB) Name() string {
	return "spyTB"
}

func TestRunUserStoreTests_Success(t *testing.T) {
	store := newMemoryUserStore()
	adaptertest.RunUserStoreTests(t, store)
}

func TestRunUserStoreTestsTB_Success(t *testing.T) {
	store := newMemoryUserStore()
	var tb testing.TB = t
	adaptertest.RunUserStoreTestsTB(tb, store)
}

func TestRunAccountStoreTests_Success(t *testing.T) {
	userStore := newMemoryUserStore()
	accountStore := newMemoryAccountStore()
	adaptertest.RunAccountStoreTests(t, accountStore, userStore)
}

func TestRunAccountStoreTestsTB_Success(t *testing.T) {
	userStore := newMemoryUserStore()
	accountStore := newMemoryAccountStore()
	var tb testing.TB = t
	adaptertest.RunAccountStoreTestsTB(tb, accountStore, userStore)
}

func TestRunSessionStoreTests_Success(t *testing.T) {
	userStore := newMemoryUserStore()
	sessionStore := newMemorySessionStore()
	adaptertest.RunSessionStoreTests(t, sessionStore, userStore)
}

func TestRunSessionStoreTestsTB_Success(t *testing.T) {
	userStore := newMemoryUserStore()
	sessionStore := newMemorySessionStore()
	var tb testing.TB = t
	adaptertest.RunSessionStoreTestsTB(tb, sessionStore, userStore)
}

func TestRunVerificationStoreTests_Success(t *testing.T) {
	verificationStore := newMemoryVerificationStore()
	adaptertest.RunVerificationStoreTests(t, verificationStore)
}

func TestRunVerificationStoreTestsTB_Success(t *testing.T) {
	verificationStore := newMemoryVerificationStore()
	var tb testing.TB = t
	adaptertest.RunVerificationStoreTestsTB(tb, verificationStore)
}

func TestRunRateLimitStoreTests_Success(t *testing.T) {
	store := newMemoryRateLimitStore()
	adaptertest.RunRateLimitStoreTests(t, store)
}

func TestRunRateLimitStoreTestsTB_Success(t *testing.T) {
	spy := &spyTB{}
	store := newMemoryRateLimitStore()
	adaptertest.RunRateLimitStoreTestsTB(spy, store)
	if spy.Failed() {
		t.Fatalf("expected memory rate limit store to pass all tests, but spy captured failure: %v", spy.errors)
	}
}

func TestRunAll_Success(t *testing.T) {
	stores := adaptertest.Stores{
		User:         newMemoryUserStore(),
		Account:      newMemoryAccountStore(),
		Session:      newMemorySessionStore(),
		Verification: newMemoryVerificationStore(),
		RateLimit:    newMemoryRateLimitStore(),
	}
	adaptertest.RunAll(t, stores)
}

func TestRunAllTB_Success(t *testing.T) {
	spy := &spyTB{}
	stores := adaptertest.Stores{
		User:         newMemoryUserStore(),
		Account:      newMemoryAccountStore(),
		Session:      newMemorySessionStore(),
		Verification: newMemoryVerificationStore(),
		RateLimit:    newMemoryRateLimitStore(),
	}
	adaptertest.RunAllTB(spy, stores)
	if spy.Failed() {
		t.Fatalf("expected RunAllTB to pass all tests, but spy captured failure: %v", spy.errors)
	}
}

// brokenUserStoreNoID fails to assign user.ID on Create
type brokenUserStoreNoID struct {
	*memoryUserStore
}

func (b *brokenUserStoreNoID) Create(ctx context.Context, u *kagi.User) error {
	_ = b.memoryUserStore.Create(ctx, u)
	u.ID = "" // deliberately violate ADR-0011
	return nil
}

func TestUserStore_FailureCapture(t *testing.T) {
	spy := &spyTB{}
	broken := &brokenUserStoreNoID{memoryUserStore: newMemoryUserStore()}

	adaptertest.RunUserStoreTestsTB(spy, broken)

	if !spy.Failed() {
		t.Fatal("expected spy to capture test failure for broken user store")
	}
	if len(spy.errors) == 0 {
		t.Fatal("expected spy to have recorded error messages")
	}
}

// brokenAccountStoreNilSlice returns nil instead of []*Account{} on ListByUserID
type brokenAccountStoreNilSlice struct {
	*memoryAccountStore
}

func (b *brokenAccountStoreNilSlice) ListByUserID(ctx context.Context, userID string) ([]*kagi.Account, error) {
	return nil, nil // deliberately violate non-nil empty slice contract
}

func TestAccountStore_FailureCapture(t *testing.T) {
	spy := &spyTB{}
	broken := &brokenAccountStoreNilSlice{memoryAccountStore: newMemoryAccountStore()}
	userStore := newMemoryUserStore()

	adaptertest.RunAccountStoreTestsTB(spy, broken, userStore)

	if !spy.Failed() {
		t.Fatal("expected spy to capture test failure for broken account store")
	}
	if len(spy.errors) == 0 {
		t.Fatal("expected spy to have recorded error messages")
	}
}

// brokenSessionStoreNilSlice returns nil instead of []*Session{} on ListByUserID
type brokenSessionStoreNilSlice struct {
	*memorySessionStore
}

func (b *brokenSessionStoreNilSlice) ListByUserID(ctx context.Context, userID string) ([]*kagi.Session, error) {
	return nil, nil // deliberately violate non-nil empty slice contract
}

func TestSessionStore_FailureCapture(t *testing.T) {
	spy := &spyTB{}
	broken := &brokenSessionStoreNilSlice{memorySessionStore: newMemorySessionStore()}
	userStore := newMemoryUserStore()

	adaptertest.RunSessionStoreTestsTB(spy, broken, userStore)

	if !spy.Failed() {
		t.Fatal("expected spy to capture test failure for broken session store (nil slice)")
	}
	if len(spy.errors) == 0 {
		t.Fatal("expected spy to have recorded error messages")
	}
}

// brokenVerificationStoreNoExpiry fails to enforce expiry on read in Get
type brokenVerificationStoreNoExpiry struct {
	*memoryVerificationStore
}

func (b *brokenVerificationStoreNoExpiry) Get(ctx context.Context, target string, vType kagi.VerificationType) (*kagi.Verification, error) {
	// Deliberately bypass expiry check
	key := target + ":" + string(vType)
	b.memoryVerificationStore.mu.RLock()
	defer b.memoryVerificationStore.mu.RUnlock()

	v, exists := b.memoryVerificationStore.recordsByKey[key]
	if !exists {
		return nil, kagi.ErrVerificationNotFound
	}
	cloned := *v
	return &cloned, nil
}

func TestVerificationStore_FailureCapture(t *testing.T) {
	spy := &spyTB{}
	broken := &brokenVerificationStoreNoExpiry{memoryVerificationStore: newMemoryVerificationStore()}

	adaptertest.RunVerificationStoreTestsTB(spy, broken)

	if !spy.Failed() {
		t.Fatal("expected spy to capture test failure for broken verification store (expiry violation)")
	}
	if len(spy.errors) == 0 {
		t.Fatal("expected spy to have recorded error messages")
	}
}

// brokenRateLimitStoreNoReset fails to reset counter on window expiration
type brokenRateLimitStoreNoReset struct {
	*memoryRateLimitStore
}

func (b *brokenRateLimitStoreNoReset) Increment(ctx context.Context, key string, window time.Duration) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry, exists := b.entries[key]
	if !exists {
		b.entries[key] = &kagi.RateLimitEntry{
			Key:       key,
			Count:     1,
			ExpiresAt: time.Now().UTC().Add(window),
		}
		return 1, nil
	}

	// Violates expiry reset: never resets count on expiration, just keeps incrementing
	entry.Count++
	return entry.Count, nil
}

func TestRateLimitStore_FailureCapture(t *testing.T) {
	spy := &spyTB{}
	broken := &brokenRateLimitStoreNoReset{
		memoryRateLimitStore: newMemoryRateLimitStore(),
	}
	adaptertest.RunRateLimitStoreTestsTB(spy, broken)

	if !spy.Failed() {
		t.Fatal("expected spy to capture test failure for broken rate limit store (missing expiry reset)")
	}
	if len(spy.errors) == 0 {
		t.Fatal("expected spy to have recorded error messages")
	}
}

func TestNilStoreGuards(t *testing.T) {
	spy := &spyTB{}
	adaptertest.RunUserStoreTestsTB(spy, nil)
	if !spy.Failed() {
		t.Fatal("expected failure on nil UserStore")
	}

	spy2 := &spyTB{}
	adaptertest.RunAccountStoreTestsTB(spy2, nil, newMemoryUserStore())
	if !spy2.Failed() {
		t.Fatal("expected failure on nil AccountStore")
	}

	spy3 := &spyTB{}
	adaptertest.RunAccountStoreTestsTB(spy3, newMemoryAccountStore(), nil)
	if !spy3.Failed() {
		t.Fatal("expected failure on nil userStore for AccountStore")
	}

	spy4 := &spyTB{}
	adaptertest.RunSessionStoreTestsTB(spy4, nil, newMemoryUserStore())
	if !spy4.Failed() {
		t.Fatal("expected failure on nil SessionStore")
	}

	spy5 := &spyTB{}
	adaptertest.RunSessionStoreTestsTB(spy5, newMemorySessionStore(), nil)
	if !spy5.Failed() {
		t.Fatal("expected failure on nil userStore for SessionStore")
	}

	spy6 := &spyTB{}
	adaptertest.RunVerificationStoreTestsTB(spy6, nil)
	if !spy6.Failed() {
		t.Fatal("expected failure on nil VerificationStore")
	}

	spy7 := &spyTB{}
	adaptertest.RunRateLimitStoreTestsTB(spy7, nil)
	if !spy7.Failed() {
		t.Fatal("expected failure on nil RateLimitStore")
	}
}
