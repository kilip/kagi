package adaptertest_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/adaptertest"
)

type spyTB struct {
	failed   bool
	errors   []string
	messages []string
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
}
