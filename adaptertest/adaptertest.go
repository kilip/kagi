package adaptertest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/kilip/kagi"
)

// TB represents the testing interface required by adaptertest runners.
// Both standard library testing types (*testing.T, *testing.B, testing.TB)
// and custom failure-capturing test runners satisfy this interface.
type TB interface {
	Cleanup(func())
	Error(args ...any)
	Errorf(format string, args ...any)
	Fail()
	FailNow()
	Failed() bool
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Helper()
	Log(args ...any)
	Logf(format string, args ...any)
	Name() string
}

// subtestRunner is an optional interface implemented by *testing.T
// allowing subtests to be executed via t.Run.
type subtestRunner interface {
	Run(name string, f func(t *testing.T)) bool
}

// customSubtestRunner allows custom test runners to handle subtests natively.
type customSubtestRunner interface {
	Run(name string, f func(tb TB)) bool
}

// runSubtest runs a named subtest using t.Run if tb is *testing.T or implements
// subtest runner interfaces, or sequentially if tb is another TB implementation.
func runSubtest(tb TB, name string, f func(tb TB)) bool {
	tb.Helper()
	if custom, ok := tb.(customSubtestRunner); ok {
		return custom.Run(name, f)
	}
	if runner, ok := tb.(subtestRunner); ok {
		return runner.Run(name, func(t *testing.T) {
			t.Helper()
			f(t)
		})
	}
	tb.Logf("=== RUN   %s", name)
	f(tb)
	return !tb.Failed()
}

var fixtureSeq uint64

// uniqueID returns a unique string with the given prefix, combining an atomic counter
// and random bytes to guarantee fixture isolation across tests and parallel runs.
func uniqueID(prefix string) string {
	seq := atomic.AddUint64(&fixtureSeq, 1)
	var b [6]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s_%d_%s", prefix, seq, hex.EncodeToString(b[:]))
}

// uniqueEmail generates a unique email address with the given prefix.
func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s@example.com", uniqueID(prefix))
}

// uniqueTokenHash generates a 64-character lowercase hex SHA-256 token hash (ADR-0014).
func uniqueTokenHash(prefix string) string {
	seq := atomic.AddUint64(&fixtureSeq, 1)
	var b [32]byte
	_, _ = rand.Read(b[:])
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%x", prefix, seq, b)))
	return hex.EncodeToString(h[:])
}

// RunUserStoreTests executes table-driven tests covering all UserStore methods
// and sentinel error returns against *testing.T.
func RunUserStoreTests(t *testing.T, store kagi.UserStore) {
	t.Helper()
	RunUserStoreTestsTB(t, store)
}

// RunUserStoreTestsTB executes table-driven tests covering all UserStore methods
// and sentinel error returns against any TB implementation.
func RunUserStoreTestsTB(tb TB, store kagi.UserStore) {
	tb.Helper()
	if store == nil {
		tb.Fatal("store must not be nil")
		return
	}
	runUserStoreTests(tb, store)
}

// RunAccountStoreTests executes table-driven tests covering all AccountStore methods
// and sentinel error returns against *testing.T.
func RunAccountStoreTests(t *testing.T, store kagi.AccountStore, userStore kagi.UserStore) {
	t.Helper()
	RunAccountStoreTestsTB(t, store, userStore)
}

// RunAccountStoreTestsTB executes table-driven tests covering all AccountStore methods
// and sentinel error returns against any TB implementation.
func RunAccountStoreTestsTB(tb TB, store kagi.AccountStore, userStore kagi.UserStore) {
	tb.Helper()
	if store == nil {
		tb.Fatal("store must not be nil")
		return
	}
	if userStore == nil {
		tb.Fatal("userStore must not be nil")
		return
	}
	runAccountStoreTests(tb, store, userStore)
}

// RunSessionStoreTests executes table-driven tests covering all SessionStore methods
// and sentinel error returns against *testing.T.
func RunSessionStoreTests(t *testing.T, store kagi.SessionStore, userStore kagi.UserStore) {
	t.Helper()
	RunSessionStoreTestsTB(t, store, userStore)
}

// RunSessionStoreTestsTB executes table-driven tests covering all SessionStore methods
// and sentinel error returns against any TB implementation.
func RunSessionStoreTestsTB(tb TB, store kagi.SessionStore, userStore kagi.UserStore) {
	tb.Helper()
	if store == nil {
		tb.Fatal("store must not be nil")
		return
	}
	if userStore == nil {
		tb.Fatal("userStore must not be nil")
		return
	}
	runSessionStoreTests(tb, store, userStore)
}

// RunVerificationStoreTests executes table-driven tests covering all VerificationStore methods
// and sentinel error returns against *testing.T.
func RunVerificationStoreTests(t *testing.T, store kagi.VerificationStore) {
	t.Helper()
	RunVerificationStoreTestsTB(t, store)
}

// RunVerificationStoreTestsTB executes table-driven tests covering all VerificationStore methods
// and sentinel error returns against any TB implementation.
func RunVerificationStoreTestsTB(tb TB, store kagi.VerificationStore) {
	tb.Helper()
	if store == nil {
		tb.Fatal("store must not be nil")
		return
	}
	runVerificationStoreTests(tb, store)
}
