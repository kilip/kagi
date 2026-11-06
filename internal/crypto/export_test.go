package crypto

// SetRandReadForTesting allows testing error paths when crypto/rand fails.
// It returns a restore function that reverts randRead to its original state.
func SetRandReadForTesting(fn func([]byte) (int, error)) func() {
	orig := randRead
	randRead = fn
	return func() {
		randRead = orig
	}
}
