package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// TokenEntropyBytes is the number of random entropy bytes used to generate
	// secure tokens (32 bytes = 256 bits of entropy).
	TokenEntropyBytes = 32

	// SessionTokenLength is the fixed character length of an unpadded Base64URL
	// session token (43 ASCII characters).
	SessionTokenLength = 43

	// SHA256HexLength is the fixed character length of a hex-encoded SHA-256
	// hash (64 hex characters).
	SHA256HexLength = 64

	// DefaultOTPLength is the default length for numeric one-time passwords.
	DefaultOTPLength = 6

	// MinOTPLength is the minimum permitted length for numeric one-time passwords.
	MinOTPLength = 6

	// MaxOTPLength is the maximum permitted length for numeric one-time passwords.
	MaxOTPLength = 10
)

var (
	// ErrInvalidTokenLength indicates that a token does not match the expected length.
	ErrInvalidTokenLength = errors.New("crypto: invalid token length")

	// ErrInvalidTokenFormat indicates that a token contains invalid characters.
	ErrInvalidTokenFormat = errors.New("crypto: invalid token format")

	// ErrInvalidOTPLength indicates that the requested OTP length is outside permitted bounds.
	ErrInvalidOTPLength = errors.New("crypto: invalid OTP length")
)

// GenerateRandomBytes reads n cryptographically secure random bytes from crypto/rand.
func GenerateRandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("crypto: negative byte count")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto: failed to read random bytes: %w", err)
	}
	return b, nil
}

// GenerateURLSafeToken generates nBytes of cryptographically secure random
// entropy from crypto/rand, encodes it as an unpadded Base64URL string,
// and zeroizes the raw entropy buffer before returning.
func GenerateURLSafeToken(nBytes int) (string, error) {
	if nBytes < 0 {
		return "", errors.New("crypto: negative byte count")
	}
	if nBytes == 0 {
		return "", nil
	}
	buf, err := GenerateRandomBytes(nBytes)
	if err != nil {
		return "", err
	}
	defer zeroize(buf)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateSessionToken generates a cryptographically secure 43-character
// URL-safe session token using 32 bytes of entropy.
func GenerateSessionToken() (string, error) {
	return GenerateURLSafeToken(TokenEntropyBytes)
}

// GenerateVerificationToken generates a cryptographically secure 43-character
// URL-safe verification token using 32 bytes of entropy.
func GenerateVerificationToken() (string, error) {
	return GenerateURLSafeToken(TokenEntropyBytes)
}

// ValidateSessionTokenFormat validates that rawToken has length SessionTokenLength
// and contains only valid unpadded Base64URL characters ([A-Za-z0-9-_]).
// It returns ErrInvalidTokenLength if len(rawToken) != SessionTokenLength,
// or ErrInvalidTokenFormat if invalid characters are detected.
func ValidateSessionTokenFormat(rawToken string) error {
	if len(rawToken) != SessionTokenLength {
		return ErrInvalidTokenLength
	}
	for i := range len(rawToken) {
		c := rawToken[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return ErrInvalidTokenFormat
	}
	return nil
}

// GenerateOTP generates a cryptographically secure numeric one-time password
// of the given length using rejection sampling to eliminate modulo bias.
// Permitted lengths are between MinOTPLength and MaxOTPLength inclusive.
// If length is outside this range, ErrInvalidOTPLength is returned.
func GenerateOTP(length int) (string, error) {
	if length < MinOTPLength || length > MaxOTPLength {
		return "", ErrInvalidOTPLength
	}

	var digits [MaxOTPLength]byte
	var buf [32]byte
	defer func() {
		zeroize(digits[:])
		zeroize(buf[:])
	}()

	count := 0
	for count < length {
		if _, err := rand.Read(buf[:]); err != nil {
			return "", fmt.Errorf("crypto: failed to read random bytes: %w", err)
		}
		for _, b := range buf {
			if b < 250 {
				digits[count] = '0' + (b % 10)
				count++
				if count == length {
					break
				}
			}
		}
	}

	return string(digits[:length]), nil
}

// HashSHA256 returns the lowercase hex-encoded SHA-256 digest of data.
func HashSHA256(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// HashToken returns the lowercase hex-encoded SHA-256 digest of token.
// It is a convenience helper calling HashSHA256.
func HashToken(token string) string {
	return HashSHA256(token)
}

// ConstantTimeCompare returns true if the two strings a and b have equal contents,
// and false otherwise. The comparison is performed in constant time relative to
// the length of the inputs to prevent timing attacks.
//
// If the lengths of a and b differ, ConstantTimeCompare returns false immediately
// without comparing contents.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// VerifyHash computes the SHA-256 hex digest of data and compares it against
// expectedHash in constant time using ConstantTimeCompare.
func VerifyHash(data, expectedHash string) bool {
	computed := HashSHA256(data)
	return ConstantTimeCompare(computed, expectedHash)
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
