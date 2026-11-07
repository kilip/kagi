package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// CSRFKeyInfo is the HKDF expansion info context string for deriving the CSRF HMAC key.
	CSRFKeyInfo = "kagi-csrf-hmac-sha256-v1"

	// CSRFKeyLength is the length in bytes of the derived CSRF HMAC key.
	CSRFKeyLength = 32

	// CSRFTokenBytes is the number of raw entropy bytes in a CSRF token.
	CSRFTokenBytes = 32

	// CSRFCookiePayloadBytes is the length in bytes of the unencoded CSRF cookie payload.
	CSRFCookiePayloadBytes = 64

	// CSRFMaskedTokenBytes is the length in bytes of the unencoded masked CSRF token.
	CSRFMaskedTokenBytes = 64

	// CSRFEncodedLength is the character length of Base64URL-encoded CSRF cookies and masked tokens.
	CSRFEncodedLength = 86
)

var (
	// ErrWeakMasterSecret indicates that the provided master secret has less than 32 bytes of entropy.
	ErrWeakMasterSecret = errors.New("crypto: master secret must be at least 32 bytes")

	// ErrInvalidKeyLength indicates that the requested derived key length is invalid.
	ErrInvalidKeyLength = errors.New("crypto: invalid key length")

	// ErrCSRFTokenMissing indicates that the CSRF cookie or client token is missing.
	ErrCSRFTokenMissing = errors.New("crypto: csrf token missing")

	// ErrCSRFTokenInvalid indicates that the CSRF cookie or client token is malformed or invalid.
	ErrCSRFTokenInvalid = errors.New("crypto: csrf token invalid")

	// ErrCSRFTokenMismatch indicates that the client CSRF token does not match the cookie CSRF token.
	ErrCSRFTokenMismatch = errors.New("crypto: csrf token mismatch")
)

// DeriveKey derives a cryptographic subkey of the specified length from a master secret
// and domain separation info string using HKDF-Expand with SHA-256 (RFC 5869).
// It returns ErrWeakMasterSecret if len(secret) < 32, or ErrInvalidKeyLength if length <= 0.
func DeriveKey(secret []byte, info string, length int) ([]byte, error) {
	if len(secret) < 32 {
		return nil, ErrWeakMasterSecret
	}
	if length <= 0 {
		return nil, ErrInvalidKeyLength
	}

	reader := hkdf.Expand(sha256.New, secret, []byte(info))
	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("crypto: hkdf expand failed: %w", err)
	}
	return key, nil
}

// DeriveCSRFKey derives a 32-byte CSRF HMAC key from masterSecret using HKDF-Expand with SHA-256
// and the CSRFKeyInfo domain separation string.
// It returns ErrWeakMasterSecret if len(masterSecret) < 32.
func DeriveCSRFKey(masterSecret []byte) ([]byte, error) {
	return DeriveKey(masterSecret, CSRFKeyInfo, CSRFKeyLength)
}

// CreateCSRFCookie generates a cryptographically secure 32-byte raw CSRF token,
// computes its HMAC-SHA256 signature using csrfKey, and returns both the raw token
// and the 86-character Base64URL-encoded cookie value.
// It returns ErrCSRFTokenInvalid if len(csrfKey) == 0.
func CreateCSRFCookie(csrfKey []byte) ([]byte, string, error) {
	if len(csrfKey) == 0 {
		return nil, "", ErrCSRFTokenInvalid
	}

	rawToken, err := GenerateRandomBytes(CSRFTokenBytes)
	if err != nil {
		return nil, "", err
	}

	mac := hmac.New(sha256.New, csrfKey)
	mac.Write(rawToken)
	sig := mac.Sum(nil)

	payload := make([]byte, CSRFCookiePayloadBytes)
	copy(payload[:CSRFTokenBytes], rawToken)
	copy(payload[CSRFTokenBytes:], sig)

	cookieValue := base64.RawURLEncoding.EncodeToString(payload)
	return rawToken, cookieValue, nil
}

// ValidateCSRFCookie decodes an 86-character Base64URL CSRF cookie payload, verifies
// its HMAC-SHA256 signature against csrfKey in constant time, and returns the 32-byte raw token.
// It returns ErrCSRFTokenMissing if cookieValue is empty, or ErrCSRFTokenInvalid if decoding,
// payload length, or signature verification fails.
func ValidateCSRFCookie(cookieValue string, csrfKey []byte) ([]byte, error) {
	if cookieValue == "" {
		return nil, ErrCSRFTokenMissing
	}
	if len(csrfKey) == 0 {
		return nil, ErrCSRFTokenInvalid
	}
	if len(cookieValue) != CSRFEncodedLength {
		return nil, ErrCSRFTokenInvalid
	}

	payload, err := base64.RawURLEncoding.DecodeString(cookieValue)
	if err != nil || len(payload) != CSRFCookiePayloadBytes {
		return nil, ErrCSRFTokenInvalid
	}

	rawToken := payload[:CSRFTokenBytes]
	sig := payload[CSRFTokenBytes:]

	mac := hmac.New(sha256.New, csrfKey)
	mac.Write(rawToken)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(expectedMAC, sig) {
		return nil, ErrCSRFTokenInvalid
	}

	ret := make([]byte, CSRFTokenBytes)
	copy(ret, rawToken)
	return ret, nil
}

// MaskCSRFToken applies a random 32-byte XOR mask to rawToken to mitigate BREACH compression
// side-channel attacks, returning an 86-character unpadded Base64URL-encoded token.
// It returns ErrCSRFTokenInvalid if len(rawToken) != CSRFTokenBytes.
func MaskCSRFToken(rawToken []byte) (string, error) {
	if len(rawToken) != CSRFTokenBytes {
		return "", ErrCSRFTokenInvalid
	}

	mask, err := GenerateRandomBytes(CSRFTokenBytes)
	if err != nil {
		return "", err
	}

	payload := make([]byte, CSRFMaskedTokenBytes)
	copy(payload[:CSRFTokenBytes], mask)
	for i := range CSRFTokenBytes {
		payload[CSRFTokenBytes+i] = rawToken[i] ^ mask[i]
	}

	return base64.RawURLEncoding.EncodeToString(payload), nil
}

// UnmaskCSRFToken decodes an 86-character Base64URL-encoded masked CSRF token, extracts the
// 32-byte mask and masked token, and recovers the original 32-byte raw token via XOR.
// It returns ErrCSRFTokenMissing if maskedToken is empty, or ErrCSRFTokenInvalid if decoding
// or payload length verification fails.
func UnmaskCSRFToken(maskedToken string) ([]byte, error) {
	if maskedToken == "" {
		return nil, ErrCSRFTokenMissing
	}
	if len(maskedToken) != CSRFEncodedLength {
		return nil, ErrCSRFTokenInvalid
	}

	payload, err := base64.RawURLEncoding.DecodeString(maskedToken)
	if err != nil || len(payload) != CSRFMaskedTokenBytes {
		return nil, ErrCSRFTokenInvalid
	}

	mask := payload[:CSRFTokenBytes]
	masked := payload[CSRFTokenBytes:]

	rawToken := make([]byte, CSRFTokenBytes)
	for i := range CSRFTokenBytes {
		rawToken[i] = masked[i] ^ mask[i]
	}
	return rawToken, nil
}

// ValidateCSRF validates a CSRF cookie and client-submitted masked token against csrfKey.
// It verifies the cookie's HMAC signature, unmasks the client token, and ensures the unmasked
// token matches the cookie's raw token in constant time.
// It returns ErrCSRFTokenMissing if either token is empty, ErrCSRFTokenInvalid if decoding or
// signature verification fails, or ErrCSRFTokenMismatch if the tokens do not match.
func ValidateCSRF(cookieValue string, clientToken string, csrfKey []byte) error {
	if cookieValue == "" || clientToken == "" {
		return ErrCSRFTokenMissing
	}

	cookieRaw, err := ValidateCSRFCookie(cookieValue, csrfKey)
	if err != nil {
		return err
	}

	clientRaw, err := UnmaskCSRFToken(clientToken)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(cookieRaw, clientRaw) != 1 {
		return ErrCSRFTokenMismatch
	}

	return nil
}
