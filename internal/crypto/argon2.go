package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrInvalidHash indicates that the encoded hash string is malformed or invalid.
	ErrInvalidHash = errors.New("crypto: invalid hash format")

	// ErrIncompatibleVersion indicates that the Argon2 version in the hash is not supported.
	ErrIncompatibleVersion = errors.New("crypto: incompatible argon2 version")

	// ErrInvalidParams indicates that the Argon2 parameters are outside allowed security bounds.
	ErrInvalidParams = errors.New("crypto: invalid argon2 parameters")
)

// Argon2Params defines the parameters for Argon2id password hashing.
// The types match kagi.PasswordConfig.
type Argon2Params struct {
	// Memory is the memory cost in KiB.
	Memory uint32
	// Iterations is the time cost (number of passes over memory).
	Iterations uint32
	// Parallelism is the degree of parallelism (number of threads/lanes).
	Parallelism uint8
	// SaltLength is the length of the randomly generated salt in bytes.
	SaltLength uint32
	// KeyLength is the length of the derived key in bytes.
	KeyLength uint32
}

// DefaultArgon2Params returns the OWASP-recommended default Argon2id parameters.
//
// Defaults:
//   - Memory: 64 MB (65536 KiB)
//   - Iterations: 3
//   - Parallelism: 2
//   - SaltLength: 16 bytes
//   - KeyLength: 32 bytes
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// validateParams checks that parameters fall within safe, supported bounds.
func validateParams(params Argon2Params) error {
	if params.Iterations < 1 || params.Iterations > 100 {
		return ErrInvalidParams
	}
	if params.Parallelism < 1 || params.Parallelism > 64 {
		return ErrInvalidParams
	}
	if params.Memory < 8*uint32(params.Parallelism) || params.Memory > 1048576 {
		return ErrInvalidParams
	}
	if params.SaltLength < 16 {
		return ErrInvalidParams
	}
	if params.KeyLength < 16 {
		return ErrInvalidParams
	}
	return nil
}

// HashPassword hashes a password using Argon2id with the specified parameters
// and returns a standard PHC-formatted string:
// $argon2id$v=19$m=%d,t=%d,p=%d$%s$%s
func HashPassword(password string, params Argon2Params) (string, error) {
	if err := validateParams(params); err != nil {
		return "", err
	}

	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("crypto: failed to generate salt: %w", err)
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	keyB64 := base64.RawStdEncoding.EncodeToString(key)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism, saltB64, keyB64), nil
}

// parseHash parses and validates an Argon2id PHC encoded hash string.
func parseHash(encodedHash string) (params Argon2Params, salt, key []byte, err error) {
	parts := strings.Split(encodedHash, "$")
	// Format is $argon2id$v=19$m=%d,t=%d,p=%d$%s$%s
	// Splitting with leading '$' yields 6 elements:
	// parts[0] == ""
	// parts[1] == "argon2id"
	// parts[2] == "v=19"
	// parts[3] == "m=...,t=...,p=..."
	// parts[4] == "<salt_b64>"
	// parts[5] == "<key_b64>"
	if len(parts) != 6 || parts[0] != "" {
		return params, nil, nil, ErrInvalidHash
	}

	if parts[1] != "argon2id" {
		return params, nil, nil, ErrInvalidHash
	}

	if !strings.HasPrefix(parts[2], "v=") {
		return params, nil, nil, ErrInvalidHash
	}
	version, err := strconv.ParseUint(strings.TrimPrefix(parts[2], "v="), 10, 32)
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return params, nil, nil, ErrIncompatibleVersion
	}

	paramList := strings.Split(parts[3], ",")
	var (
		hasM, hasT, hasP bool
		memory           uint64
		iterations       uint64
		parallelism      uint64
	)
	for _, param := range paramList {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			return params, nil, nil, ErrInvalidHash
		}
		switch kv[0] {
		case "m":
			if hasM {
				return params, nil, nil, ErrInvalidHash
			}
			memory, err = strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return params, nil, nil, ErrInvalidHash
			}
			hasM = true
		case "t":
			if hasT {
				return params, nil, nil, ErrInvalidHash
			}
			iterations, err = strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return params, nil, nil, ErrInvalidHash
			}
			hasT = true
		case "p":
			if hasP {
				return params, nil, nil, ErrInvalidHash
			}
			parallelism, err = strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return params, nil, nil, ErrInvalidHash
			}
			hasP = true
		default:
			return params, nil, nil, ErrInvalidHash
		}
	}

	if !hasM || !hasT || !hasP {
		return params, nil, nil, ErrInvalidHash
	}

	if iterations < 1 || iterations > 100 {
		return params, nil, nil, ErrInvalidParams
	}
	if parallelism < 1 || parallelism > 64 {
		return params, nil, nil, ErrInvalidParams
	}
	if memory < 8*parallelism || memory > 1048576 {
		return params, nil, nil, ErrInvalidParams
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	if len(salt) < 16 {
		return params, nil, nil, ErrInvalidParams
	}

	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	if len(key) < 16 {
		return params, nil, nil, ErrInvalidParams
	}

	params = Argon2Params{
		Memory:      uint32(memory),
		Iterations:  uint32(iterations),
		Parallelism: uint8(parallelism),
		SaltLength:  uint32(len(salt)),
		KeyLength:   uint32(len(key)),
	}

	return params, salt, key, nil
}

// VerifyPassword compares a password against an encoded Argon2id PHC string in constant time.
//
// It parses the hash, strictly validates all parameter bounds to avoid panics or timing leaks,
// recomputes the Argon2id key, and compares it using crypto/subtle.ConstantTimeCompare.
//
// Returns (true, nil) on match, (false, nil) on mismatch, and (false, error) on malformed
// or incompatible hash.
func VerifyPassword(password, encodedHash string) (bool, error) {
	params, salt, expectedKey, err := parseHash(encodedHash)
	if err != nil {
		return false, err
	}

	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	if subtle.ConstantTimeCompare(derivedKey, expectedKey) == 1 {
		return true, nil
	}
	return false, nil
}

// NeedsRehash checks whether the encoded hash was created with parameters
// differing from targetParams.
//
// Returns (true, nil) when parameters differ, (false, nil) when parameters match,
// and (false, error) if the encoded hash is invalid or incompatible.
func NeedsRehash(encodedHash string, targetParams Argon2Params) (bool, error) {
	params, _, _, err := parseHash(encodedHash)
	if err != nil {
		return false, err
	}

	if params.Memory != targetParams.Memory ||
		params.Iterations != targetParams.Iterations ||
		params.Parallelism != targetParams.Parallelism ||
		params.SaltLength != targetParams.SaltLength ||
		params.KeyLength != targetParams.KeyLength {
		return true, nil
	}

	return false, nil
}

// DummyHash constructs and returns a syntactically valid Argon2id PHC string in O(1) time
// without computing Argon2 key derivation.
//
// This enables authentication handlers to execute VerifyPassword for non-existent users
// with identical computational timing, mitigating user enumeration timing attacks without
// causing double-hashing overhead.
func DummyHash(params Argon2Params) string {
	if params.Iterations < 1 || params.Iterations > 100 ||
		params.Parallelism < 1 || params.Parallelism > 64 ||
		params.Memory < 8*uint32(params.Parallelism) || params.Memory > 1048576 {
		defaults := DefaultArgon2Params()
		params.Memory = defaults.Memory
		params.Iterations = defaults.Iterations
		params.Parallelism = defaults.Parallelism
	}
	saltLen := params.SaltLength
	if saltLen < 16 {
		saltLen = 16
	}
	keyLen := params.KeyLength
	if keyLen < 16 {
		keyLen = 32
	}

	salt := make([]byte, saltLen)
	key := make([]byte, keyLen)
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	keyB64 := base64.RawStdEncoding.EncodeToString(key)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism, saltB64, keyB64)
}
