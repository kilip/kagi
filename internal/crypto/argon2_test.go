package crypto_test

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kilip/kagi/internal/crypto"
	"golang.org/x/crypto/argon2"
)

// fastParams returns low-cost parameters for fast unit testing.
func fastParams() crypto.Argon2Params {
	return crypto.Argon2Params{
		Memory:      64, // 64 KiB (>= 8*2 = 16)
		Iterations:  1,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func TestDefaultArgon2Params(t *testing.T) {
	t.Parallel()

	params := crypto.DefaultArgon2Params()

	if params.Memory != 64*1024 {
		t.Errorf("expected Memory=65536, got %d", params.Memory)
	}
	if params.Iterations != 3 {
		t.Errorf("expected Iterations=3, got %d", params.Iterations)
	}
	if params.Parallelism != 2 {
		t.Errorf("expected Parallelism=2, got %d", params.Parallelism)
	}
	if params.SaltLength != 16 {
		t.Errorf("expected SaltLength=16, got %d", params.SaltLength)
	}
	if params.KeyLength != 32 {
		t.Errorf("expected KeyLength=32, got %d", params.KeyLength)
	}
}

func TestHashPassword_FormatAndUniqueness(t *testing.T) {
	t.Parallel()

	params := fastParams()
	password := "correct-horse-battery-staple"

	hash1, err := crypto.HashPassword(password, params)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	hash2, err := crypto.HashPassword(password, params)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Format verification: $argon2id$v=19$m=%d,t=%d,p=%d$%s$%s
	phcPattern := regexp.MustCompile(`^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)
	if !phcPattern.MatchString(hash1) {
		t.Errorf("hash does not match expected PHC format: %s", hash1)
	}

	// Salts must be randomly generated, so two hashes of identical password must differ
	if hash1 == hash2 {
		t.Errorf("expected distinct hashes due to random salts, got identical: %s", hash1)
	}

	// Expected parameter segment in output
	expectedParamSegment := fmt.Sprintf("m=%d,t=%d,p=%d", params.Memory, params.Iterations, params.Parallelism)
	if !strings.Contains(hash1, expectedParamSegment) {
		t.Errorf("expected parameter segment %q in %s", expectedParamSegment, hash1)
	}
}

func TestHashAndVerify_DefaultParams(t *testing.T) {
	t.Parallel()

	password := "user-secure-password"
	hash, err := crypto.HashPassword(password, crypto.DefaultArgon2Params())
	if err != nil {
		t.Fatalf("HashPassword with DefaultArgon2Params failed: %v", err)
	}

	match, err := crypto.VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !match {
		t.Errorf("expected match=true for default params")
	}

	mismatch, err := crypto.VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed on wrong password: %v", err)
	}
	if mismatch {
		t.Errorf("expected match=false on wrong password")
	}

	needsRehash, err := crypto.NeedsRehash(hash, crypto.DefaultArgon2Params())
	if err != nil {
		t.Fatalf("NeedsRehash failed: %v", err)
	}
	if needsRehash {
		t.Errorf("expected NeedsRehash=false for hash generated with DefaultArgon2Params")
	}
}

func TestHashPassword_ParameterValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params crypto.Argon2Params
	}{
		{
			name: "iterations 0",
			params: crypto.Argon2Params{
				Memory: 64, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 16,
			},
		},
		{
			name: "iterations 101",
			params: crypto.Argon2Params{
				Memory: 64, Iterations: 101, Parallelism: 1, SaltLength: 16, KeyLength: 16,
			},
		},
		{
			name: "parallelism 0",
			params: crypto.Argon2Params{
				Memory: 64, Iterations: 1, Parallelism: 0, SaltLength: 16, KeyLength: 16,
			},
		},
		{
			name: "parallelism 65",
			params: crypto.Argon2Params{
				Memory: 1024, Iterations: 1, Parallelism: 65, SaltLength: 16, KeyLength: 16,
			},
		},
		{
			name: "memory below 8*parallelism (p=1, m=7)",
			params: crypto.Argon2Params{
				Memory: 7, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16,
			},
		},
		{
			name: "memory below 8*parallelism (p=2, m=15)",
			params: crypto.Argon2Params{
				Memory: 15, Iterations: 1, Parallelism: 2, SaltLength: 16, KeyLength: 16,
			},
		},
		{
			name: "memory above 1 GiB (1048577 KiB)",
			params: crypto.Argon2Params{
				Memory: 1048577, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16,
			},
		},
		{
			name: "salt length 0",
			params: crypto.Argon2Params{
				Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 0, KeyLength: 16,
			},
		},
		{
			name: "salt length 15",
			params: crypto.Argon2Params{
				Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 15, KeyLength: 16,
			},
		},
		{
			name: "key length 0",
			params: crypto.Argon2Params{
				Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 0,
			},
		},
		{
			name: "key length 15",
			params: crypto.Argon2Params{
				Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 15,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hash, err := crypto.HashPassword("secret", tt.params)
			if !errors.Is(err, crypto.ErrInvalidParams) {
				t.Errorf("expected ErrInvalidParams, got err=%v, hash=%s", err, hash)
			}
		})
	}
}

func TestVerifyPassword_SuccessAndFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		password      string
		checkPassword string
		wantMatch     bool
	}{
		{
			name:          "standard password match",
			password:      "superSecret123!",
			checkPassword: "superSecret123!",
			wantMatch:     true,
		},
		{
			name:          "standard password mismatch",
			password:      "superSecret123!",
			checkPassword: "wrongPassword",
			wantMatch:     false,
		},
		{
			name:          "empty password match",
			password:      "",
			checkPassword: "",
			wantMatch:     true,
		},
		{
			name:          "empty password mismatch with non-empty",
			password:      "",
			checkPassword: "non-empty",
			wantMatch:     false,
		},
		{
			name:          "unicode and emoji password match",
			password:      "Pässwörd!🔑🔒🔐",
			checkPassword: "Pässwörd!🔑🔒🔐",
			wantMatch:     true,
		},
		{
			name:          "unicode and emoji password mismatch",
			password:      "Pässwörd!🔑🔒🔐",
			checkPassword: "Pässwörd!🔑🔒🔓",
			wantMatch:     false,
		},
		{
			name:          "case sensitivity mismatch",
			password:      "PasswordCase123",
			checkPassword: "passwordcase123",
			wantMatch:     false,
		},
		{
			name:          "long password (72+ bytes, e.g. bcrypt boundary)",
			password:      "ThisIsA72ByteOrLongerPasswordStringDesignedToTestArgon2idHandlingProperly!",
			checkPassword: "ThisIsA72ByteOrLongerPasswordStringDesignedToTestArgon2idHandlingProperly!",
			wantMatch:     true,
		},
		{
			name:          "long password (1024 characters) match",
			password:      strings.Repeat("aB3$", 256),
			checkPassword: strings.Repeat("aB3$", 256),
			wantMatch:     true,
		},
	}

	params := fastParams()

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encodedHash, err := crypto.HashPassword(tt.password, params)
			if err != nil {
				t.Fatalf("HashPassword failed: %v", err)
			}

			match, err := crypto.VerifyPassword(tt.checkPassword, encodedHash)
			if err != nil {
				t.Fatalf("VerifyPassword unexpected error: %v", err)
			}

			if match != tt.wantMatch {
				t.Errorf("VerifyPassword() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestVerifyPassword_InvalidHashFormat(t *testing.T) {
	t.Parallel()

	validSalt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	validKey := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

	tests := []struct {
		name        string
		encodedHash string
		wantErr     error
	}{
		{
			name:        "empty string",
			encodedHash: "",
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "plain string without dollars",
			encodedHash: "argon2id_not_a_hash",
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "missing leading dollar",
			encodedHash: fmt.Sprintf("argon2id$v=19$m=64,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "too few parts (missing key)",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2$%s", validSalt),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "too many parts",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2$%s$%s$extra", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "trailing dollar",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2$%s$%s$", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "unsupported algorithm bcrypt",
			encodedHash: fmt.Sprintf("$bcrypt$v=19$m=64,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "unsupported algorithm argon2i",
			encodedHash: fmt.Sprintf("$argon2i$v=19$m=64,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "unsupported algorithm argon2d",
			encodedHash: fmt.Sprintf("$argon2d$v=19$m=64,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "missing v= prefix in version",
			encodedHash: fmt.Sprintf("$argon2id$19$m=64,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "non-numeric version",
			encodedHash: fmt.Sprintf("$argon2id$v=abc$m=64,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "incompatible version 16 (0x10)",
			encodedHash: fmt.Sprintf("$argon2id$v=16$m=64,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrIncompatibleVersion,
		},
		{
			name:        "incompatible version 20",
			encodedHash: fmt.Sprintf("$argon2id$v=20$m=64,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrIncompatibleVersion,
		},
		{
			name:        "malformed parameter string",
			encodedHash: fmt.Sprintf("$argon2id$v=19$malformed$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "missing memory parameter",
			encodedHash: fmt.Sprintf("$argon2id$v=19$t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "missing iterations parameter",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "missing parallelism parameter",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "duplicate parameter m",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,m=64,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "duplicate parameter t",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "duplicate parameter p",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "unknown parameter key",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2,k=10$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "invalid base64 in salt",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2$!notbase64!$%s", validKey),
			wantErr:     crypto.ErrInvalidHash,
		},
		{
			name:        "invalid base64 in key",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2$%s$!notbase64!", validSalt),
			wantErr:     crypto.ErrInvalidHash,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			match, err := crypto.VerifyPassword("password", tt.encodedHash)
			if match {
				t.Errorf("expected match=false on invalid hash")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestVerifyPassword_ParameterBoundsValidation(t *testing.T) {
	t.Parallel()

	validSalt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	validKey := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	shortSalt := base64.RawStdEncoding.EncodeToString([]byte("short"))
	shortKey := base64.RawStdEncoding.EncodeToString([]byte("short"))
	emptySalt := base64.RawStdEncoding.EncodeToString([]byte{})
	emptyKey := base64.RawStdEncoding.EncodeToString([]byte{})

	tests := []struct {
		name        string
		encodedHash string
		wantErr     error
	}{
		{
			name:        "iterations t=0 (prevents argon2 panic)",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=0,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidParams,
		},
		{
			name:        "iterations t=101",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=101,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidParams,
		},
		{
			name:        "parallelism p=0 (prevents argon2 panic)",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=0$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidParams,
		},
		{
			name:        "parallelism p=65",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=1024,t=1,p=65$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidParams,
		},
		{
			name:        "memory m < 8*p (p=2, m=15)",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=15,t=1,p=2$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidParams,
		},
		{
			name:        "memory m > 1048576 (1048577 KiB)",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=1048577,t=1,p=1$%s$%s", validSalt, validKey),
			wantErr:     crypto.ErrInvalidParams,
		},
		{
			name:        "salt length < 16 bytes",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2$%s$%s", shortSalt, validKey),
			wantErr:     crypto.ErrInvalidParams,
		},
		{
			name:        "empty salt length",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2$%s$%s", emptySalt, validKey),
			wantErr:     crypto.ErrInvalidParams,
		},
		{
			name:        "key length < 16 bytes",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2$%s$%s", validSalt, shortKey),
			wantErr:     crypto.ErrInvalidParams,
		},
		{
			name:        "universal bypass attempt: empty key (0 bytes)",
			encodedHash: fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2$%s$%s", validSalt, emptyKey),
			wantErr:     crypto.ErrInvalidParams,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			match, err := crypto.VerifyPassword("password", tt.encodedHash)
			if match {
				t.Fatalf("SECURITY VIOLATION: matched invalid hash %s", tt.name)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestNeedsRehash(t *testing.T) {
	t.Parallel()

	baseParams := fastParams()
	encodedHash, err := crypto.HashPassword("secret", baseParams)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	tests := []struct {
		name         string
		targetParams crypto.Argon2Params
		wantRehash   bool
	}{
		{
			name:         "identical parameters",
			targetParams: baseParams,
			wantRehash:   false,
		},
		{
			name: "different memory",
			targetParams: crypto.Argon2Params{
				Memory:      baseParams.Memory * 2,
				Iterations:  baseParams.Iterations,
				Parallelism: baseParams.Parallelism,
				SaltLength:  baseParams.SaltLength,
				KeyLength:   baseParams.KeyLength,
			},
			wantRehash: true,
		},
		{
			name: "different iterations",
			targetParams: crypto.Argon2Params{
				Memory:      baseParams.Memory,
				Iterations:  baseParams.Iterations + 1,
				Parallelism: baseParams.Parallelism,
				SaltLength:  baseParams.SaltLength,
				KeyLength:   baseParams.KeyLength,
			},
			wantRehash: true,
		},
		{
			name: "different parallelism",
			targetParams: crypto.Argon2Params{
				Memory:      baseParams.Memory,
				Iterations:  baseParams.Iterations,
				Parallelism: baseParams.Parallelism + 1,
				SaltLength:  baseParams.SaltLength,
				KeyLength:   baseParams.KeyLength,
			},
			wantRehash: true,
		},
		{
			name: "different salt length",
			targetParams: crypto.Argon2Params{
				Memory:      baseParams.Memory,
				Iterations:  baseParams.Iterations,
				Parallelism: baseParams.Parallelism,
				SaltLength:  baseParams.SaltLength + 16,
				KeyLength:   baseParams.KeyLength,
			},
			wantRehash: true,
		},
		{
			name: "different key length",
			targetParams: crypto.Argon2Params{
				Memory:      baseParams.Memory,
				Iterations:  baseParams.Iterations,
				Parallelism: baseParams.Parallelism,
				SaltLength:  baseParams.SaltLength,
				KeyLength:   baseParams.KeyLength + 16,
			},
			wantRehash: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rehash, err := crypto.NeedsRehash(encodedHash, tt.targetParams)
			if err != nil {
				t.Fatalf("NeedsRehash failed: %v", err)
			}
			if rehash != tt.wantRehash {
				t.Errorf("NeedsRehash() = %v, want %v", rehash, tt.wantRehash)
			}
		})
	}

	// NeedsRehash with invalid hash
	rehash, err := crypto.NeedsRehash("invalid-hash", baseParams)
	if rehash {
		t.Errorf("expected rehash=false on invalid hash")
	}
	if !errors.Is(err, crypto.ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash, got %v", err)
	}
}

func TestDummyHash(t *testing.T) {
	t.Parallel()

	params := fastParams()

	start := time.Now()
	dummy := crypto.DummyHash(params)
	duration := time.Since(start)

	// DummyHash must execute in O(1) time without deriving keys
	if duration > 10*time.Millisecond {
		t.Errorf("DummyHash took %v, expected < 10ms (O(1))", duration)
	}

	// Verify syntax matches PHC format
	phcPattern := regexp.MustCompile(`^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)
	if !phcPattern.MatchString(dummy) {
		t.Errorf("DummyHash generated invalid PHC format: %s", dummy)
	}

	// NeedsRehash against matching params must return (false, nil)
	rehash, err := crypto.NeedsRehash(dummy, params)
	if err != nil {
		t.Fatalf("NeedsRehash failed on dummy hash: %v", err)
	}
	if rehash {
		t.Errorf("NeedsRehash on dummy hash returned true, expected false")
	}

	// VerifyPassword against dummy hash should succeed parsing and return (false, nil)
	match, err := crypto.VerifyPassword("arbitrary-password", dummy)
	if err != nil {
		t.Fatalf("VerifyPassword on dummy hash returned error: %v", err)
	}
	if match {
		t.Fatalf("VerifyPassword on dummy hash matched unexpectedly")
	}

	// Calling DummyHash with zero params should safely fall back to default params
	dummyDefault := crypto.DummyHash(crypto.Argon2Params{})
	if !phcPattern.MatchString(dummyDefault) {
		t.Errorf("DummyHash with zero params generated invalid PHC format: %s", dummyDefault)
	}
	expectedDefaults := crypto.DefaultArgon2Params()
	rehashDefault, err := crypto.NeedsRehash(dummyDefault, expectedDefaults)
	if err != nil {
		t.Fatalf("NeedsRehash on default dummy hash returned error: %v", err)
	}
	if rehashDefault {
		t.Errorf("expected dummy hash with zero params to match DefaultArgon2Params")
	}
}

func TestVerifyPassword_KnownVector(t *testing.T) {
	t.Parallel()

	// Compute known vector with fixed salt and key using argon2.IDKey directly
	password := "password"
	salt := []byte("somesecuresalt16")
	timeCost := uint32(1)
	memCost := uint32(64)
	threads := uint8(2)
	keyLen := uint32(32)

	key := argon2.IDKey([]byte(password), salt, timeCost, memCost, threads, keyLen)
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	keyB64 := base64.RawStdEncoding.EncodeToString(key)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memCost, timeCost, threads, saltB64, keyB64)

	match, err := crypto.VerifyPassword(password, encoded)
	if err != nil {
		t.Fatalf("VerifyPassword failed on known vector: %v", err)
	}
	if !match {
		t.Errorf("VerifyPassword failed to match known vector")
	}
}

func TestConstantTimeComparisonGuarantee(t *testing.T) {
	t.Parallel()

	// Verify subtle.ConstantTimeCompare property: empty slices return 1
	if subtle.ConstantTimeCompare([]byte{}, []byte{}) != 1 {
		t.Fatal("subtle.ConstantTimeCompare([]byte{}, []byte{}) is expected to be 1")
	}

	// Verify that our VerifyPassword refuses empty-key hashes to prevent auth bypass
	fakeSalt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	emptyKey := base64.RawStdEncoding.EncodeToString([]byte{})
	bypassHash := fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=2$%s$%s", fakeSalt, emptyKey)

	match, err := crypto.VerifyPassword("", bypassHash)
	if match {
		t.Fatalf("CRITICAL: universal authentication bypass on empty-key hash succeeded!")
	}
	if !errors.Is(err, crypto.ErrInvalidParams) {
		t.Errorf("expected ErrInvalidParams, got %v", err)
	}
}

func TestConcurrentHashAndVerify(t *testing.T) {
	t.Parallel()

	params := fastParams()
	var wg sync.WaitGroup
	workers := 50
	iterations := 2

	for workerID := range workers {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := range iterations {
				pwd := fmt.Sprintf("pass-worker-%d-iter-%d", workerID, j)
				hash, err := crypto.HashPassword(pwd, params)
				if err != nil {
					t.Errorf("HashPassword failed: %v", err)
					return
				}

				match, err := crypto.VerifyPassword(pwd, hash)
				if err != nil {
					t.Errorf("VerifyPassword error: %v", err)
					return
				}
				if !match {
					t.Errorf("VerifyPassword mismatch for %s", pwd)
					return
				}

				matchWrong, err := crypto.VerifyPassword("wrong", hash)
				if err != nil {
					t.Errorf("VerifyPassword wrong error: %v", err)
					return
				}
				if matchWrong {
					t.Errorf("VerifyPassword incorrectly matched wrong password")
					return
				}
			}
		}(workerID)
	}

	wg.Wait()
}

func BenchmarkHashPassword(b *testing.B) {
	params := fastParams()
	pwd := "benchmarkPassword123!"
	b.ResetTimer()
	for b.Loop() {
		_, err := crypto.HashPassword(pwd, params)
		if err != nil {
			b.Fatalf("HashPassword failed: %v", err)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	params := fastParams()
	pwd := "benchmarkPassword123!"
	hash, err := crypto.HashPassword(pwd, params)
	if err != nil {
		b.Fatalf("HashPassword failed: %v", err)
	}
	b.ResetTimer()
	for b.Loop() {
		match, err := crypto.VerifyPassword(pwd, hash)
		if err != nil {
			b.Fatalf("VerifyPassword failed: %v", err)
		}
		if !match {
			b.Fatalf("VerifyPassword mismatch")
		}
	}
}

func BenchmarkDummyHash(b *testing.B) {
	params := fastParams()
	b.ResetTimer()
	for b.Loop() {
		_ = crypto.DummyHash(params)
	}
}
