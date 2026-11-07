package crypto_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"testing"

	"github.com/kilip/kagi/internal/crypto"
)

func TestCSRF_Constants(t *testing.T) {
	t.Parallel()

	if crypto.CSRFKeyInfo != "kagi-csrf-hmac-sha256-v1" {
		t.Errorf("expected CSRFKeyInfo='kagi-csrf-hmac-sha256-v1', got %q", crypto.CSRFKeyInfo)
	}
	if crypto.CSRFKeyLength != 32 {
		t.Errorf("expected CSRFKeyLength=32, got %d", crypto.CSRFKeyLength)
	}
	if crypto.CSRFTokenBytes != 32 {
		t.Errorf("expected CSRFTokenBytes=32, got %d", crypto.CSRFTokenBytes)
	}
	if crypto.CSRFCookiePayloadBytes != 64 {
		t.Errorf("expected CSRFCookiePayloadBytes=64, got %d", crypto.CSRFCookiePayloadBytes)
	}
	if crypto.CSRFMaskedTokenBytes != 64 {
		t.Errorf("expected CSRFMaskedTokenBytes=64, got %d", crypto.CSRFMaskedTokenBytes)
	}
	if crypto.CSRFEncodedLength != 86 {
		t.Errorf("expected CSRFEncodedLength=86, got %d", crypto.CSRFEncodedLength)
	}
}

func TestCSRF_SentinelErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		text string
	}{
		{
			name: "ErrWeakMasterSecret",
			err:  crypto.ErrWeakMasterSecret,
			text: "crypto: master secret must be at least 32 bytes",
		},
		{
			name: "ErrInvalidKeyLength",
			err:  crypto.ErrInvalidKeyLength,
			text: "crypto: invalid key length",
		},
		{
			name: "ErrCSRFTokenMissing",
			err:  crypto.ErrCSRFTokenMissing,
			text: "crypto: csrf token missing",
		},
		{
			name: "ErrCSRFTokenInvalid",
			err:  crypto.ErrCSRFTokenInvalid,
			text: "crypto: csrf token invalid",
		},
		{
			name: "ErrCSRFTokenMismatch",
			err:  crypto.ErrCSRFTokenMismatch,
			text: "crypto: csrf token mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.err == nil {
				t.Fatal("expected non-nil error")
			}
			if tt.err.Error() != tt.text {
				t.Errorf("expected error message %q, got %q", tt.text, tt.err.Error())
			}
		})
	}
}

func TestDeriveKey(t *testing.T) {
	t.Parallel()

	validSecret32 := bytes.Repeat([]byte{0x42}, 32)
	validSecret48 := bytes.Repeat([]byte{0x55}, 48)
	validSecret64 := bytes.Repeat([]byte{0x77}, 64)

	t.Run("happy paths and determinism", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name   string
			secret []byte
			info   string
			length int
		}{
			{name: "32-byte secret 32-byte key", secret: validSecret32, info: "test-info", length: 32},
			{name: "48-byte secret 16-byte key", secret: validSecret48, info: "test-info", length: 16},
			{name: "64-byte secret 64-byte key", secret: validSecret64, info: "different-info", length: 64},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				k1, err := crypto.DeriveKey(tt.secret, tt.info, tt.length)
				if err != nil {
					t.Fatalf("unexpected DeriveKey error: %v", err)
				}
				if len(k1) != tt.length {
					t.Errorf("expected length %d, got %d", tt.length, len(k1))
				}

				// Deterministic derivation
				k2, err := crypto.DeriveKey(tt.secret, tt.info, tt.length)
				if err != nil {
					t.Fatalf("unexpected DeriveKey error on second call: %v", err)
				}
				if !bytes.Equal(k1, k2) {
					t.Errorf("expected identical keys on subsequent calls, got different")
				}
			})
		}
	})

	t.Run("domain separation", func(t *testing.T) {
		t.Parallel()

		keyCSRF, err := crypto.DeriveKey(validSecret32, "kagi-csrf-hmac-sha256-v1", 32)
		if err != nil {
			t.Fatalf("unexpected error deriving CSRF key: %v", err)
		}

		keyOAuth, err := crypto.DeriveKey(validSecret32, "kagi-oauth-aead-encryption-v1", 32)
		if err != nil {
			t.Fatalf("unexpected error deriving OAuth key: %v", err)
		}

		if bytes.Equal(keyCSRF, keyOAuth) {
			t.Errorf("domain separation failed: keys derived with different info strings are identical")
		}
	})

	t.Run("weak master secrets", func(t *testing.T) {
		t.Parallel()

		weakSecrets := [][]byte{
			nil,
			{},
			bytes.Repeat([]byte{0x01}, 1),
			bytes.Repeat([]byte{0x01}, 16),
			bytes.Repeat([]byte{0x01}, 31),
		}

		for _, sec := range weakSecrets {
			k, err := crypto.DeriveKey(sec, "test-info", 32)
			if !errors.Is(err, crypto.ErrWeakMasterSecret) {
				t.Errorf("expected ErrWeakMasterSecret for secret length %d, got %v", len(sec), err)
			}
			if k != nil {
				t.Errorf("expected nil key on error, got %v", k)
			}
		}
	})

	t.Run("invalid key length", func(t *testing.T) {
		t.Parallel()

		invalidLengths := []int{0, -1, -32}

		for _, l := range invalidLengths {
			k, err := crypto.DeriveKey(validSecret32, "test-info", l)
			if !errors.Is(err, crypto.ErrInvalidKeyLength) {
				t.Errorf("expected ErrInvalidKeyLength for length %d, got %v", l, err)
			}
			if k != nil {
				t.Errorf("expected nil key on error, got %v", k)
			}
		}
	})
}

func TestDeriveCSRFKey(t *testing.T) {
	t.Parallel()

	validSecret := bytes.Repeat([]byte{0xaa}, 32)

	t.Run("happy path matches DeriveKey with CSRFKeyInfo", func(t *testing.T) {
		t.Parallel()

		csrfKey, err := crypto.DeriveCSRFKey(validSecret)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(csrfKey) != crypto.CSRFKeyLength {
			t.Fatalf("expected key length %d, got %d", crypto.CSRFKeyLength, len(csrfKey))
		}

		expectedKey, err := crypto.DeriveKey(validSecret, crypto.CSRFKeyInfo, crypto.CSRFKeyLength)
		if err != nil {
			t.Fatalf("unexpected DeriveKey error: %v", err)
		}

		if !bytes.Equal(csrfKey, expectedKey) {
			t.Errorf("DeriveCSRFKey output does not match DeriveKey with CSRFKeyInfo")
		}
	})

	t.Run("weak secret returns ErrWeakMasterSecret", func(t *testing.T) {
		t.Parallel()

		_, err := crypto.DeriveCSRFKey([]byte("too-short"))
		if !errors.Is(err, crypto.ErrWeakMasterSecret) {
			t.Errorf("expected ErrWeakMasterSecret, got %v", err)
		}
	})
}

func TestCreateCSRFCookie(t *testing.T) {
	t.Parallel()

	csrfKey := bytes.Repeat([]byte{0x12}, 32)

	t.Run("happy path structure and encoding", func(t *testing.T) {
		t.Parallel()

		rawToken, cookieValue, err := crypto.CreateCSRFCookie(csrfKey)
		if err != nil {
			t.Fatalf("unexpected CreateCSRFCookie error: %v", err)
		}
		if len(rawToken) != crypto.CSRFTokenBytes {
			t.Fatalf("expected raw token length %d, got %d", crypto.CSRFTokenBytes, len(rawToken))
		}
		if len(cookieValue) != crypto.CSRFEncodedLength {
			t.Fatalf("expected cookie string length %d, got %d", crypto.CSRFEncodedLength, len(cookieValue))
		}

		payload, err := base64.RawURLEncoding.DecodeString(cookieValue)
		if err != nil {
			t.Fatalf("cookie value is not valid raw base64url: %v", err)
		}
		if len(payload) != crypto.CSRFCookiePayloadBytes {
			t.Fatalf("expected payload length %d, got %d", crypto.CSRFCookiePayloadBytes, len(payload))
		}

		tokenPart := payload[:crypto.CSRFTokenBytes]
		sigPart := payload[crypto.CSRFTokenBytes:]

		if !bytes.Equal(tokenPart, rawToken) {
			t.Errorf("payload raw token part does not match returned raw token")
		}

		mac := hmac.New(sha256.New, csrfKey)
		mac.Write(rawToken)
		expectedSig := mac.Sum(nil)

		if !hmac.Equal(expectedSig, sigPart) {
			t.Errorf("payload signature does not match expected HMAC-SHA256")
		}
	})

	t.Run("uniqueness across consecutive calls", func(t *testing.T) {
		t.Parallel()

		raw1, cookie1, err := crypto.CreateCSRFCookie(csrfKey)
		if err != nil {
			t.Fatalf("call 1 failed: %v", err)
		}
		raw2, cookie2, err := crypto.CreateCSRFCookie(csrfKey)
		if err != nil {
			t.Fatalf("call 2 failed: %v", err)
		}

		if bytes.Equal(raw1, raw2) {
			t.Errorf("two consecutive CreateCSRFCookie calls generated identical raw tokens")
		}
		if cookie1 == cookie2 {
			t.Errorf("two consecutive CreateCSRFCookie calls generated identical cookie values")
		}
	})

	t.Run("empty key returns ErrCSRFTokenInvalid", func(t *testing.T) {
		t.Parallel()

		_, _, err := crypto.CreateCSRFCookie(nil)
		if !errors.Is(err, crypto.ErrCSRFTokenInvalid) {
			t.Errorf("expected ErrCSRFTokenInvalid for nil key, got %v", err)
		}

		_, _, err = crypto.CreateCSRFCookie([]byte{})
		if !errors.Is(err, crypto.ErrCSRFTokenInvalid) {
			t.Errorf("expected ErrCSRFTokenInvalid for empty slice key, got %v", err)
		}
	})

}

func TestValidateCSRFCookie(t *testing.T) {
	t.Parallel()

	csrfKey := bytes.Repeat([]byte{0x23}, 32)
	wrongKey := bytes.Repeat([]byte{0x99}, 32)

	rawToken, cookieValue, err := crypto.CreateCSRFCookie(csrfKey)
	if err != nil {
		t.Fatalf("failed to create valid test cookie: %v", err)
	}

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()

		validatedRaw, err := crypto.ValidateCSRFCookie(cookieValue, csrfKey)
		if err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
		if !bytes.Equal(validatedRaw, rawToken) {
			t.Errorf("validated raw token does not match original raw token")
		}
	})

	t.Run("table-driven failures", func(t *testing.T) {
		t.Parallel()

		tamperedPayload, _ := base64.RawURLEncoding.DecodeString(cookieValue)
		tamperedToken := make([]byte, len(tamperedPayload))
		copy(tamperedToken, tamperedPayload)
		tamperedToken[0] ^= 0x01 // flip 1 bit in token part
		tamperedTokenCookie := base64.RawURLEncoding.EncodeToString(tamperedToken)

		tamperedSig := make([]byte, len(tamperedPayload))
		copy(tamperedSig, tamperedPayload)
		tamperedSig[len(tamperedSig)-1] ^= 0x01 // flip 1 bit in signature part
		tamperedSigCookie := base64.RawURLEncoding.EncodeToString(tamperedSig)

		tests := []struct {
			name        string
			cookieValue string
			key         []byte
			wantErr     error
		}{
			{
				name:        "empty cookie value",
				cookieValue: "",
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenMissing,
			},
			{
				name:        "nil csrf key",
				cookieValue: cookieValue,
				key:         nil,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "empty csrf key",
				cookieValue: cookieValue,
				key:         []byte{},
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "wrong key",
				cookieValue: cookieValue,
				key:         wrongKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "tampered raw token in payload",
				cookieValue: tamperedTokenCookie,
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "tampered signature in payload",
				cookieValue: tamperedSigCookie,
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "truncated cookie string (85 chars)",
				cookieValue: cookieValue[:85],
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "extended cookie string (87 chars)",
				cookieValue: cookieValue + "A",
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "padded base64 cookie string",
				cookieValue: base64.URLEncoding.EncodeToString(tamperedPayload),
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "invalid base64url characters",
				cookieValue: string(bytes.Repeat([]byte{'!'}, 86)),
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "valid base64url but wrong payload length (32 bytes)",
				cookieValue: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				_, err := crypto.ValidateCSRFCookie(tt.cookieValue, tt.key)
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			})
		}
	})
}

func TestMaskAndUnmaskCSRFToken(t *testing.T) {
	t.Parallel()

	rawToken, err := crypto.GenerateRandomBytes(crypto.CSRFTokenBytes)
	if err != nil {
		t.Fatalf("failed to generate raw token: %v", err)
	}

	t.Run("happy path mask and unmask roundtrip", func(t *testing.T) {
		t.Parallel()

		masked, err := crypto.MaskCSRFToken(rawToken)
		if err != nil {
			t.Fatalf("unexpected MaskCSRFToken error: %v", err)
		}
		if len(masked) != crypto.CSRFEncodedLength {
			t.Fatalf("expected masked token length %d, got %d", crypto.CSRFEncodedLength, len(masked))
		}

		unmasked, err := crypto.UnmaskCSRFToken(masked)
		if err != nil {
			t.Fatalf("unexpected UnmaskCSRFToken error: %v", err)
		}
		if !bytes.Equal(unmasked, rawToken) {
			t.Errorf("unmasked raw token does not match original raw token")
		}
	})

	t.Run("BREACH mitigation: random masking uniqueness", func(t *testing.T) {
		t.Parallel()

		const iterations = 100
		seen := make(map[string]bool, iterations)

		for i := range iterations {
			masked, err := crypto.MaskCSRFToken(rawToken)
			if err != nil {
				t.Fatalf("MaskCSRFToken failed on iter %d: %v", i, err)
			}
			if seen[masked] {
				t.Fatalf("duplicate masked token generated at iter %d: %s", i, masked)
			}
			seen[masked] = true

			unmasked, err := crypto.UnmaskCSRFToken(masked)
			if err != nil {
				t.Fatalf("UnmaskCSRFToken failed on iter %d: %v", i, err)
			}
			if !bytes.Equal(unmasked, rawToken) {
				t.Fatalf("unmasked token mismatch at iter %d", i)
			}
		}
	})

	t.Run("MaskCSRFToken invalid rawToken length", func(t *testing.T) {
		t.Parallel()

		invalidRawTokens := [][]byte{
			nil,
			{},
			bytes.Repeat([]byte{0x01}, 16),
			bytes.Repeat([]byte{0x01}, 31),
			bytes.Repeat([]byte{0x01}, 33),
			bytes.Repeat([]byte{0x01}, 64),
		}

		for _, inv := range invalidRawTokens {
			_, err := crypto.MaskCSRFToken(inv)
			if !errors.Is(err, crypto.ErrCSRFTokenInvalid) {
				t.Errorf("expected ErrCSRFTokenInvalid for raw token length %d, got %v", len(inv), err)
			}
		}
	})

	t.Run("UnmaskCSRFToken table-driven failures", func(t *testing.T) {
		t.Parallel()

		validMasked, err := crypto.MaskCSRFToken(rawToken)
		if err != nil {
			t.Fatalf("failed to create valid masked token: %v", err)
		}

		tests := []struct {
			name        string
			maskedToken string
			wantErr     error
		}{
			{
				name:        "empty string",
				maskedToken: "",
				wantErr:     crypto.ErrCSRFTokenMissing,
			},
			{
				name:        "truncated (85 chars)",
				maskedToken: validMasked[:85],
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "extended (87 chars)",
				maskedToken: validMasked + "B",
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "short string (10 chars)",
				maskedToken: "1234567890",
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "invalid base64url characters",
				maskedToken: string(bytes.Repeat([]byte{'?'}, 86)),
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "valid base64url but wrong payload length (32 bytes)",
				maskedToken: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				_, err := crypto.UnmaskCSRFToken(tt.maskedToken)
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected %v, got %v", tt.wantErr, err)
				}
			})
		}
	})
}

func TestValidateCSRF(t *testing.T) {
	t.Parallel()

	csrfKey := bytes.Repeat([]byte{0x34}, 32)
	otherKey := bytes.Repeat([]byte{0x78}, 32)

	rawToken1, cookieValue1, err := crypto.CreateCSRFCookie(csrfKey)
	if err != nil {
		t.Fatalf("failed to create cookie 1: %v", err)
	}

	maskedToken1, err := crypto.MaskCSRFToken(rawToken1)
	if err != nil {
		t.Fatalf("failed to mask token 1: %v", err)
	}

	rawToken2, cookieValue2, err := crypto.CreateCSRFCookie(csrfKey)
	if err != nil {
		t.Fatalf("failed to create cookie 2: %v", err)
	}

	maskedToken2, err := crypto.MaskCSRFToken(rawToken2)
	if err != nil {
		t.Fatalf("failed to mask token 2: %v", err)
	}

	t.Run("happy path validation success", func(t *testing.T) {
		t.Parallel()

		if err := crypto.ValidateCSRF(cookieValue1, maskedToken1, csrfKey); err != nil {
			t.Errorf("expected ValidateCSRF to succeed, got %v", err)
		}
		if err := crypto.ValidateCSRF(cookieValue2, maskedToken2, csrfKey); err != nil {
			t.Errorf("expected ValidateCSRF to succeed, got %v", err)
		}
	})

	t.Run("multiple masked tokens from same cookie succeed", func(t *testing.T) {
		t.Parallel()

		for range 10 {
			freshMasked, err := crypto.MaskCSRFToken(rawToken1)
			if err != nil {
				t.Fatalf("failed to mask token: %v", err)
			}
			if err := crypto.ValidateCSRF(cookieValue1, freshMasked, csrfKey); err != nil {
				t.Errorf("expected ValidateCSRF to succeed with freshly masked token, got %v", err)
			}
		}
	})

	t.Run("table-driven failures", func(t *testing.T) {
		t.Parallel()

		// Tampered client token (valid base64, 86 chars, bit flipped in XOR payload)
		payload1, _ := base64.RawURLEncoding.DecodeString(maskedToken1)
		tamperedClientPayload := make([]byte, len(payload1))
		copy(tamperedClientPayload, payload1)
		tamperedClientPayload[len(tamperedClientPayload)-1] ^= 0x01
		tamperedClientToken := base64.RawURLEncoding.EncodeToString(tamperedClientPayload)

		tests := []struct {
			name        string
			cookieValue string
			clientToken string
			key         []byte
			wantErr     error
		}{
			{
				name:        "empty cookie value",
				cookieValue: "",
				clientToken: maskedToken1,
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenMissing,
			},
			{
				name:        "empty client token",
				cookieValue: cookieValue1,
				clientToken: "",
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenMissing,
			},
			{
				name:        "both cookie and client token empty",
				cookieValue: "",
				clientToken: "",
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenMissing,
			},
			{
				name:        "wrong csrf key",
				cookieValue: cookieValue1,
				clientToken: maskedToken1,
				key:         otherKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "malformed cookie (invalid base64)",
				cookieValue: string(bytes.Repeat([]byte{'!'}, 86)),
				clientToken: maskedToken1,
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "malformed client token (truncated)",
				cookieValue: cookieValue1,
				clientToken: maskedToken1[:40],
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenInvalid,
			},
			{
				name:        "token mismatch between cookie 1 and client token 2",
				cookieValue: cookieValue1,
				clientToken: maskedToken2,
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenMismatch,
			},
			{
				name:        "token mismatch between cookie 2 and client token 1",
				cookieValue: cookieValue2,
				clientToken: maskedToken1,
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenMismatch,
			},
			{
				name:        "tampered client token yields mismatch error",
				cookieValue: cookieValue1,
				clientToken: tamperedClientToken,
				key:         csrfKey,
				wantErr:     crypto.ErrCSRFTokenMismatch,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				err := crypto.ValidateCSRF(tt.cookieValue, tt.clientToken, tt.key)
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected %v, got %v", tt.wantErr, err)
				}
			})
		}
	})
}

func TestConstantTimeBehavior(t *testing.T) {
	t.Parallel()

	// Verify subtle.ConstantTimeCompare property: empty slices return 1
	if subtle.ConstantTimeCompare([]byte{}, []byte{}) != 1 {
		t.Fatal("subtle.ConstantTimeCompare([]byte{}, []byte{}) is expected to be 1")
	}

	// Verify subtle.ConstantTimeCompare returns 0 for differing 32-byte slices
	a := bytes.Repeat([]byte{0xaa}, 32)
	b := bytes.Repeat([]byte{0xaa}, 32)
	b[31] = 0xbb
	if subtle.ConstantTimeCompare(a, b) != 0 {
		t.Fatal("expected subtle.ConstantTimeCompare to return 0 for differing slices")
	}

	// Verify hmac.Equal behaves in constant time on 32-byte hashes
	if !hmac.Equal(a, a) {
		t.Fatal("hmac.Equal on identical slices must be true")
	}
	if hmac.Equal(a, b) {
		t.Fatal("hmac.Equal on differing slices must be false")
	}
}

func TestConcurrentCSRFOperations(t *testing.T) {
	t.Parallel()

	csrfKey := bytes.Repeat([]byte{0xab}, 32)
	const goroutines = 30
	const iterations = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := range goroutines {
		go func(gid int) {
			defer wg.Done()

			for i := range iterations {
				rawToken, cookieValue, err := crypto.CreateCSRFCookie(csrfKey)
				if err != nil {
					t.Errorf("[goroutine %d iter %d] CreateCSRFCookie failed: %v", gid, i, err)
					return
				}

				maskedToken, err := crypto.MaskCSRFToken(rawToken)
				if err != nil {
					t.Errorf("[goroutine %d iter %d] MaskCSRFToken failed: %v", gid, i, err)
					return
				}

				if err := crypto.ValidateCSRF(cookieValue, maskedToken, csrfKey); err != nil {
					t.Errorf("[goroutine %d iter %d] ValidateCSRF failed: %v", gid, i, err)
					return
				}
			}
		}(g)
	}

	wg.Wait()
}

func BenchmarkDeriveCSRFKey(b *testing.B) {
	secret := bytes.Repeat([]byte{0xfe}, 32)
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := crypto.DeriveCSRFKey(secret)
		if err != nil {
			b.Fatalf("DeriveCSRFKey failed: %v", err)
		}
	}
}

func BenchmarkCreateCSRFCookie(b *testing.B) {
	csrfKey := bytes.Repeat([]byte{0xde}, 32)
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, err := crypto.CreateCSRFCookie(csrfKey)
		if err != nil {
			b.Fatalf("CreateCSRFCookie failed: %v", err)
		}
	}
}

func BenchmarkValidateCSRFCookie(b *testing.B) {
	csrfKey := bytes.Repeat([]byte{0xde}, 32)
	_, cookieValue, err := crypto.CreateCSRFCookie(csrfKey)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := crypto.ValidateCSRFCookie(cookieValue, csrfKey)
		if err != nil {
			b.Fatalf("ValidateCSRFCookie failed: %v", err)
		}
	}
}

func BenchmarkMaskCSRFToken(b *testing.B) {
	rawToken := bytes.Repeat([]byte{0x42}, 32)
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := crypto.MaskCSRFToken(rawToken)
		if err != nil {
			b.Fatalf("MaskCSRFToken failed: %v", err)
		}
	}
}

func BenchmarkUnmaskCSRFToken(b *testing.B) {
	rawToken := bytes.Repeat([]byte{0x42}, 32)
	masked, err := crypto.MaskCSRFToken(rawToken)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := crypto.UnmaskCSRFToken(masked)
		if err != nil {
			b.Fatalf("UnmaskCSRFToken failed: %v", err)
		}
	}
}

func BenchmarkValidateCSRF(b *testing.B) {
	csrfKey := bytes.Repeat([]byte{0xde}, 32)
	rawToken, cookieValue, err := crypto.CreateCSRFCookie(csrfKey)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	maskedToken, err := crypto.MaskCSRFToken(rawToken)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		err := crypto.ValidateCSRF(cookieValue, maskedToken, csrfKey)
		if err != nil {
			b.Fatalf("ValidateCSRF failed: %v", err)
		}
	}
}

// TestCSRF_EntropyFailure tests error handling when the entropy source fails.
// Must NOT be marked t.Parallel() because it mutates package-level randRead.
func TestCSRF_EntropyFailure(t *testing.T) {
	restore := crypto.SetRandReadForTesting(func(_ []byte) (int, error) {
		return 0, errors.New("simulated entropy failure")
	})
	defer restore()

	csrfKey := bytes.Repeat([]byte{0x12}, 32)
	rawToken := bytes.Repeat([]byte{0x34}, 32)

	t.Run("CreateCSRFCookie error on entropy failure", func(t *testing.T) {
		raw, cookie, err := crypto.CreateCSRFCookie(csrfKey)
		if err == nil {
			t.Fatal("expected error from CreateCSRFCookie, got nil")
		}
		if raw != nil {
			t.Errorf("expected nil raw token, got %v", raw)
		}
		if cookie != "" {
			t.Errorf("expected empty cookie, got %q", cookie)
		}
	})

	t.Run("MaskCSRFToken error on entropy failure", func(t *testing.T) {
		masked, err := crypto.MaskCSRFToken(rawToken)
		if err == nil {
			t.Fatal("expected error from MaskCSRFToken, got nil")
		}
		if masked != "" {
			t.Errorf("expected empty masked token, got %q", masked)
		}
	})
}
