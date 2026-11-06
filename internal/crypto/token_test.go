package crypto_test

import (
	"errors"
	"math"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/kilip/kagi/internal/crypto"
)

func TestToken_Constants(t *testing.T) {
	t.Parallel()

	if crypto.TokenEntropyBytes != 32 {
		t.Errorf("expected TokenEntropyBytes=32, got %d", crypto.TokenEntropyBytes)
	}
	if crypto.SessionTokenLength != 43 {
		t.Errorf("expected SessionTokenLength=43, got %d", crypto.SessionTokenLength)
	}
	if crypto.SHA256HexLength != 64 {
		t.Errorf("expected SHA256HexLength=64, got %d", crypto.SHA256HexLength)
	}
	if crypto.DefaultOTPLength != 6 {
		t.Errorf("expected DefaultOTPLength=6, got %d", crypto.DefaultOTPLength)
	}
	if crypto.MinOTPLength != 6 {
		t.Errorf("expected MinOTPLength=6 per NIST SP 800-63B, got %d", crypto.MinOTPLength)
	}
	if crypto.MaxOTPLength != 10 {
		t.Errorf("expected MaxOTPLength=10, got %d", crypto.MaxOTPLength)
	}
}

func TestToken_SentinelErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		text string
	}{
		{
			name: "ErrInvalidTokenLength",
			err:  crypto.ErrInvalidTokenLength,
			text: "crypto: invalid token length",
		},
		{
			name: "ErrInvalidTokenFormat",
			err:  crypto.ErrInvalidTokenFormat,
			text: "crypto: invalid token format",
		},
		{
			name: "ErrInvalidOTPLength",
			err:  crypto.ErrInvalidOTPLength,
			text: "crypto: invalid OTP length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.err == nil {
				t.Fatal("expected non-nil error")
			}
			if tt.err.Error() != tt.text {
				t.Errorf("expected %q, got %q", tt.text, tt.err.Error())
			}
		})
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	t.Parallel()

	t.Run("valid lengths", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int{0, 1, 16, 32, 64, 128} {
			b1, err := crypto.GenerateRandomBytes(n)
			if err != nil {
				t.Fatalf("unexpected error for n=%d: %v", n, err)
			}
			if len(b1) != n {
				t.Errorf("expected length %d, got %d", n, len(b1))
			}

			if n > 0 {
				b2, err := crypto.GenerateRandomBytes(n)
				if err != nil {
					t.Fatalf("unexpected error for n=%d: %v", n, err)
				}
				if string(b1) == string(b2) {
					t.Errorf("two consecutive GenerateRandomBytes(%d) returned identical bytes", n)
				}
			}
		}
	})

	t.Run("negative lengths", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int{-1, -10, -100} {
			b, err := crypto.GenerateRandomBytes(n)
			if err == nil {
				t.Fatalf("expected error for negative length %d, got nil", n)
			}
			if b != nil {
				t.Errorf("expected nil bytes on error, got %v", b)
			}
		}
	})
}

func TestGenerateURLSafeToken(t *testing.T) {
	t.Parallel()

	validBase64URL := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	t.Run("valid byte counts", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int{16, 32, 48, 64} {
			tok, err := crypto.GenerateURLSafeToken(n)
			if err != nil {
				t.Fatalf("unexpected error for n=%d: %v", n, err)
			}
			if strings.Contains(tok, "=") {
				t.Errorf("token contains padding '=': %s", tok)
			}
			if !validBase64URL.MatchString(tok) {
				t.Errorf("token contains invalid characters: %s", tok)
			}
		}
	})

	t.Run("zero bytes", func(t *testing.T) {
		t.Parallel()
		tok, err := crypto.GenerateURLSafeToken(0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tok != "" {
			t.Errorf("expected empty token, got %q", tok)
		}
	})

	t.Run("negative byte counts", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int{-1, -16} {
			tok, err := crypto.GenerateURLSafeToken(n)
			if err == nil {
				t.Fatalf("expected error for negative byte count %d, got nil", n)
			}
			if tok != "" {
				t.Errorf("expected empty token on error, got %q", tok)
			}
		}
	})
}

func TestGenerateSessionToken(t *testing.T) {
	t.Parallel()

	t.Run("properties and validation", func(t *testing.T) {
		t.Parallel()
		tok, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("GenerateSessionToken failed: %v", err)
		}
		if len(tok) != crypto.SessionTokenLength {
			t.Errorf("expected length %d, got %d (%s)", crypto.SessionTokenLength, len(tok), tok)
		}
		if err := crypto.ValidateSessionTokenFormat(tok); err != nil {
			t.Errorf("generated session token failed validation: %v", err)
		}
	})

	t.Run("uniqueness across 10,000 tokens", func(t *testing.T) {
		t.Parallel()
		const tokenCount = 10_000
		seen := make(map[string]struct{}, tokenCount)

		for range tokenCount {
			tok, err := crypto.GenerateSessionToken()
			if err != nil {
				t.Fatalf("GenerateSessionToken failed: %v", err)
			}
			if len(tok) != crypto.SessionTokenLength {
				t.Fatalf("expected length %d, got %d", crypto.SessionTokenLength, len(tok))
			}
			if _, exists := seen[tok]; exists {
				t.Fatalf("collision detected in GenerateSessionToken: %s", tok)
			}
			seen[tok] = struct{}{}
		}

		if len(seen) != tokenCount {
			t.Errorf("expected %d unique tokens, got %d", tokenCount, len(seen))
		}
	})
}

func TestGenerateVerificationToken(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{})
	for range 100 {
		tok, err := crypto.GenerateVerificationToken()
		if err != nil {
			t.Fatalf("GenerateVerificationToken failed: %v", err)
		}
		if len(tok) != crypto.SessionTokenLength {
			t.Errorf("expected length %d, got %d (%s)", crypto.SessionTokenLength, len(tok), tok)
		}
		if err := crypto.ValidateSessionTokenFormat(tok); err != nil {
			t.Errorf("generated verification token failed validation: %v", err)
		}
		if _, exists := seen[tok]; exists {
			t.Fatalf("collision detected in GenerateVerificationToken: %s", tok)
		}
		seen[tok] = struct{}{}
	}
}

func TestValidateSessionTokenFormat(t *testing.T) {
	t.Parallel()

	t.Run("valid tokens", func(t *testing.T) {
		t.Parallel()
		validTokens := []struct {
			name  string
			token string
		}{
			{
				name:  "mixed alphanumeric and url-safe symbols",
				token: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
			},
			{
				name:  "all digits and symbols",
				token: "0123456789-_abcdefghijklmnopqrstuvwxyzABCDE",
			},
			{
				name:  "all lowercase",
				token: strings.Repeat("a", crypto.SessionTokenLength),
			},
			{
				name:  "all uppercase",
				token: strings.Repeat("Z", crypto.SessionTokenLength),
			},
			{
				name:  "all digits",
				token: strings.Repeat("7", crypto.SessionTokenLength),
			},
			{
				name:  "all hyphens",
				token: strings.Repeat("-", crypto.SessionTokenLength),
			},
			{
				name:  "all underscores",
				token: strings.Repeat("_", crypto.SessionTokenLength),
			},
			{
				name:  "alternating hyphens and underscores",
				token: "-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-",
			},
		}

		for _, tc := range validTokens {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				if err := crypto.ValidateSessionTokenFormat(tc.token); err != nil {
					t.Errorf("expected token %q to be valid, got: %v", tc.token, err)
				}
			})
		}
	})

	t.Run("invalid lengths", func(t *testing.T) {
		t.Parallel()
		invalidLengths := []struct {
			name  string
			token string
		}{
			{name: "empty string (length 0)", token: ""},
			{name: "single char (length 1)", token: "a"},
			{name: "short (length 10)", token: strings.Repeat("a", 10)},
			{name: "off-by-one short (length 42)", token: strings.Repeat("a", 42)},
			{name: "off-by-one long (length 44)", token: strings.Repeat("a", 44)},
			{name: "long (length 100)", token: strings.Repeat("a", 100)},
			{name: "43 multi-byte UTF-8 runes (86 bytes)", token: strings.Repeat("é", 43)},
		}

		for _, tc := range invalidLengths {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := crypto.ValidateSessionTokenFormat(tc.token)
				if !errors.Is(err, crypto.ErrInvalidTokenLength) {
					t.Errorf("expected ErrInvalidTokenLength for len=%d, got: %v", len(tc.token), err)
				}
			})
		}
	})

	t.Run("invalid characters with length 43", func(t *testing.T) {
		t.Parallel()
		invalidChars := []struct {
			name  string
			token string
		}{
			{name: "padding '=' at end", token: strings.Repeat("a", 42) + "="},
			{name: "padding '=' at start", token: "=" + strings.Repeat("a", 42)},
			{name: "padding '=' in middle", token: strings.Repeat("a", 21) + "=" + strings.Repeat("a", 21)},
			{name: "standard base64 '+'", token: strings.Repeat("a", 42) + "+"},
			{name: "standard base64 '/'", token: strings.Repeat("a", 42) + "/"},
			{name: "space character", token: strings.Repeat("a", 42) + " "},
			{name: "tab character", token: strings.Repeat("a", 42) + "\t"},
			{name: "newline character", token: strings.Repeat("a", 42) + "\n"},
			{name: "carriage return", token: strings.Repeat("a", 42) + "\r"},
			{name: "null byte", token: strings.Repeat("a", 42) + "\x00"},
			{name: "bell control character", token: strings.Repeat("a", 42) + "\x07"},
			{name: "escape character", token: strings.Repeat("a", 42) + "\x1b"},
			{name: "delete character", token: strings.Repeat("a", 42) + "\x7f"},
			{name: "punctuation dot", token: strings.Repeat("a", 42) + "."},
			{name: "punctuation comma", token: strings.Repeat("a", 42) + ","},
			{name: "punctuation colon", token: strings.Repeat("a", 42) + ":"},
			{name: "punctuation semicolon", token: strings.Repeat("a", 42) + ";"},
			{name: "punctuation exclamation", token: strings.Repeat("a", 42) + "!"},
			{name: "punctuation question", token: strings.Repeat("a", 42) + "?"},
			{name: "symbol at", token: strings.Repeat("a", 42) + "@"},
			{name: "symbol hash", token: strings.Repeat("a", 42) + "#"},
			{name: "symbol dollar", token: strings.Repeat("a", 42) + "$"},
			{name: "symbol percent", token: strings.Repeat("a", 42) + "%"},
			{name: "symbol caret", token: strings.Repeat("a", 42) + "^"},
			{name: "symbol ampersand", token: strings.Repeat("a", 42) + "&"},
			{name: "symbol asterisk", token: strings.Repeat("a", 42) + "*"},
			{name: "symbol open paren", token: strings.Repeat("a", 42) + "("},
			{name: "symbol close paren", token: strings.Repeat("a", 42) + ")"},
			{name: "symbol tilde", token: strings.Repeat("a", 42) + "~"},
			{name: "symbol backtick", token: strings.Repeat("a", 42) + "`"},
			{name: "symbol backslash", token: strings.Repeat("a", 42) + "\\"},
			{name: "non-ASCII high byte 0x80", token: strings.Repeat("a", 42) + "\x80"},
			{name: "non-ASCII high byte 0xff", token: strings.Repeat("a", 42) + "\xff"},
			{name: "UTF-8 2-byte character in 43-byte string", token: strings.Repeat("a", 41) + "é"},
		}

		for _, tc := range invalidChars {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				if len(tc.token) != crypto.SessionTokenLength {
					t.Fatalf("test setup error: token length is %d, want %d", len(tc.token), crypto.SessionTokenLength)
				}
				err := crypto.ValidateSessionTokenFormat(tc.token)
				if !errors.Is(err, crypto.ErrInvalidTokenFormat) {
					t.Errorf("expected ErrInvalidTokenFormat for %q, got: %v", tc.name, err)
				}
			})
		}
	})
}

func TestGenerateOTP(t *testing.T) {
	t.Parallel()

	numericRegex := regexp.MustCompile(`^[0-9]+$`)

	t.Run("boundary and valid lengths", func(t *testing.T) {
		t.Parallel()
		validLengths := []struct {
			length int
			name   string
		}{
			{length: crypto.MinOTPLength, name: "minimum boundary (6 digits)"},
			{length: 7, name: "intermediate length 7"},
			{length: 8, name: "intermediate length 8"},
			{length: 9, name: "intermediate length 9"},
			{length: crypto.MaxOTPLength, name: "maximum boundary (10 digits)"},
		}

		for _, tc := range validLengths {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				for range 20 {
					otp, err := crypto.GenerateOTP(tc.length)
					if err != nil {
						t.Fatalf("GenerateOTP(%d) failed: %v", tc.length, err)
					}
					if len(otp) != tc.length {
						t.Errorf("expected length %d, got %d (%s)", tc.length, len(otp), otp)
					}
					if !numericRegex.MatchString(otp) {
						t.Errorf("expected purely numeric OTP, got %s", otp)
					}
				}
			})
		}
	})

	t.Run("invalid boundary lengths", func(t *testing.T) {
		t.Parallel()
		invalidLengths := []struct {
			length int
			name   string
		}{
			{length: -10, name: "negative length -10"},
			{length: -1, name: "negative length -1"},
			{length: 0, name: "zero length"},
			{length: 1, name: "length 1"},
			{length: 4, name: "length 4"},
			{length: 5, name: "below min boundary (length 5)"},
			{length: 11, name: "above max boundary (length 11)"},
			{length: 12, name: "length 12"},
			{length: 100, name: "length 100"},
		}

		for _, tc := range invalidLengths {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				otp, err := crypto.GenerateOTP(tc.length)
				if !errors.Is(err, crypto.ErrInvalidOTPLength) {
					t.Errorf("GenerateOTP(%d): expected ErrInvalidOTPLength, got: %v", tc.length, err)
				}
				if otp != "" {
					t.Errorf("expected empty OTP on error, got %s", otp)
				}
			})
		}
	})
}

func TestGenerateOTP_PearsonChiSquare(t *testing.T) {
	t.Parallel()

	// Generate 10,000 OTP codes of length 6 (total N = 60,000 digits).
	// Under uniform distribution, each digit 0..9 has expected count E = 6,000.
	// Degrees of freedom df = 10 - 1 = 9.
	// For alpha = 0.001, the critical value of chi-square is 27.877.
	const numOTPs = 10_000
	const otpLen = crypto.DefaultOTPLength
	const totalDigits = numOTPs * otpLen
	const expectedPerDigit = float64(totalDigits) / 10.0
	const criticalValueChiSquare = 27.877

	counts := make(map[byte]int, 10)

	for range numOTPs {
		otp, err := crypto.GenerateOTP(otpLen)
		if err != nil {
			t.Fatalf("GenerateOTP failed during statistical test: %v", err)
		}
		for i := range len(otp) {
			counts[otp[i]]++
		}
	}

	var chiSquare float64
	for d := byte('0'); d <= '9'; d++ {
		observed := float64(counts[d])
		diff := observed - expectedPerDigit
		chiSquare += (diff * diff) / expectedPerDigit
	}

	if chiSquare >= criticalValueChiSquare {
		t.Errorf("chi-squared value %f exceeds critical threshold %f (alpha=0.001); counts: %v",
			chiSquare, criticalValueChiSquare, counts)
	}

	// Verify each digit appeared and deviation is well within 10% tolerance
	for d := byte('0'); d <= '9'; d++ {
		obs := counts[d]
		if obs == 0 {
			t.Fatalf("digit %c did not appear in %d digits", d, totalDigits)
		}
		pctDiff := math.Abs(float64(obs)-expectedPerDigit) / expectedPerDigit
		if pctDiff > 0.10 {
			t.Errorf("digit %c count %d deviated by %.2f%% from expected %.0f", d, obs, pctDiff*100, expectedPerDigit)
		}
	}
}

func TestHashSHA256(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string NIST vector",
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "NIST abc vector",
			input:    "abc",
			expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			name:     "NIST 448-bit string vector",
			input:    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		},
		{
			name:     "quick brown fox vector",
			input:    "The quick brown fox jumps over the lazy dog",
			expected: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		},
		{
			name:     "kagi brand vector",
			input:    "kagi",
			expected: "d80b4f1b596b87ac1979c8dab09af199512127a3f09610ba759eca693a61691d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hash := crypto.HashSHA256(tt.input)
			if hash != tt.expected {
				t.Errorf("HashSHA256(%q) = %q, expected %q", tt.input, hash, tt.expected)
			}
			if len(hash) != crypto.SHA256HexLength {
				t.Errorf("expected hash length %d, got %d", crypto.SHA256HexLength, len(hash))
			}
			if strings.ToLower(hash) != hash {
				t.Errorf("hash contains uppercase characters: %s", hash)
			}
		})
	}
}

func TestHashToken(t *testing.T) {
	t.Parallel()

	t.Run("consistent with HashSHA256", func(t *testing.T) {
		t.Parallel()
		for range 10 {
			token, err := crypto.GenerateSessionToken()
			if err != nil {
				t.Fatalf("GenerateSessionToken failed: %v", err)
			}

			hashToken := crypto.HashToken(token)
			hashSHA := crypto.HashSHA256(token)

			if hashToken != hashSHA {
				t.Errorf("HashToken(%q) = %q, want %q", token, hashToken, hashSHA)
			}
			if len(hashToken) != crypto.SHA256HexLength {
				t.Errorf("expected hash length %d, got %d", crypto.SHA256HexLength, len(hashToken))
			}
		}
	})

	t.Run("known vector empty string", func(t *testing.T) {
		t.Parallel()
		expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		if got := crypto.HashToken(""); got != expected {
			t.Errorf("HashToken(\"\") = %q, want %q", got, expected)
		}
	})
}

func TestConstantTimeCompare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{
			name:     "both empty",
			a:        "",
			b:        "",
			expected: true,
		},
		{
			name:     "identical short strings",
			a:        "hello",
			b:        "hello",
			expected: true,
		},
		{
			name:     "identical 64-char hashes",
			a:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			b:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expected: true,
		},
		{
			name:     "empty vs non-empty",
			a:        "",
			b:        "nonempty",
			expected: false,
		},
		{
			name:     "non-empty vs empty",
			a:        "nonempty",
			b:        "",
			expected: false,
		},
		{
			name:     "prefix differing length",
			a:        "hello",
			b:        "hell",
			expected: false,
		},
		{
			name:     "suffix differing length",
			a:        "hell",
			b:        "hello",
			expected: false,
		},
		{
			name:     "64-char vs 63-char hash",
			a:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			b:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
			expected: false,
		},
		{
			name:     "64-char vs 65-char hash",
			a:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			b:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855a",
			expected: false,
		},
		{
			name:     "mismatch at first character",
			a:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			b:        "f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expected: false,
		},
		{
			name:     "mismatch in middle character",
			a:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			b:        "e3b0c44298fc1c149afbf4c8996fb92527ae41e4649b934ca495991b7852b855",
			expected: false,
		},
		{
			name:     "mismatch at last character",
			a:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			b:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856",
			expected: false,
		},
		{
			name:     "completely different same length",
			a:        "hello",
			b:        "world",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := crypto.ConstantTimeCompare(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("ConstantTimeCompare(%q, %q) = %v, expected %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestVerifyHash(t *testing.T) {
	t.Parallel()

	data := "sensitive-token-payload"
	expectedHash := crypto.HashSHA256(data)

	tests := []struct {
		name     string
		data     string
		hash     string
		expected bool
	}{
		{
			name:     "positive match",
			data:     data,
			hash:     expectedHash,
			expected: true,
		},
		{
			name:     "mismatching data",
			data:     "wrong-data",
			hash:     expectedHash,
			expected: false,
		},
		{
			name:     "tampered hash at last char",
			data:     data,
			hash:     expectedHash[:len(expectedHash)-1] + "x",
			expected: false,
		},
		{
			name:     "tampered hash at first char",
			data:     data,
			hash:     "x" + expectedHash[1:],
			expected: false,
		},
		{
			name:     "tampered hash in middle",
			data:     data,
			hash:     expectedHash[:32] + "x" + expectedHash[33:],
			expected: false,
		},
		{
			name:     "truncated hash",
			data:     data,
			hash:     expectedHash[:len(expectedHash)-1],
			expected: false,
		},
		{
			name:     "empty hash",
			data:     data,
			hash:     "",
			expected: false,
		},
		{
			name:     "case sensitivity rejection for uppercase hex",
			data:     data,
			hash:     strings.ToUpper(expectedHash),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := crypto.VerifyHash(tt.data, tt.hash)
			if got != tt.expected {
				t.Errorf("VerifyHash(%q, %q) = %v, want %v", tt.data, tt.hash, got, tt.expected)
			}
		})
	}
}

func TestZeroAllocations(t *testing.T) {

	t.Run("ValidateSessionTokenFormat valid token zero allocations", func(t *testing.T) {
		validToken := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
		allocs := testing.AllocsPerRun(1000, func() {
			if err := crypto.ValidateSessionTokenFormat(validToken); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
		if allocs != 0 {
			t.Errorf("ValidateSessionTokenFormat allocated %f times, expected 0", allocs)
		}
	})

	t.Run("ValidateSessionTokenFormat invalid length zero allocations", func(t *testing.T) {
		invalidLenToken := "invalid-len"
		allocs := testing.AllocsPerRun(1000, func() {
			_ = crypto.ValidateSessionTokenFormat(invalidLenToken)
		})
		if allocs != 0 {
			t.Errorf("ValidateSessionTokenFormat allocated %f times, expected 0", allocs)
		}
	})

	t.Run("ValidateSessionTokenFormat invalid char zero allocations", func(t *testing.T) {
		invalidCharToken := strings.Repeat("a", 42) + "="
		allocs := testing.AllocsPerRun(1000, func() {
			_ = crypto.ValidateSessionTokenFormat(invalidCharToken)
		})
		if allocs != 0 {
			t.Errorf("ValidateSessionTokenFormat allocated %f times, expected 0", allocs)
		}
	})

	t.Run("ConstantTimeCompare matching zero allocations", func(t *testing.T) {
		h1 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		h2 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		allocs := testing.AllocsPerRun(1000, func() {
			_ = crypto.ConstantTimeCompare(h1, h2)
		})
		if allocs != 0 {
			t.Errorf("ConstantTimeCompare allocated %f times, expected 0", allocs)
		}
	})

	t.Run("ConstantTimeCompare mismatched zero allocations", func(t *testing.T) {
		h1 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		h2 := "f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		allocs := testing.AllocsPerRun(1000, func() {
			_ = crypto.ConstantTimeCompare(h1, h2)
		})
		if allocs != 0 {
			t.Errorf("ConstantTimeCompare allocated %f times, expected 0", allocs)
		}
	})

	t.Run("GenerateOTP low allocations", func(t *testing.T) {
		allocs := testing.AllocsPerRun(1000, func() {
			otp, err := crypto.GenerateOTP(crypto.DefaultOTPLength)
			if err != nil || len(otp) != crypto.DefaultOTPLength {
				t.Fatalf("GenerateOTP failed: %v", err)
			}
		})
		if allocs > 2.0 {
			t.Errorf("GenerateOTP allocated %f times, expected <= 2.0", allocs)
		}
	})
}

// TestEntropyFailure tests error paths when the system entropy source fails.
// Must NOT be marked t.Parallel() because it mutates internal randRead.
func TestEntropyFailure(t *testing.T) {
	restore := crypto.SetRandReadForTesting(func(_ []byte) (int, error) {
		return 0, errors.New("simulated entropy failure")
	})
	defer restore()

	t.Run("GenerateRandomBytes error on entropy failure", func(t *testing.T) {
		b, err := crypto.GenerateRandomBytes(32)
		if err == nil {
			t.Fatal("expected error from GenerateRandomBytes, got nil")
		}
		if b != nil {
			t.Errorf("expected nil bytes, got %v", b)
		}
	})

	t.Run("GenerateURLSafeToken error on entropy failure", func(t *testing.T) {
		tok, err := crypto.GenerateURLSafeToken(32)
		if err == nil {
			t.Fatal("expected error from GenerateURLSafeToken, got nil")
		}
		if tok != "" {
			t.Errorf("expected empty token, got %q", tok)
		}
	})

	t.Run("GenerateOTP error on entropy failure", func(t *testing.T) {
		otp, err := crypto.GenerateOTP(crypto.DefaultOTPLength)
		if err == nil {
			t.Fatal("expected error from GenerateOTP, got nil")
		}
		if otp != "" {
			t.Errorf("expected empty OTP, got %q", otp)
		}
	})
}

func TestConcurrentCryptoOperations(t *testing.T) {
	t.Parallel()

	const workers = 64
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(workers)

	for workerID := range workers {
		go func(id int) {
			defer wg.Done()

			for iter := range iterations {
				// 1. Session token generation and validation
				sessTok, err := crypto.GenerateSessionToken()
				if err != nil {
					t.Errorf("worker %d iter %d: GenerateSessionToken failed: %v", id, iter, err)
					return
				}
				if len(sessTok) != crypto.SessionTokenLength {
					t.Errorf("worker %d iter %d: invalid session token length: %d", id, iter, len(sessTok))
					return
				}
				if err := crypto.ValidateSessionTokenFormat(sessTok); err != nil {
					t.Errorf("worker %d iter %d: ValidateSessionTokenFormat failed: %v", id, iter, err)
					return
				}

				// 2. Verification token generation and validation
				verTok, err := crypto.GenerateVerificationToken()
				if err != nil {
					t.Errorf("worker %d iter %d: GenerateVerificationToken failed: %v", id, iter, err)
					return
				}
				if len(verTok) != crypto.SessionTokenLength {
					t.Errorf("worker %d iter %d: invalid verification token length: %d", id, iter, len(verTok))
					return
				}
				if err := crypto.ValidateSessionTokenFormat(verTok); err != nil {
					t.Errorf("worker %d iter %d: ValidateSessionTokenFormat failed: %v", id, iter, err)
					return
				}

				// 3. Numeric OTP generation across valid bounds (6..10)
				otpLen := crypto.MinOTPLength + (iter % (crypto.MaxOTPLength - crypto.MinOTPLength + 1))
				otp, err := crypto.GenerateOTP(otpLen)
				if err != nil {
					t.Errorf("worker %d iter %d: GenerateOTP(%d) failed: %v", id, iter, otpLen, err)
					return
				}
				if len(otp) != otpLen {
					t.Errorf("worker %d iter %d: expected OTP length %d, got %d", id, iter, otpLen, len(otp))
					return
				}

				// 4. SHA-256 hashing and constant-time verification
				sessHash := crypto.HashSHA256(sessTok)
				if len(sessHash) != crypto.SHA256HexLength {
					t.Errorf("worker %d iter %d: invalid hash length: %d", id, iter, len(sessHash))
					return
				}

				if !crypto.VerifyHash(sessTok, sessHash) {
					t.Errorf("worker %d iter %d: VerifyHash positive match failed", id, iter)
					return
				}

				if crypto.VerifyHash("wrong-token", sessHash) {
					t.Errorf("worker %d iter %d: VerifyHash false positive on mismatched token", id, iter)
					return
				}

				// 5. HashToken consistency
				tokenHash := crypto.HashToken(sessTok)
				if !crypto.ConstantTimeCompare(sessHash, tokenHash) {
					t.Errorf("worker %d iter %d: HashToken != HashSHA256", id, iter)
					return
				}
			}
		}(workerID)
	}

	wg.Wait()
}

func BenchmarkGenerateSessionToken(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		tok, err := crypto.GenerateSessionToken()
		if err != nil {
			b.Fatalf("GenerateSessionToken failed: %v", err)
		}
		if len(tok) != crypto.SessionTokenLength {
			b.Fatalf("invalid length: %d", len(tok))
		}
	}
}

func BenchmarkValidateSessionTokenFormat(b *testing.B) {
	tok, err := crypto.GenerateSessionToken()
	if err != nil {
		b.Fatalf("GenerateSessionToken failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if err := crypto.ValidateSessionTokenFormat(tok); err != nil {
			b.Fatalf("ValidateSessionTokenFormat failed: %v", err)
		}
	}
}

func BenchmarkGenerateOTP(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		otp, err := crypto.GenerateOTP(crypto.DefaultOTPLength)
		if err != nil {
			b.Fatalf("GenerateOTP failed: %v", err)
		}
		if len(otp) != crypto.DefaultOTPLength {
			b.Fatalf("invalid OTP length: %d", len(otp))
		}
	}
}

func BenchmarkHashSHA256(b *testing.B) {
	tok, err := crypto.GenerateSessionToken()
	if err != nil {
		b.Fatalf("GenerateSessionToken failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		h := crypto.HashSHA256(tok)
		if len(h) != crypto.SHA256HexLength {
			b.Fatalf("invalid hash length: %d", len(h))
		}
	}
}

func BenchmarkConstantTimeCompare(b *testing.B) {
	tok, err := crypto.GenerateSessionToken()
	if err != nil {
		b.Fatalf("GenerateSessionToken failed: %v", err)
	}
	h1 := crypto.HashSHA256(tok)
	h2 := crypto.HashSHA256(tok)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if !crypto.ConstantTimeCompare(h1, h2) {
			b.Fatalf("ConstantTimeCompare returned false")
		}
	}
}

func BenchmarkVerifyHash(b *testing.B) {
	tok, err := crypto.GenerateSessionToken()
	if err != nil {
		b.Fatalf("GenerateSessionToken failed: %v", err)
	}
	h := crypto.HashSHA256(tok)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if !crypto.VerifyHash(tok, h) {
			b.Fatalf("VerifyHash returned false")
		}
	}
}
