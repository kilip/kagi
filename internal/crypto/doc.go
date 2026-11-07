// Package crypto provides cryptographic utilities for the kagi core, including
// secure password hashing and verification using Argon2id with OWASP-recommended
// parameters, standard PHC string formatting, cryptographically secure token
// generation, numeric OTP generation with rejection sampling, SHA-256 hashing,
// constant-time comparisons, timing attack mitigations, HKDF subkey derivation
// (RFC 5869), and masked HMAC double-submit CSRF protection (ADR-0015).
package crypto
