# ADR-0005: OTP via email, `Mailer` interface

Status: Accepted · Date: 2026-11-05

## Context
OTP is needed for passwordless login, 2FA and email verification. A library should not choose the mail provider.

## Decision
MVP supports email OTP only, for all three use cases. Kagi defines a `Mailer` interface implemented by the host application; templates are overridable. Codes are stored hashed with short TTL and an attempt limit. Rate limiting per email and per IP is mandatory: it is DB-backed by default (`RateLimitStore`) and uses `SecondaryStorage` (Redis) when configured. 2FA puts the session in a pending state until the second factor is verified.

## Consequences
- No SMTP/SES code in core.
- OTP works end-to-end without Redis.
- TOTP, backup codes and SMS are deferred.
