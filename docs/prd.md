# Kagi — PRD (lite)

Status: Draft v0.3 · Date: 2026-11-05 · License: MIT · Module: `github.com/kilip/kagi`

## Problem
Go has no reusable, batteries-included auth library comparable to Better Auth: framework-agnostic, storage-pluggable, and customizable. Teams re-implement sessions, password hashing, OAuth and OTP in every project.

## Goal
Kagi ("key" in Japanese) is an open-source Go library for authentication. It provides a framework-agnostic core, pluggable storage adapters, and thin HTTP wrappers.

## Target users
Go backend developers who want to own their auth (no hosted service) and keep control of their database schema.

## MVP scope
- Email/password: sign up, sign in, sign out, password reset (via email verification)
- OAuth sign-in via `golang.org/x/oauth2`, presets: **Google**, **GitHub**
- OTP via email: passwordless login, 2FA, email verification
- Multiple login methods per user (account linking; auto-link only on provider-verified email)
- Opaque session tokens
- Database adapter: **ent**
- Rate limiting that works without Redis (DB-backed by default)
- Secondary storage adapter: **Redis** (optional)
- HTTP wrapper: **Fiber** (with OpenAPI 3.1 spec generated from Go comments)

## Out of MVP (deferred)
SMS delivery, TOTP and backup codes, JWT sessions, gorm and sqlc adapters, HTTP wrappers other than Fiber.

## Principles
1. Core depends only on stdlib and `golang.org/x/*`.
2. Adapters and HTTP wrappers are separate Go modules.
3. Secure by default (hashed secrets, constant-time compare, rate-limited OTP).
4. README-driven API design; stay small and stable (v0.x, then semver).
5. Users can fully customize their schema.

## Success criteria
- End-to-end example: Fiber + ent covering email/password, OAuth and OTP.
- Core has zero imports of ent, gorm, Fiber or Redis.
- Every adapter passes the shared conformance suite (`adaptertest`).
- All MVP features work without Redis; Redis only improves performance and multi-instance behavior.

## Open questions
- Mapping of user-defined extra fields between ent entities and domain structs (decide in P3).
- Release and tagging strategy for submodules (decide in P8).

## Resolved
- ID type: `string` (see [ADR-0011](adr/0011-string-ids.md)).
- OAuth presets at MVP: Google and GitHub.
- Account linking policy (see [ADR-0012](adr/0012-account-linking-policy.md)).
- OpenAPI 3.1 HTTP contract and sentinel error mapping (see [ADR-0013](adr/0013-openapi-v3-contract.md)).
- Password reset is in MVP scope.

## Roadmap
See [Roadmap MVP](https://github.com/users/kilip/projects/11) (target `v0.1.0`: 2027-03-10).

## Related
- [ADR-0001: HTTP-agnostic core service layer](adr/0001-http-agnostic-core.md)
- [ADR-0002: Multi-module monorepo](adr/0002-multi-module-monorepo.md)
- [ADR-0003: Opaque session tokens](adr/0003-opaque-sessions.md)
- [ADR-0004: Data model](adr/0004-data-model.md)
- [ADR-0005: OTP via email](adr/0005-email-otp.md)
- [ADR-0006: ent adapter via mixins and entc extension](adr/0006-ent-adapter-mixins-extension.md)
- [ADR-0007: Storage ports & conformance suite](adr/0007-storage-ports-and-conformance.md)
- [ADR-0008: OAuth via golang.org/x/oauth2](adr/0008-oauth-x-oauth2.md)
- [ADR-0009: Developer tooling](adr/0009-tooling.md)
- [ADR-0010: Expiry handling and cleanup](adr/0010-expiry-and-cleanup.md)
- [ADR-0011: String IDs in domain and ports](adr/0011-string-ids.md)
- [ADR-0012: Account linking policy](adr/0012-account-linking-policy.md)
- [ADR-0013: OpenAPI 3.1 contract via Go comments and sentinel error mapping](adr/0013-openapi-v3-contract.md)
