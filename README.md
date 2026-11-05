# Kagi (鍵)

Reusable, framework-agnostic authentication library for Go. *Kagi* (鍵) means "key" in Japanese.

> **Status:** Early development (`v0.x`). The API is under active design and not yet stable.

## Overview

Kagi gives Go backend teams a self-hosted, batteries-included authentication layer without locking them into a web framework, ORM, or fixed database schema. It provides:

- A **framework-agnostic core** that depends only on the Go standard library and `golang.org/x/*`.
- **Pluggable storage adapters** so you keep full ownership of your database schema.
- **Thin HTTP wrappers** that map core services onto your router of choice.

## Features (MVP Scope)

- **Email & Password:** Sign up, sign in, sign out, and password reset with `argon2id` password hashing.
- **OAuth 2.0:** Social sign-in built on `golang.org/x/oauth2` with Google and GitHub presets.
- **Email OTP:** Passwordless sign-in, two-factor authentication (2FA), and email verification with attempt limits and per-email/per-IP rate limiting.
- **Account Linking:** Multiple login methods linked to a single user account; OAuth sign-ins auto-link only when the provider verifies the email.
- **Opaque Sessions:** High-entropy `crypto/rand` tokens stored as hashes in the database.
- **Optional Secondary Storage (Redis):** Session caching and fast rate limiting via Redis, with full fallback to database-backed rate limiting when Redis is not configured.
- **Safe Expiry & Cleanup:** Strict read-time expiry checks (`expires_at > now`) plus idempotent, batched cleanup helpers (`Cleanup` / opt-in `RunCleanup`).

## Architecture & Modules

Kagi is organized as a multi-module monorepo so your application only pulls in the dependencies it actually uses:

| Module / Path | Purpose | Status |
| :--- | :--- | :--- |
| `github.com/kilip/kagi` (`/`) | Core domain models, storage ports, mailer port, and auth services | MVP |
| `github.com/kilip/kagi/oauth` (`./oauth`) | OAuth 2.0 provider presets | MVP |
| `github.com/kilip/kagi/adaptertest` (`./adaptertest`) | Shared conformance suite for storage adapters | MVP |
| `github.com/kilip/kagi/adapter/ent` (`./adapter/ent`) | Ent mixins and `entc.Extension` codegen adapter | MVP |
| `github.com/kilip/kagi/adapter/redis` (`./adapter/redis`) | Optional Redis `SecondaryStorage` adapter | MVP |
| `github.com/kilip/kagi/http/fiber` (`./http/fiber`) | Fiber HTTP handlers and middleware | MVP |
| `github.com/kilip/kagi/examples/fiber-ent` (`./examples/fiber-ent`) | End-to-end Fiber + Ent example app | MVP |
| `github.com/kilip/kagi/adapter/gorm` (`./adapter/gorm`) | GORM storage adapter | Planned |
| `github.com/kilip/kagi/adapter/sqlc` (`./adapter/sqlc`) | sqlc storage adapter | Planned |

## Design Principles

1. **Zero framework/ORM lock-in in core:** Core never imports `ent`, `gorm`, `sqlc`, Redis, or Fiber.
2. **Schema ownership stays with you:** Using Ent mixins and `entc` code generation, Kagi integrates directly into your existing Ent schema and entities.
3. **Secure by default:** `argon2id` password hashes, hashed session/OTP/verification tokens generated with `crypto/rand`, constant-time comparisons, and built-in rate limiting.
4. **Everything works without Redis:** The primary database is always the source of truth; Redis is an optional performance and multi-instance enhancement.

## Documentation

- [Product requirements (PRD)](./docs/prd.md)
- [Architecture decision records](./docs/adr/README.md)
- [Roadmap and progress (GitHub Project)](https://github.com/users/kilip/projects/11)

## Contributing

Contributions, issues, and feedback are welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, architecture rules, and commit conventions before submitting a pull request.

## License

MIT — see [LICENSE](./LICENSE).
