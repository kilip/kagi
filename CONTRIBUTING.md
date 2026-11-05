# Contributing to Kagi

Thank you for your interest in contributing to **Kagi**! This document covers the development setup, architecture rules, and workflow conventions for the repository.

## Prerequisites & Setup

Kagi uses [mise](https://mise.jdx.dev/) to manage tool versions and development tasks, [lefthook](https://github.com/evilmartians/lefthook) for Git hooks, and [cocogitto](https://docs.cocogitto.io/) (`cog`) to verify commit messages.

1. Install required tools (`go`, `lefthook`, `cocogitto`):
   ```bash
   mise install
   ```
2. Install Git hooks:
   ```bash
   lefthook install
   ```

## Repository Layout

Kagi is a multi-module Go monorepo coordinated with `go.work`. Every directory with its own `go.mod` is an independent Go module:

| Path | Description |
| :--- | :--- |
| `/` | Core module (`github.com/kilip/kagi`): domain structs, storage ports, and auth services (`credential`, `oauth`, `otp`). |
| `oauth/` | OAuth provider presets built on `golang.org/x/oauth2`. |
| `internal/` | Internal packages (`crypto`, `ratelimit`, `clock`). |
| `adaptertest/` | Shared conformance test suite that every storage adapter must pass. |
| `adapter/ent/` | Ent storage adapter (`mixin` and `entc.Extension` for code generation). |
| `adapter/redis/` | Optional Redis `SecondaryStorage` adapter for session caching and rate limiting. |
| `adapter/gorm/` | GORM storage adapter (planned). |
| `adapter/sqlc/` | sqlc storage adapter (planned). |
| `http/fiber/` | Fiber HTTP handlers and middleware. |
| `examples/` | Runnable end-to-end example applications. |

## Architecture & Security Guidelines

- **HTTP-agnostic core:** Core (`/`) must never import `net/http` request/cookie handling or web frameworks like Fiber. Cookies, headers, and HTTP transport belong strictly in `http/*` modules.
- **Minimal core dependencies:** Core depends only on the Go standard library and `golang.org/x/*`. Never import `ent`, `gorm`, `sqlc`, Redis clients, or HTTP frameworks in the core module. Do not add new dependencies to core without prior discussion.
- **Port boundaries:** All persistence goes through core storage interfaces (`UserStore`, `AccountStore`, `SessionStore`, `VerificationStore`, `RateLimitStore`, `SecondaryStorage`). Do not leak adapter-specific types into core.
- **Redis is optional:** Everything must work with the primary database alone (including DB-backed rate limiting). `SecondaryStorage` (Redis) is an optional layer for caching sessions and accelerating rate limits.
- **Expiry & cleanup:** Always verify expiration on read (`expires_at > now`). Never rely on background cleanup for correctness. Do not spawn background goroutines by default.
- **Security rules:**
  - Hash passwords with `argon2id`.
  - Generate session tokens, OTP codes, and verification tokens with `crypto/rand`; store only hashes and compare in constant time.
  - Never log passwords, session tokens, OTP codes, or OAuth secrets.

## Testing & Code Style

- Write deterministic, table-driven tests.
- Use `internal/clock` instead of `time.Now()` in code under test.
- Any new or modified storage adapter behavior must be covered by the shared suite in `adaptertest/`.
- Mocks are generated with `go.uber.org/mock` (`mockgen`).

## Development Tasks

Run tasks across all workspace modules using `mise`:

```bash
# Format all Go files with gofmt
mise run fmt

# Run go vet across all workspace modules
mise run vet

# Run tests across all workspace modules
mise run test

# Regenerate mocks (go generate ./...)
mise run mock
```

## Git & Commit Conventions

1. **Branching:** Never commit directly to `main`. Create a feature or fix branch named `type/short-description` (e.g., `feat/opaque-session`, `fix/otp-expiry`).
2. **Atomic commits:** Keep one logical change per commit. Do not mix refactoring with behavior changes.
3. **Commit format:** Use **Conventional Commits** with an emoji and **no scope** (`type: <emoji> subject`). Commit messages are validated by `cog verify` via the `commit-msg` hook.

   | Type | Emoji | Example |
   | :--- | :---: | :--- |
   | `feat` | ✨ | `feat: ✨ add refresh token rotation` |
   | `fix` | 🐛 | `fix: 🐛 handle empty response body` |
   | `refactor` | ♻️ | `refactor: ♻️ extract query builder` |
   | `perf` | ⚡ | `perf: ⚡ cache parsed index` |
   | `test` | ✅ | `test: ✅ cover discount edge cases` |
   | `docs` | 📝 | `docs: 📝 document local setup` |
   | `build` | 📦 | `build: 📦 bump go to 1.27` |
   | `ci` | 👷 | `ci: 👷 cache go modules` |
   | `chore` | 🔧 | `chore: 🔧 update gitignore` |
   | `revert` | ⏪ | `revert: ⏪ revert refresh token rotation` |

   - **Subject:** Imperative mood, lowercase after the emoji, no trailing period, max ~72 characters including the emoji.
   - **Body (optional):** Explain *why*, not *what*, wrapped at ~72 characters.
   - **Breaking changes:** Add `!` after the type (`type!: <emoji> subject`) and include a `BREAKING CHANGE:` footer while keeping the same type emoji.

## Pull Request Checklist

Before opening a pull request, make sure:

- [ ] `mise run fmt` produces no diffs.
- [ ] `mise run vet` passes across all modules.
- [ ] `mise run test` passes across all modules.
- [ ] New or changed storage adapter functionality is covered in `adaptertest/`.
- [ ] Public types and functions have clear Go doc comments.
