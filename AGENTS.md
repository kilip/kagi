# AGENTS.md

Guidance for AI coding agents working on Kagi.

## Project
Kagi is an open-source (MIT) reusable authentication library for Go. Module path: `github.com/kilip/kagi`.

MVP scope: email/password (including password reset), OAuth (Google and GitHub presets), and OTP (email only: passwordless login, 2FA, email verification), with multiple login methods per user.

## Docs
- Product scope: `docs/prd.md`. Architecture decisions: `docs/adr/` (index in `docs/adr/README.md`). Read the relevant ADRs before changing ports, the data model, security behavior or core dependencies.
- Decisions that are expensive to reverse need a new ADR from `docs/adr/template.md`. Never rewrite an accepted ADR; supersede it.
- Work is tracked in the GitHub Project (https://github.com/users/kilip/projects/11) and repo milestones M0–M8.

## Layout
Multi-module monorepo with `go.work`. Each directory with its own `go.mod` is a separate module.

- `/` core module: domain structs, storage ports, services (credential, oauth, otp). No HTTP.
- `oauth/` OAuth provider presets.
- `internal/` crypto, ratelimit, clock.
- `adaptertest/` conformance suite that every storage adapter must pass.
- `adapter/ent` (MVP), `adapter/gorm`, `adapter/sqlc`, `adapter/redis`: separate modules.
- `adapter/ent/mixin` and `adapter/ent/entc`: ent mixins and an `entc.Extension` that generates the adapter into the user's own ent package.
- `http/fiber`: Fiber handlers and middleware (separate module).
- `examples/`: runnable examples (separate modules).

## Architecture rules
- Core depends only on the standard library and `golang.org/x/*`. Never import ent, gorm, sqlc, Redis clients or Fiber from core.
- Core is HTTP-agnostic. Cookies, headers and requests are handled only in `http/*` wrappers.
- Storage is accessed through ports (`UserStore`, `AccountStore`, `SessionStore`, `VerificationStore`, `RateLimitStore`, `SecondaryStorage`). Adapter types must not leak into core.
- Data model: `user`, `account` (one row per login method), `session`, `verification`, `rate_limit`.
- Entity IDs are `string` in domain structs and ports; adapters convert to native column types (ADR-0011).
- Account linking: auto-link an OAuth sign-in to an existing user only when the provider asserts a verified email; never unlink a user's last login method (ADR-0012).
- Sessions are opaque tokens. Store only the hash. `SecondaryStorage` (Redis) is optional: when configured it caches sessions and handles rate limits; the database is always the source of truth. Everything must work without Redis (DB-backed rate limiting).
- Email is sent through a `Mailer` interface implemented by the host app. Do not add SMTP/SES code to core.
- OAuth is built on `golang.org/x/oauth2`.
- Keep the public API small. Prefer `internal/` for anything not meant to be imported.

## Expiry and cleanup
- Always check expiry on read (`expires_at > now`); never rely on cleanup for correctness.
- A single `Cleanup(ctx)` handles expired sessions, verifications and rate limits: idempotent, batched deletes.
- Do not start goroutines by default. Scheduling is the host app's job; `RunCleanup(ctx, interval)` is an opt-in helper.
- Index expiry columns; update rate-limit counters with atomic upserts.

## Security rules
- Passwords: argon2id.
- Session tokens, OTP codes and verification tokens: generate with `crypto/rand`, store hashed, compare in constant time.
- OTP: short TTL, attempt limit, rate limiting per email and per IP.
- Never log passwords, tokens, OTP codes or OAuth secrets.

## Tooling
- `mise` manages tools and tasks: `mise run test`, `mise run vet`, `mise run fmt`, `mise run mock`, `mise run openapi`.
- Mocks use `go.uber.org/mock` (`mockgen`). OpenAPI 3.1 specs use `swaggo/swag` v2 (`swag`).
- Git hooks via `lefthook`. Commits must follow Conventional Commits (checked by `cog verify`).

## Git & commits
- Use **Conventional Commits** with an emoji (no scope): `type: <emoji> subject`
  - Put the emoji right after `: `, keeping the `type:` prefix parseable.
  - Use this exact emoji mapping:

    | Type       | Emoji | Example                                  |
    | ---------- | ----- | ---------------------------------------- |
    | `feat`     | ✨    | `feat: ✨ add refresh token rotation`     |
    | `fix`      | 🐛    | `fix: 🐛 handle empty response body`      |
    | `refactor` | ♻️    | `refactor: ♻️ extract query builder`      |
    | `perf`     | ⚡    | `perf: ⚡ cache parsed index`             |
    | `test`     | ✅    | `test: ✅ cover discount edge cases`      |
    | `docs`     | 📝    | `docs: 📝 document local setup`           |
    | `build`    | 📦    | `build: 📦 bump go to 1.24`               |
    | `ci`       | 👷    | `ci: 👷 cache go modules`                 |
    | `chore`    | 🔧    | `chore: 🔧 update gitignore`              |
    | `revert`   | ⏪    | `revert: ⏪ revert refresh token rotation` |

  - Subject: imperative mood, lowercase after emoji, no trailing period, max ~72 chars including emoji.
  - Body (when needed): explain *why*, not *what*; wrap at ~72 chars.
  - Breaking changes: add `!` after type (`type!: <emoji> subject`) and a `BREAKING CHANGE:` footer; keep the same type emoji.
- One logical change per commit. Do not mix refactors with behavior changes.
- Never commit directly to `main`/`master`. Work on a branch named `type/short-description` (e.g. `feat/opaque-session`, `fix/otp-expiry`).
- Never skip hooks (`--no-verify`) unless explicitly instructed.

## Conventions
- Always plan first (outline affected files, approach, and reasoning) and wait for explicit user approval before executing tasks or writing code.
- Run `gofmt` and `go vet` before finishing. Run tests in every module you touched.
- New or changed adapter behavior must be covered by `adaptertest`.
- Write table-driven tests. Use `internal/clock` instead of `time.Now()` in code under test.
- Do not add dependencies to the core module without a clear reason.
