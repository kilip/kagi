# ADR-0013: OpenAPI 3.1 contract via Go comments and sentinel error mapping

Status: Accepted · Date: 2026-11-05

## Context
Host applications and frontend clients need a machine-readable HTTP contract for Kagi's authentication endpoints. At the same time, the core module must remain strictly HTTP-agnostic with minimal dependencies ([ADR-0001](0001-http-agnostic-core.md)), and sessions in the MVP use opaque tokens delivered via cookies ([ADR-0003](0003-opaque-sessions.md)).

## Decision
- **OpenAPI 3.1 from Go code comments:** Kagi targets **OpenAPI 3.1.0**, generated from declarative Go doc comments (`// @Summary`, `// @Param`, `// @Success`, `// @Failure`, etc.) using `swaggo/swag` v2 (`swag init --v3.1`, managed in `mise.toml`) via `mise run openapi`. This extends the developer tooling defined in [ADR-0009](0009-tooling.md).
- **Lives strictly in `http/*`:** OpenAPI annotations, request/response DTOs, and generated specs live in the HTTP wrapper module (`http/fiber` for the MVP), never in the core module. Generating the spec via the CLI keeps runtime `go.mod` dependencies clean.
- **Cookie authentication for MVP:** The OpenAPI security scheme defines cookie-based authentication (`in: cookie`, `HttpOnly`, `Secure`, `SameSite`) matching [ADR-0003](0003-opaque-sessions.md). Bearer/header token schemes are out of MVP scope.
- **Sentinel errors in core, mapped in `http/*`:** The core module exposes domain failures as Go sentinel errors (`errors.New`, checked via `errors.Is`) in `errors.go` (e.g. `ErrInvalidCredentials`, `ErrRateLimitExceeded`). The HTTP wrapper translates these sentinel errors into HTTP status codes and a uniform JSON `ErrorResponse` schema documented in OpenAPI.
- **Endpoint paths defined during implementation:** Exact route paths and the complete set of sentinel errors are finalized as each handler and service is implemented (for example, `POST /sign-in`, `POST /otp/verify`).

Example handler annotation in `http/fiber`:

```go
// signIn handles email/password authentication.
//
//	@Summary		Sign in with email and password
//	@Tags			credential
//	@Accept			json
//	@Produce		json
//	@Param			request	body		signInRequest	true	"Credentials"
//	@Success		200		{object}	authResponse
//	@Failure		400,401	{object}	ErrorResponse
//	@Failure		429		{object}	ErrorResponse
//	@Router			/sign-in [post]
```

## Consequences
- Documentation stays colocated with the HTTP handlers in `http/fiber` and produces standard OpenAPI 3.1 artifacts without adding runtime dependencies to core or `http/fiber`.
- Core error handling stays idiomatic (`errors.Is`) and completely decoupled from HTTP status codes.
- Future HTTP wrappers (`net/http`, `gin`) must map core sentinel errors to the same HTTP status codes and response schemas to keep the contract consistent across frameworks.
