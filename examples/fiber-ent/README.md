# Kagi Fiber + Ent Example

This example demonstrates how to build a complete email and password authentication system using [Kagi](https://github.com/kilip/kagi), the [Fiber](https://gofiber.io/) web framework, and the [Ent](https://entgo.io/) entity framework.

## Overview

- **Framework**: Fiber v2 (`github.com/gofiber/fiber/v2`)
- **ORM / Storage**: Ent (`entgo.io/ent`) with SQLite
- **Auth Engine**: Kagi (`github.com/kilip/kagi`) with the Fiber HTTP adapter (`github.com/kilip/kagi/http/fiber`)

### Zero Redis Dependency

This setup operates **completely without Redis** (`SecondaryStorage: nil`). SQLite handles all persistent and operational storage needs via Ent adapters:

- **User Store**: User entity persistence
- **Account Store**: Password / credential credentials linked to users
- **Session Store**: Database-backed opaque session tokens
- **Verification Store**: Verification and OTP tokens
- **Rate Limit Store**: Database-backed sliding window rate limiting

Kagi does not require Redis for session management or rate limiting; setting `SecondaryStorage: nil` is fully supported for simpler self-hosted architectures.

---

## Prerequisites

- **Go 1.27** (or managed via [mise](https://mise.jdx.dev/))
- SQLite development libraries (used by `go-sqlite3`)

---

## Running the Application

From this directory (`examples/fiber-ent`):

```bash
go run .
```

By default, the server runs on `http://127.0.0.1:3000` and creates a local SQLite database `kagi_example.db`.

Configuration can be customized via environment variables:

- `DATABASE_URL`: SQLite connection string (default: `file:kagi_example.db?cache=shared&_fk=1`)
- `KAGI_SECRET`: Secret key used for signing cookies and tokens (minimum 32 bytes)
- `PORT`: Server listening port (default: `3000`)

---

## Step-by-Step curl Walkthrough

This walkthrough demonstrates the end-to-end authentication lifecycle using `curl` and a cookie jar (`cookies.txt`).

### 1. Retrieve CSRF Token

Fetch the CSRF token and store the `kagi_csrf` cookie in `cookies.txt`:

```bash
CSRF_TOKEN=$(curl -s -c cookies.txt http://localhost:3000/auth/csrf | jq -r '.csrf_token')
echo "CSRF Token: $CSRF_TOKEN"
```

### 2. Sign Up

Register a new user account with email and password, passing the CSRF cookie and `X-CSRF-Token` header:

```bash
curl -i -s -b cookies.txt -c cookies.txt \
  -X POST http://localhost:3000/auth/sign-up \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -d '{
    "email": "user@example.com",
    "password": "ValidPassword123!",
    "name": "Example User"
  }'
```

*Expected response*: HTTP `201 Created` with JSON containing the registered user details.

### 3. Sign In

Sign in using the created account credentials. This issues an authenticated `kagi_session` cookie stored in `cookies.txt`:

```bash
curl -i -s -b cookies.txt -c cookies.txt \
  -X POST http://localhost:3000/auth/sign-in \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -d '{
    "email": "user@example.com",
    "password": "ValidPassword123!"
  }'
```

*Expected response*: HTTP `200 OK` with JSON containing the authenticated `user` and `session` objects, and a `Set-Cookie: kagi_session=...` header.

### 4. Access Protected Endpoint

Access the protected `/me` endpoint using the session cookie saved in `cookies.txt`:

```bash
curl -i -s -b cookies.txt http://localhost:3000/me
```

*Expected response*: HTTP `200 OK` returning the authenticated user and current session payload.

### 5. Sign Out

Revoke the session and invalidate the session cookie:

```bash
curl -i -s -b cookies.txt -c cookies.txt \
  -X POST http://localhost:3000/auth/sign-out \
  -H "X-CSRF-Token: $CSRF_TOKEN"
```

*Expected response*: HTTP `200 OK` with the `kagi_session` cookie cleared.

### 6. Verify Access Revoked

Verify that access to the protected `/me` endpoint is now rejected:

```bash
curl -i -s -b cookies.txt http://localhost:3000/me
```

*Expected response*: HTTP `401 Unauthorized`.

---

## Ent Schema Customization & Code Generation

Kagi provides schema mixins and code generation extensions for Ent (`github.com/kilip/kagi/adapter/ent`):

### Schema Definitions

The schema definitions live in `schema/`:
- `schema/user.go`: Includes `mixin.UserMixin{}`
- `schema/account.go`: Includes `mixin.AccountMixin{}`
- `schema/session.go`: Includes `mixin.SessionMixin{}`
- `schema/verification.go`: Includes `mixin.VerificationMixin{}`
- `schema/rate_limit.go`: Includes `mixin.RateLimitMixin{}`

You can add custom fields, indexes, or hooks to any of these schemas alongside Kagi's mixins.

### Code Generation

Code generation uses `entc.go` configured with Kagi's Ent extension (`kagientc.NewExtension()`):

```go
// generate.go
package main

//go:generate go run entc.go
```

Whenever you modify any schema in `schema/`, regenerate the Ent client code and Kagi store adapters:

```bash
go generate ./...
```
