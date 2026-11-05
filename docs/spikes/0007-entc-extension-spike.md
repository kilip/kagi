# Spike Findings: entc Extension Generating Adapter into User's ent Package

- **Issue:** [#7 Spike: entc extension generating the adapter into the user's ent package](https://github.com/kilip/kagi/issues/7)
- **Status:** Complete · Feasibility Confirmed
- **Date:** 2026-11-05
- **Related ADR:** [ADR-0006: ent adapter via mixins and an entc extension](../adr/0006-ent-adapter-mixins-extension.md)

---

## 1. Executive Summary

The spike successfully demonstrated that generating the Kagi storage adapter directly into the user's `ent` package using an `entc.Extension` is **fully feasible, performant, and architecturally sound**.

A working prototype was built with:
1. `UserMixin` (`adapter/ent/mixin/user.go`) specifying core required fields and custom schema annotations (`KagiUser`).
2. An `entc.Extension` (`adapter/ent/entc`) injecting code generation templates via `embed.FS`.
3. An isolated test harness (`adapter/ent/internal/spike`) that:
   - Successfully executes `entc.Generate` without code generation errors.
   - Generates `kagi_user_store.go` directly inside the target `ent` package.
   - Compiles cleanly and passes all lifecycle tests (Create, GetByID, GetByEmail, Update, Delete, duplicate email constraint handling) against an in-memory SQLite database.

**Verdict on ADR-0006:** **Confirmed without architectural revision.**

---

## 2. Key Technical Findings

### 2.1 Package Namespace & Import Graph
- **Zero Circular Dependencies:**
  - Kagi Core (`github.com/kilip/kagi`) remains 100% agnostic of Ent, importing zero external database libraries.
  - The generated file `kagi_user_store.go` is part of `package ent`. It imports `github.com/kilip/kagi` and local subpackages (e.g. `spike/ent/user` for predicates).
  - The extension (`adapter/ent/entc`) only depends on `entgo.io/ent/entc` and `entgo.io/ent/entc/gen`.
- **Direct Access to Client & Predicates:**
  - Because the adapter code resides in `package ent`, it has natural access to `*Client`, `*UserClient`, and query predicates (`user.EmailEQ(...)`) without requiring any export workarounds.

### 2.2 ID Type Conversions (ADR-0011 Compliance)
- Kagi domain structs and storage ports use `string` for all entity IDs.
- The template inspects the schema's `ID.Type`:
  - `int` / `int64`: Converted using `strconv.Itoa` / `strconv.Atoi` / `strconv.ParseInt`.
  - `string`: Direct assignment.
  - `uuid.UUID`: Converted using `uuid.Parse` and `.String()`.
- The prototype confirmed that standard auto-increment integer IDs work transparently with Kagi's string IDs, properly returning `kagi.ErrUserNotFound` when an unparseable ID is passed.

### 2.3 Toolchain & Dependency Notes
- When using modern Go toolchains (Go 1.24+ / Go 1.27), `entc.Generate` requires `golang.org/x/tools >= v0.52.0` (or `v0.30.0+` depending on toolchain) to avoid `package "context" without types was imported from "entgo.io/ent"`.
- `adapter/ent/go.mod` is configured with modern module dependencies ensuring robust builds across the monorepo workspace.

---

## 3. Recommended Follow-up Specifications

With the feasibility proven by this spike, the downstream issues can proceed with clear specifications:

1. **Issue #22 (ent mixins: User, Account, Session, Verification, RateLimit):**
   - Implement the remaining 4 mixins under `adapter/ent/mixin/` following the pattern proven in `user.go`.
   - Provide custom schema annotations (`KagiAccount`, `KagiSession`, `KagiVerification`, `KagiRateLimit`) on each mixin.

2. **Issue #23 (entc extension generating the Kagi adapter):**
   - Expand `adapter/ent/entc` templates to generate adapters for all 5 ports: `UserStore`, `AccountStore`, `SessionStore`, `VerificationStore`, and `RateLimitStore`.
   - Add a coordinator constructor `NewKagiAdapter(client *Client)` returning all 5 stores.

3. **Issue #24 (ent extra-field mapping):**
   - Users can add custom fields to their schemas (e.g., `tenant_id`, `avatar_url`).
   - The spike confirms that extra fields in user schemas do not interfere with Kagi's generated queries, provided non-Kagi fields are either optional or have default values. Custom hooks or mapping callbacks can be introduced if bidirectional sync of application-specific fields is needed.

4. **Issue #25 (Run adaptertest against ent on SQLite and Postgres):**
   - Connect the generated stores to the `adaptertest` conformance test suite.
