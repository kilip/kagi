# Implementation Plan: Spike entc Extension Generating Adapter into User's ent Package (Issue #7)

- **Issue:** [#7 Spike: entc extension generating the adapter into the user's ent package](https://github.com/kilip/kagi/issues/7)
- **Status:** Approved for Execution
- **Milestone:** M0 Foundation
- **Labels:** `area/ent`, `type/spike`
- **Related ADRs:**
  - [ADR-0006: ent adapter via mixins and an entc extension](../../docs/adr/0006-ent-adapter-mixins-extension.md)
  - [ADR-0007: Storage ports, optional secondary storage, conformance suite](../../docs/adr/0007-storage-ports-and-conformance.md)
  - [ADR-0011: String IDs in domain and ports](../../docs/adr/0011-string-ids.md)

---

## 1. Executive Summary

This plan outlines the architecture, developer experience, technical design, and execution strategy for GitHub Issue #7. This is a **spike** whose goal is to validate whether generating a Kagi storage adapter directly into a user's `ent` package using an `entc.Extension` (as decided in [ADR-0006](../../docs/adr/0006-ent-adapter-mixins-extension.md)) is viable, ergonomic, and maintainable.

This plan synthesizes inputs from three specialized perspectives:
1. **Product Manager (PM / DX):** Precise spike scoping, developer journey, acceptance criteria, throwaway vs. reusable boundaries, and downstream handoff into roadmap issues (#22–#25).
2. **Chief Architect:** Dependency decoupling, preventing import cycles, package namespaces, code-generation pipeline architecture, string-to-native ID conversions (ADR-0011), and formal validation/revision of ADR-0006.
3. **Go Backend Expert:** Concrete `entgo.io/ent/entc` extension mechanics, template embedding (`embed.FS`), AST inspection, schema annotations, and an isolated spike harness in `adapter/ent/internal/spike` with SQLite in-memory verification.

---

## 2. Product Manager Perspective

### 2.1 Spike Scope & Boundaries
- **In Scope (Spike Minimum Viable Proof):**
  - Define a minimal `UserMixin` (`adapter/ent/mixin/user.go`) with required core fields.
  * Define an `entc.Extension` (`adapter/ent/entc`) that contributes templates to `entc.Generate`.
  * Generate a conforming `kagi.UserStore` implementation directly inside the target `ent` package.
  * An isolated test harness (`adapter/ent/internal/spike`) running `entc.Generate` programmatically, compiling the generated code, and running basic operations with SQLite in-memory.
  * Document all findings, edge cases, and architectural trade-offs in a formal spike report confirming or refining ADR-0006.
- **Out of Scope for this Spike:**
  * Implementing all 5 entities (`Account`, `Session`, `Verification`, `RateLimit`) — deferred to #22 and #23.
  * Running the full `adaptertest` conformance suite against SQLite and Postgres — deferred to #25.
  * Complex extra-field bidirectional mapping engine — deferred to #24.

### 2.2 Target Developer Experience (DX)
The primary customer is a Go developer building an application with Ent who wants auth without handing over database ownership or wrestling with fixed schemas:

1. **User Schema Definition (`schema/user.go` in user app):**
   ```go
   package schema

   import (
       "entgo.io/ent"
       "entgo.io/ent/schema/field"
       "github.com/kilip/kagi/adapter/ent/mixin"
   )

   type User struct {
       ent.Schema
   }

   func (User) Mixin() []ent.Mixin {
       return []ent.Mixin{
           mixin.UserMixin{}, // injects email, name, email_verified, etc.
       }
   }

   func (User) Fields() []ent.Field {
       return []ent.Field{
           field.String("tenant_id").Optional(), // User's custom application fields
       }
   }
   ```

2. **User Code Generation Entrypoint (`generate.go` or `ent/entc.go` in user app):**
   ```go
   //go:build ignore

   package main

   import (
       "log"
       "entgo.io/ent/entc"
       "entgo.io/ent/entc/gen"
       kagientc "github.com/kilip/kagi/adapter/ent/entc"
   )

   func main() {
       err := entc.Generate("./schema", &gen.Config{}, entc.Extensions(kagientc.NewExtension()))
       if err != nil {
           log.Fatalf("running ent codegen: %v", err)
       }
   }
   ```

3. **Application Wiring:**
   ```go
   client, err := ent.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
   if err != nil {
       log.Fatal(err)
   }

   // The generated adapter is immediately available in package ent:
   userStore := ent.NewKagiUserStore(client)

   auth, err := kagi.New(kagi.Config{
       UserStore: userStore,
       // ...
   })
   ```

### 2.3 Deliverables & Acceptance Criteria
- [ ] **Acceptance Criterion 1:** Throwaway prototype generates code via `entc.Extension` and compiles cleanly without syntax or import errors.
- [ ] **Acceptance Criterion 2:** Prototype passes functional smoke tests (in-memory SQLite) verifying `kagi.UserStore.Create`, `GetByID`, and `GetByEmail`.
- [ ] **Acceptance Criterion 3:** Findings report written up in `docs/spikes/0007-entc-extension.md`; [ADR-0006](../../docs/adr/0006-ent-adapter-mixins-extension.md) confirmed or amended.

---

## 3. Chief Architect Perspective

### 3.1 Architecture & Import Graph

The architecture must respect strict layer boundaries. Core must never import Ent or know about database schemas. The code generation pipeline must be acyclic:

```
┌────────────────────────────────────────────────────────┐
│               github.com/kilip/kagi (Core)             │
│   - Domain: kagi.User                                  │
│   - Port:   kagi.UserStore                             │
│   - Errors: kagi.ErrNotFound, kagi.ErrDuplicateEmail   │
└───────────────────────────▲────────────────────────────┘
                            │ imports
┌───────────────────────────┴────────────────────────────┐
│      Generated User Package (e.g. app/ent)             │
│   - package ent                                        │
│   - client.go, user.go, predicate.go                   │
│   - kagi_user_store.go (generated by Kagi entc tmpl)   │
└───────────────────────────▲────────────────────────────┘
                            │ generated during `entc.Generate`
┌───────────────────────────┴────────────────────────────┐
│       github.com/kilip/kagi/adapter/ent/entc           │
│   - Implements entc.Extension                          │
│   - Embeds Go templates (templates/kagi_user_store.tmpl)│
└────────────────────────────────────────────────────────┘
```

#### Why Generating into `package ent` is Sound:
1. **Direct Access to Client & Predicates:** Because `kagi_user_store.go` resides in `package ent`, it has zero-friction access to `*Client`, `*UserClient`, and query predicates (`user.EmailEQ(email)`, `user.IDEQ(id)`).
2. **Zero Export Gymnastics:** No need to expose private methods or intermediate query helpers.
3. **No Circular Imports:**
   - Schema imports `kagi/adapter/ent/mixin`.
   - `entc` generator imports `kagi/adapter/ent/entc`.
   - Generated code in `package ent` imports `kagi` (core domain/ports).
   - Core has zero dependencies on `ent`.

### 3.2 ID Strategy & Conversions (ADR-0011 Compliance)
Core domain models use `string` for all entity IDs (`kagi.User.ID`). Ent schemas can have different ID types depending on user preference:
- Standard auto-increment `int` / `int64` (default in SQLite/PostgreSQL).
- `string` (e.g., ULID, NanoID).
- `uuid.UUID`.

**Template Strategy:**
The template inspects `$.ID.Type.String()` on the user entity:
- If `int`:
  - `ID -> string`: `strconv.Itoa(u.ID)`
  - `string -> ID`: `strconv.Atoi(id)` with error checking (returns `kagi.ErrNotFound` or invalid ID error on parse failure).
- If `string`: direct assignment.
- If `uuid.UUID`: `uuid.Parse(id)` / `u.ID.String()`.

For this spike, we test with the standard Ent default (`int` ID) to ensure non-trivial type conversion functions properly.

### 3.3 Evaluating ADR-0006: Key Questions for the Spike
1. **Template Brittleness:** Does generating `kagi_user_store.go` via `gen.Template` cause maintenance pain or break when ent updates?
2. **Package Namespace Pollution:** Does adding `NewKagiUserStore(client)` or attaching methods to `*Client` clash with user methods?
3. **Alternative Architecture Comparison:**
   - *Alternative A (ADR-0006):* Generate adapter directly into `package ent`.
   - *Alternative B:* Generate a subpackage `ent/kagi` that imports `ent`.
   - *Alternative C:* Static adapter package where user passes closures or mapping interfaces.

---

## 4. Go Backend Expert Perspective

### 4.1 Ent Extension Mechanics (`entgo.io/ent/entc`)

Ent provides the `entc.Extension` interface:
```go
type Extension interface {
    Hooks() []gen.Hook
    Annotations() []ent.Annotation
    Templates() []*gen.Template
    Options() []entc.Option
}
```

By embedding `entc.DefaultExtension`, we only implement `Templates() []*gen.Template`:
```go
package entc

import (
    "embed"
    "entgo.io/ent/entc"
    "entgo.io/ent/entc/gen"
)

//go:embed templates/*
var templateFS embed.FS

type Extension struct {
    entc.DefaultExtension
}

func NewExtension() *Extension {
    return &Extension{}
}

func (e *Extension) Templates() []*gen.Template {
    tmpl := gen.MustParse(gen.NewTemplate("kagi_user_store").ParseFS(templateFS, "templates/kagi_user_store.tmpl"))
    return []*gen.Template{tmpl}
}
```

### 4.2 Template Design (`templates/kagi_user_store.tmpl`)
The template will be conditionally rendered for the entity that incorporates `UserMixin` (detected via schema annotation or field presence):

```gotemplate
{{ define "kagi_user_store" }}
{{ $pkg := base $.Config.Package }}
{{ template "header" $ }}

import (
    "context"
    "strconv"
    "time"

    "github.com/kilip/kagi"
)

// KagiUserStore implements kagi.UserStore using the ent client.
type KagiUserStore struct {
    client *Client
}

// NewKagiUserStore creates a new kagi.UserStore backed by ent.
func NewKagiUserStore(client *Client) *KagiUserStore {
    return &KagiUserStore{client: client}
}

var _ kagi.UserStore = (*KagiUserStore)(nil)

// Create inserts a new user entity.
func (s *KagiUserStore) Create(ctx context.Context, u *kagi.User) error {
    b := s.client.User.Create().
        SetEmail(u.Email).
        SetName(u.Name).
        SetEmailVerified(u.EmailVerified).
        SetTwoFactorEnabled(u.TwoFactorEnabled).
        SetCreatedAt(u.CreatedAt).
        SetUpdatedAt(u.UpdatedAt)

    created, err := b.Save(ctx)
    if err != nil {
        if IsConstraintError(err) {
            return kagi.ErrDuplicateEmail
        }
        return err
    }

    u.ID = strconv.Itoa(created.ID)
    return nil
}

// GetByID retrieves a user by their string ID.
func (s *KagiUserStore) GetByID(ctx context.Context, id string) (*kagi.User, error) {
    intID, err := strconv.Atoi(id)
    if err != nil {
        return nil, kagi.ErrNotFound
    }

    u, err := s.client.User.Get(ctx, intID)
    if err != nil {
        if IsNotFound(err) {
            return nil, kagi.ErrNotFound
        }
        return nil, err
    }

    return toKagiUser(u), nil
}

// GetByEmail retrieves a user by their email address.
func (s *KagiUserStore) GetByEmail(ctx context.Context, email string) (*kagi.User, error) {
    u, err := s.client.User.Query().
        Where(user.EmailEQ(email)).
        Only(ctx)
    if err != nil {
        if IsNotFound(err) {
            return nil, kagi.ErrNotFound
        }
        return nil, err
    }

    return toKagiUser(u), nil
}

// Update updates an existing user.
func (s *KagiUserStore) Update(ctx context.Context, u *kagi.User) error {
    intID, err := strconv.Atoi(u.ID)
    if err != nil {
        return kagi.ErrNotFound
    }

    err = s.client.User.UpdateOneID(intID).
        SetEmail(u.Email).
        SetName(u.Name).
        SetEmailVerified(u.EmailVerified).
        SetTwoFactorEnabled(u.TwoFactorEnabled).
        SetUpdatedAt(time.Now()).
        Exec(ctx)
    if err != nil {
        if IsNotFound(err) {
            return kagi.ErrNotFound
        }
        if IsConstraintError(err) {
            return kagi.ErrDuplicateEmail
        }
        return err
    }
    return nil
}

// Delete removes a user by ID.
func (s *KagiUserStore) Delete(ctx context.Context, id string) error {
    intID, err := strconv.Atoi(id)
    if err != nil {
        return kagi.ErrNotFound
    }

    err = s.client.User.DeleteOneID(intID).Exec(ctx)
    if err != nil {
        if IsNotFound(err) {
            return kagi.ErrNotFound
        }
        return err
    }
    return nil
}

func toKagiUser(u *User) *kagi.User {
    return &kagi.User{
        ID:               strconv.Itoa(u.ID),
        Email:            u.Email,
        Name:             u.Name,
        EmailVerified:    u.EmailVerified,
        TwoFactorEnabled: u.TwoFactorEnabled,
        CreatedAt:        u.CreatedAt,
        UpdatedAt:        u.UpdatedAt,
    }
}
{{ end }}
```

### 4.3 Spike Harness Structure (`adapter/ent/internal/spike`)
To avoid polluting user-facing packages, the spike test harness lives in `adapter/ent/internal/spike`:
```
adapter/ent/
├── go.mod
├── mixin/
│   ├── doc.go
│   └── user.go             <-- UserMixin definition
├── entc/
│   ├── doc.go
│   ├── extension.go        <-- entc.Extension implementation
│   └── templates/
│       └── kagi_user_store.tmpl
└── internal/
    └── spike/
        ├── schema/
        │   └── user.go     <-- Ent schema applying UserMixin
        ├── ent/            <-- Generated files (ignored in git or temporary)
        └── spike_test.go   <-- Test runner for codegen + SQLite CRUD
```

---

## 5. Step-by-Step Implementation Breakdown

### Step 1: Module Dependencies
- In `adapter/ent/go.mod`:
  - Add `entgo.io/ent v0.14.3` (or latest stable compatible).
  - Add `github.com/mattn/go-sqlite3` for in-memory DB tests.
  - Require root module `github.com/kilip/kagi v0.0.0` (resolved via `go.work`).

### Step 2: Implement User Mixin
- File: `adapter/ent/mixin/user.go`
- Provide `UserMixin struct{ mixin.Schema }`.
- Fields:
  - `email`: string, unique, not empty.
  - `name`: string, default `""`.
  - `email_verified`: bool, default `false`.
  - `two_factor_enabled`: bool, default `false`.
  - `created_at`: time.Time, default `time.Now`.
  - `updated_at`: time.Time, default `time.Now`, update default `time.Now`.
- Annotation: add a custom schema annotation so `entc` can reliably identify which node is the Kagi User entity.

### Step 3: Implement `entc.Extension` & Template
- File: `adapter/ent/entc/extension.go`
- File: `adapter/ent/entc/templates/kagi_user_store.tmpl`
- Implement template registration using `embed.FS`.

### Step 4: Build Spike Test Harness
- Directory: `adapter/ent/internal/spike`
- File: `adapter/ent/internal/spike/schema/user.go`
  - Minimal schema implementing `mixin.UserMixin{}`.
- File: `adapter/ent/internal/spike/spike_test.go`
  - Test 1: `TestEntcGeneration`: runs `entc.Generate` with `kagientc.NewExtension()`, verifies exit code 0 and verifies `kagi_user_store.go` exists.
  - Test 2: `TestKagiUserStore_SQLite`:
    - Opens SQLite `:memory:` with `_fk=1`.
    - Auto-migrates schema (`client.Schema.Create(ctx)`).
    - Instantiates `store := ent.NewKagiUserStore(client)`.
    - Asserts `var _ kagi.UserStore = store`.
    - Tests `Create`, `GetByID`, `GetByEmail`, `Update`, `Delete`, duplicate email error handling.

### Step 5: Write Findings & Update ADR-0006
- File: `docs/spikes/0007-entc-extension.md`
  - Document all architectural observations.
  - Confirm [ADR-0006](../../docs/adr/0006-ent-adapter-mixins-extension.md) as valid, or propose minor amendments.
  - Detail concrete specifications for Issue #22 (full mixins) and Issue #23 (full extension).

---

## 6. Verification Plan

```bash
# 1. Format and tidy dependencies
go work sync
cd adapter/ent && go mod tidy

# 2. Run the spike generator and tests
cd adapter/ent && go test -v ./internal/spike/...

# 3. Workspace validation
mise run fmt
mise run vet
mise run test
```

---

## 7. Risks & Mitigations

| Risk | Impact | Mitigation |
| :--- | :--- | :--- |
| **Ent template API changes across versions** | Generated code breaks on newer ent versions | Pin tested `entgo.io/ent` version and add CI integration test running against minimum and latest supported ent versions. |
| **Import loop between user app and Kagi** | Compilation failure in user project | Generated code only imports `github.com/kilip/kagi` (core domain/ports); core has 0 external ORM dependencies. Verified in spike test. |
| **Name collision with user-defined methods** | Compiler error on `*Client` or `*User` | Use distinctive constructor `NewKagiUserStore(client)` and struct name `KagiUserStore` rather than polluting `*Client` methods. |
| **Custom ID types (int vs UUID vs string)** | ID conversion panic or error | Template inspects `$.ID.Type` and generates appropriate conversion branches (`strconv` vs `uuid.Parse`). |
