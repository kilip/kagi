# ADR-0016: Ent extra-field mapping and store builder extensibility

Status: Proposed · Date: 2026-11-07

## Context
Kagi provides an Ent adapter via mixins (`UserMixin`, `AccountMixin`, `SessionMixin`, `VerificationMixin`, `RateLimitMixin`) and an `entc` code generation extension that generates store implementations directly into the host application's `package ent` ([ADR-0006](0006-ent-adapter-mixins-extension.md)).

While ADR-0006 established this code generation strategy to grant host applications full schema customization (extra columns, custom indexes, foreign key edges, and schema hooks), it explicitly left extra-field mapping as an open architectural question (tracked in Issue #24):
> *"Extra-field mapping is an open question (tracked in issue #24)."*

In real-world applications, entities representing users or accounts often carry application-specific attributes. Examples include:
- Multi-tenancy identifiers (`tenant_id`, `organization_id`)
- User profile information (`avatar_url`, `display_name`, `locale`, `timezone`)
- Authorization metadata (`role`, `permissions`, `is_admin`)
- Device or client tracking on sessions (`device_id`, `client_type`)

However, Kagi's core architecture enforces strict design constraints:
1. **Decoupled, HTTP-agnostic core domain ([ADR-0001](0001-http-agnostic-core.md), [ADR-0004](0004-data-model.md)):** Kagi domain structs (`kagi.User`, `kagi.Account`, `kagi.Session`, etc.) represent pure authentication identities and state. Kagi is an authentication library, not a user management CRM or authorization platform (PRD Principle 4).
2. **Compile-time type safety and adapter parity ([ADR-0007](0007-storage-ports-and-conformance.md)):** Core domain models must NOT carry untyped generic dictionaries (`map[string]any`) or rely on dynamic reflection. Untyped payloads degrade Go's type guarantees, risk runtime type-casting panics, break consistency across storage adapters (GORM, SQLC, memory, Redis), and pollute the public API.
3. **No circular dependencies:** The core Kagi module cannot import host application Ent packages.

A clear architectural strategy is required to define:
- Where application-specific fields reside.
- Schema constraints for custom fields on Ent schemas incorporating Kagi mixins.
- How write operations populate application fields during Kagi auth workflows.
- How read operations access application fields.
- Architectural patterns for complex application domain models.

## Decision

### 1. Pure authentication domain models
Kagi domain structs (`kagi.User`, `kagi.Account`, `kagi.Session`, `kagi.Verification`, `kagi.RateLimit`) remain strictly authentication-scoped. They will NOT include catch-all metadata dictionaries (`map[string]any`), generic payload slots, or dynamic reflection mechanisms. Kagi core services interact solely with authentication state.

Application-specific fields reside entirely on the host application's Ent schemas and generated entities, outside the Kagi core domain types.

### 2. Schema constraints for non-Kagi fields
Host applications can define arbitrary custom fields on Ent schemas that embed Kagi mixins. To maintain compatibility with Kagi's storage adapters:
- **Rule 1 (Optional fields):** Any non-Kagi schema field may be declared as `.Optional()`.
- **Rule 2 (Default values):** Any non-Kagi schema field may provide a default via `.Default(...)` or `.DefaultFunc(...)`.
- **Rule 3 (Required fields):** If a non-Kagi schema field is required (neither optional nor defaulted, such as a non-null `tenant_id`), it **must** be populated during write mutations via one of the write customization mechanisms described below. Otherwise, Ent's runtime validation will reject the insert or update operation with a validation error.

### 3. Dual-layer write customization
Because the Kagi Ent extension generates code directly into the host application's `package ent`, generated store constructors have compile-time access to the host's concrete builder types (`*UserCreate`, `*UserUpdateOne`, etc.).

Kagi provides two complementary mechanisms for setting application-specific fields during write operations:

#### A. Native Ent mutation hooks
Host applications can register standard Ent mutation hooks:
- **Schema-level hooks:** Declared in the schema definition via `func (User) Hooks() []ent.Hook`.
- **Client-level hooks:** Registered dynamically on the client via `client.User.Use(...)`.

Hooks intercept mutation operations (`ent.OpCreate`, `ent.OpUpdate`, `ent.OpUpdateOne`) and can inspect or mutate fields on `*ent.UserMutation`. This is particularly suitable for cross-cutting concerns, such as extracting a `tenant_id` from `context.Context` and setting it on the mutation:

```go
client.User.Use(func(next ent.Mutator) ent.Mutator {
    return hook.UserFunc(func(ctx context.Context, m *ent.UserMutation) (ent.Value, error) {
        if m.Op().Is(ent.OpCreate) {
            if tenantID, ok := tenant.FromContext(ctx); ok {
                m.SetTenantID(tenantID)
            }
        }
        return next.Mutate(ctx, m)
    })
})
```

#### B. Typed builder hooks via functional store options
The Kagi Ent extension generates functional options for each store and typed builder hook signatures:
- `UserCreateHook func(context.Context, *UserCreate, *kagi.User) error`
- `UserUpdateHook func(context.Context, *UserUpdateOne, *kagi.User) error`
- `AccountCreateHook func(context.Context, *AccountCreate, *kagi.Account) error`
- `AccountUpdateHook func(context.Context, *AccountUpdateOne, *kagi.Account) error`
- `SessionCreateHook func(context.Context, *SessionCreate, *kagi.Session) error`
- `VerificationCreateHook func(context.Context, *VerificationCreate, *kagi.Verification) error`
- `RateLimitCreateHook func(context.Context, *RateLimitCreate, *kagi.RateLimit) error`

Generated store constructors accept functional options:
```go
// Option signatures in generated package ent
type UserStoreOption func(*KagiUserStore)

func WithUserCreateHook(hook UserCreateHook) UserStoreOption
func WithUserUpdateHook(hook UserUpdateHook) UserStoreOption
```

The unified adapter constructor `NewKagiAdapter` accepts forwarding options:
```go
func WithUserStoreOptions(opts ...UserStoreOption) AdapterOption
func WithAccountStoreOptions(opts ...AccountStoreOption) AdapterOption
func WithSessionStoreOptions(opts ...SessionStoreOption) AdapterOption
func WithVerificationStoreOptions(opts ...VerificationStoreOption) AdapterOption
func WithRateLimitStoreOptions(opts ...RateLimitStoreOption) AdapterOption
```

Builder hooks run immediately before `builder.Save(ctx)` (or `builder.Exec(ctx)`). They provide direct, 100% type-safe setter access to the concrete Ent builder without casting or reflection:

```go
userStore := ent.NewKagiUserStore(client,
    ent.WithUserCreateHook(func(ctx context.Context, b *ent.UserCreate, u *kagi.User) error {
        if tenantID, ok := tenant.FromContext(ctx); ok {
            b.SetTenantID(tenantID)
        }
        b.SetRole("member")
        return nil
    }),
)
```

If any hook returns a non-nil error, the store aborts the mutation and propagates the error without executing the database query.

Store constructors remain fully backward-compatible when called without options (`NewKagiUserStore(client)`).

### 4. Direct Ent reads for application data
Kagi storage ports (`UserStore.GetByID`, `UserStore.GetByEmail`, etc.) return pure `*kagi.User` authentication structs. Mapping functions generated by the Ent extension only map the core fields defined in Kagi mixins.

When application services require application-specific attributes (e.g. displaying a user profile, checking authorization roles, or querying multi-tenant resources), they read Ent entities directly using the host application's `*ent.Client`:

```go
// Direct query utilizing Ent's full type safety and relationship traversal
user, err := entClient.User.Get(ctx, authUser.ID)
if err != nil {
    return err
}
fmt.Println(user.TenantID, user.Role, user.AvatarURL)
```

Routing application domain queries through Kagi auth ports is an anti-pattern. Keeping read operations separate preserves clean separation of concerns: Kagi handles authentication identity lifecycle, while the host application owns user domain queries and projections.

### 5. Linked 1:1 profile pattern for complex domains
For applications with rich user domains (multiple profile tables, organizational memberships, complex preferences), embedding all custom attributes directly onto the `User` entity can cause schema bloat and tight coupling.

For such architectures, the recommended pattern is a 1:1 linked entity (e.g., `Profile` or `UserProfile`) connected via an Ent edge:

```go
// Host schema: User
func (User) Edges() []ent.Edge {
    return []ent.Edge{
        edge.To("profile", Profile.Type).Unique(),
    }
}
```

The host application creates or manages the linked profile entity either via native Ent mutation hooks on `User` creation or within application-level service logic, maintaining a pristine boundary between authentication credentials and business domain models.

## Consequences

### Positive
- **Strict architectural boundaries:** Kagi core domain models remain lean, minimal, and focused exclusively on authentication state, adhering to ADR-0001 and ADR-0004.
- **Type safety:** Avoids untyped generic dictionaries (`map[string]any`) and runtime reflection. Custom fields are set and read through generated, type-safe Ent builders and entity structs.
- **Cross-adapter parity:** Storage ports remain uniform across all database backends (Ent, GORM, SQLC, memory, Redis) without introducing backend-specific leaky abstractions into core.
- **Developer ergonomics:** Host applications have full flexibility to choose between declarative Ent mutation hooks (schema/client-level) and explicit, typed builder hooks configured at store initialization.
- **Full backward compatibility:** Parameterless store and adapter constructors (`NewKagiUserStore(client)`, `NewKagiAdapter(client)`) remain completely valid and functional.
- **Query performance:** Kagi queries only select and map required authentication columns, avoiding unnecessary overhead when fetching auth sessions or verifying credentials.

### Tradeoffs and considerations
- **Two queries on sign-up if custom profile data is needed:** When an application registers a user via Kagi's auth service and immediately requires custom fields not present on `*kagi.User`, the host application must query Ent using the returned user ID. This is standard in decoupled architectures and mitigated by database primary key lookups.
- **Required fields need explicit hook configuration:** If a host schema defines required fields without default values, failing to configure a mutation or builder hook will trigger an Ent validation error at runtime. This constraint is documented in schema guidelines.
