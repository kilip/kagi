// Package ent provides the Ent storage adapter architecture for Kagi.
//
// # Architecture Overview
//
// Kagi employs a code-generation strategy for its Ent adapter (ADR-0006).
// Because Ent generates code per project, storage implementations (such as
// KagiUserStore, KagiAccountStore, KagiSessionStore, KagiVerificationStore,
// and KagiRateLimitStore) are generated directly into the host application's
// package ent via the extension in github.com/kilip/kagi/adapter/ent/entc.
//
// Host applications define their own Ent schemas by embedding Kagi mixins
// (from github.com/kilip/kagi/adapter/ent/mixin), allowing full control over
// columns, indexes, relationships, and hooks.
//
// # Extra-Field Architecture (ADR-0016)
//
// In real-world systems, user entities often carry application-specific attributes
// such as multi-tenant identifiers (tenant_id), profile data (avatar_url,
// display_name), or authorization roles. Kagi domain structs (kagi.User,
// kagi.Account, etc.) remain strictly authentication-scoped (ADR-0001, ADR-0004),
// avoiding untyped metadata dictionaries (map[string]any) or dynamic reflection.
// Application-specific fields reside entirely on the host application's Ent schemas
// and generated entities.
//
// # Schema Constraints for Custom Fields
//
// Host applications can define arbitrary custom fields on Ent schemas that embed
// Kagi mixins. Non-Kagi schema fields must satisfy one of three rules:
//
//  1. Optional fields: The field is declared with .Optional().
//  2. Default values: The field defines a default using .Default(...) or .DefaultFunc(...).
//  3. Required fields populated via hooks: If a field is required (neither optional
//     nor defaulted, such as a non-null tenant_id), it must be populated during
//     write mutations via typed builder hooks or native Ent mutation hooks.
//     Otherwise, Ent's runtime validation will reject the mutation.
//
// Example schema definition:
//
//	type User struct {
//		ent.Schema
//	}
//
//	func (User) Mixin() []ent.Mixin {
//		return []ent.Mixin{
//			mixin.UserMixin{},
//		}
//	}
//
//	func (User) Fields() []ent.Field {
//		return []ent.Field{
//			field.String("tenant_id").NotEmpty(), // required; must be populated via hook
//			field.String("avatar_url").Optional(), // optional
//			field.String("role").Default("member"), // defaulted
//		}
//	}
//
// # Writing Custom Fields: Typed Builder Hooks
//
// Because generated stores reside inside the host's package ent, generated
// store constructors provide compile-time type-safe builder hooks via functional
// options. Builder hooks execute immediately before builder.Save(ctx) and receive
// the concrete Ent builder alongside the Kagi domain model.
//
// Using WithUserCreateHook and WithUserUpdateHook:
//
//	userStore := ent.NewKagiUserStore(client,
//		ent.WithUserCreateHook(func(ctx context.Context, b *ent.UserCreate, u *kagi.User) error {
//			if tenantID, ok := tenant.FromContext(ctx); ok {
//				b.SetTenantID(tenantID)
//			}
//			b.SetRole("member")
//			return nil
//		}),
//		ent.WithUserUpdateHook(func(ctx context.Context, b *ent.UserUpdateOne, u *kagi.User) error {
//			if u.Name != "" {
//				b.SetName(u.Name)
//			}
//			return nil
//		}),
//	)
//
// When using the unified NewKagiAdapter, store options are forwarded via WithUserStoreOptions:
//
//	adapter := ent.NewKagiAdapter(client,
//		ent.WithUserStoreOptions(
//			ent.WithUserCreateHook(func(ctx context.Context, b *ent.UserCreate, u *kagi.User) error {
//				b.SetTenantID("tenant-123")
//				return nil
//			}),
//		),
//	)
//
// If a hook returns an error, the store aborts the mutation and propagates the error.
//
// # Writing Custom Fields: Native Ent Mutation Hooks
//
// Host applications can also use native Ent mutation hooks registered at the schema
// or client level. This is ideal for cross-cutting concerns such as multi-tenancy:
//
//	client.User.Use(func(next ent.Mutator) ent.Mutator {
//		return hook.UserFunc(func(ctx context.Context, m *ent.UserMutation) (ent.Value, error) {
//			if m.Op().Is(ent.OpCreate) {
//				if tenantID, ok := tenant.FromContext(ctx); ok {
//					m.SetTenantID(tenantID)
//				}
//			}
//			return next.Mutate(ctx, m)
//		})
//	})
//
// # Reading Custom Fields: Direct ent.Client Queries
//
// Kagi storage ports (e.g. UserStore.GetByID, UserStore.GetByEmail) return pure
// *kagi.User domain structs containing only authentication fields.
//
// When application services require application-specific attributes (such as displaying
// user profiles or checking permissions), they read Ent entities directly using the
// host application's *ent.Client:
//
//	// Direct query utilizing Ent's full type safety and relationship traversal
//	entUser, err := entClient.User.Get(ctx, userID)
//	if err != nil {
//		return err
//	}
//	fmt.Println(entUser.TenantID, entUser.AvatarURL, entUser.Role)
//
// Routing application domain queries through Kagi auth ports is an anti-pattern.
// Separating read queries preserves a clean architectural boundary between authentication
// lifecycle management and application business domains.
//
// # Complex Domains: 1:1 Linked Profile Pattern
//
// For applications with extensive user profiles, organizational memberships, or
// complex preferences, adding numerous columns directly to the User entity can lead
// to schema bloat. The recommended pattern is a 1:1 linked entity (such as Profile):
//
//	// Host User schema
//	func (User) Edges() []ent.Edge {
//		return []ent.Edge{
//			edge.To("profile", Profile.Type).Unique(),
//		}
//	}
//
// The linked profile entity can be created and managed via Ent mutation hooks on
// User creation or within application service logic, keeping authentication
// credentials and business domain models strictly decoupled.
package ent
