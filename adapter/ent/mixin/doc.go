// Package mixin provides Ent mixins that define the columns Kagi requires.
//
// # Overview
//
// Kagi storage adapters require specific database schemas for users, accounts,
// sessions, verifications, and rate limits. Rather than enforcing rigid, immutable
// table schemas, Kagi provides reusable Ent mixins:
//
//   - UserMixin: core user authentication fields (email, name, email_verified, two_factor_enabled, timestamps).
//   - AccountMixin: linked auth providers (user_id, provider, provider_account_id, password_hash, timestamps).
//   - SessionMixin: session records (user_id, token_hash, expires_at, ip_address, user_agent, timestamps).
//   - VerificationMixin: verification tokens and OTPs (target, token_hash, token_type, expires_at, attempts, completed_at, timestamps).
//   - RateLimitMixin: rate-limiting buckets (key, count, expires_at).
//
// Host applications embed these mixins in their Ent schema definitions:
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
// # Schema Rules for Custom Fields (ADR-0016)
//
// Host schemas embedding Kagi mixins are free to declare additional fields, custom
// indexes, edges, and hooks. To maintain compatibility with Kagi's storage adapters,
// non-Kagi fields must satisfy one of the following rules:
//
//  1. Optional fields: Declared with .Optional().
//  2. Default values: Declared with .Default(...) or .DefaultFunc(...).
//  3. Required fields populated via hooks: If a field is required (neither optional
//     nor defaulted, e.g. a non-null tenant_id), it must be populated during write
//     mutations using builder hooks or native Ent mutation hooks. Failing to populate
//     a required field will cause Ent to reject the insert or update mutation.
//
// Example schema with custom fields:
//
//	func (User) Fields() []ent.Field {
//		return []ent.Field{
//			field.String("tenant_id").NotEmpty(), // required, must be set via hook
//			field.String("avatar_url").Optional(), // optional
//			field.String("role").Default("member"), // default value
//		}
//	}
//
// # Writing Custom Fields via Typed Builder Hooks
//
// The Kagi Ent extension (github.com/kilip/kagi/adapter/ent/entc) generates typed
// builder hooks and functional options directly into the host application's package ent.
// These hooks execute prior to saving the entity, providing type-safe setter access:
//
//	userStore := ent.NewKagiUserStore(client,
//		ent.WithUserCreateHook(func(ctx context.Context, b *ent.UserCreate, u *kagi.User) error {
//			if tenantID, ok := tenant.FromContext(ctx); ok {
//				b.SetTenantID(tenantID)
//			}
//			b.SetAvatarURL("https://example.com/avatar.png")
//			return nil
//		}),
//		ent.WithUserUpdateHook(func(ctx context.Context, b *ent.UserUpdateOne, u *kagi.User) error {
//			b.SetAvatarURL("https://example.com/updated.png")
//			return nil
//		}),
//	)
//
// # Writing Custom Fields via Native Ent Mutation Hooks
//
// Host applications can also register native Ent mutation hooks at either the schema
// level or client level. This is particularly suitable for extracting context values
// such as multi-tenant identifiers:
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
// # Reading Custom Fields via Direct ent.Client Queries
//
// Kagi storage ports return pure authentication models (such as *kagi.User) that do
// not contain application-specific fields. To access custom attributes, query the Ent
// client directly:
//
//	user, err := client.User.Get(ctx, userID)
//	if err != nil {
//		return err
//	}
//	fmt.Println(user.TenantID, user.AvatarURL, user.Role)
//
// Keeping domain reads on the *ent.Client preserves clean separation of concerns
// between Kagi's authentication identity lifecycle and host application business logic.
//
// # Complex Domains: 1:1 Linked Profile Pattern
//
// For applications with extensive domain profiles, prefer connecting a separate
// profile entity via an Ent edge rather than adding many columns to User:
//
//	func (User) Edges() []ent.Edge {
//		return []ent.Edge{
//			edge.To("profile", Profile.Type).Unique(),
//		}
//	}
//
// The linked profile entity can be initialized in an Ent mutation hook or in application
// service logic, maintaining a clean boundary between authentication credentials and
// user business profile data.
package mixin
