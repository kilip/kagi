package testschema

import (
	"context"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/kilip/kagi/adapter/ent/mixin"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Mixin returns User mixins.
func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.UserMixin{},
	}
}

// Fields returns User fields.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("tenant_id").
			NotEmpty(),
		field.String("avatar_url").
			Optional(),
	}
}

// Edges returns User edges.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("accounts", Account.Type),
	}
}

// Hooks returns User hooks.
func (User) Hooks() []ent.Hook {
	return []ent.Hook{
		func(next ent.Mutator) ent.Mutator {
			return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
				return next.Mutate(ctx, m)
			})
		},
	}
}
