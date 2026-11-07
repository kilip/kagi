package testschema

import (
	"context"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/kilip/kagi/adapter/ent/mixin"
)

// Account holds the schema definition for the Account entity.
type Account struct {
	ent.Schema
}

// Mixin returns Account mixins.
func (Account) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AccountMixin{},
	}
}

// Fields returns Account fields.
func (Account) Fields() []ent.Field {
	return []ent.Field{
		field.String("metadata").
			Optional(),
	}
}

// Edges returns Account edges.
func (Account) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("accounts").
			Unique(),
	}
}

// Hooks returns Account hooks.
func (Account) Hooks() []ent.Hook {
	return []ent.Hook{
		func(next ent.Mutator) ent.Mutator {
			return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
				return next.Mutate(ctx, m)
			})
		},
	}
}
