package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/kilip/kagi/adapter/ent/mixin"
)

// User holds the schema definition for the User entity in the spike harness.
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
			Optional(),
		field.String("avatar_url").
			Optional().
			Default("https://example.com/default.png"),
	}
}
