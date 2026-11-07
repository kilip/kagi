package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/kilip/kagi/adapter/ent/mixin"
)

// Account holds the schema definition for the Account entity in the spike harness.
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
