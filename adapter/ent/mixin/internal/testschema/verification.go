package testschema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/kilip/kagi/adapter/ent/mixin"
)

// Verification holds the schema definition for the Verification entity.
type Verification struct {
	ent.Schema
}

// Mixin returns Verification mixins.
func (Verification) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.VerificationMixin{},
	}
}

// Fields returns Verification fields.
func (Verification) Fields() []ent.Field {
	return []ent.Field{
		field.String("channel").
			Optional(),
	}
}
