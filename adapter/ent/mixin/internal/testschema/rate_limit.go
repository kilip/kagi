package testschema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/kilip/kagi/adapter/ent/mixin"
)

// RateLimit holds the schema definition for the RateLimit entity.
type RateLimit struct {
	ent.Schema
}

// Mixin returns RateLimit mixins.
func (RateLimit) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.RateLimitMixin{},
	}
}

// Fields returns RateLimit fields.
func (RateLimit) Fields() []ent.Field {
	return []ent.Field{
		field.String("tier").
			Optional(),
	}
}
