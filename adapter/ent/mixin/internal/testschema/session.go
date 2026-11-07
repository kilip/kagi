package testschema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/kilip/kagi/adapter/ent/mixin"
)

// Session holds the schema definition for the Session entity.
type Session struct {
	ent.Schema
}

// Mixin returns Session mixins.
func (Session) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.SessionMixin{},
	}
}

// Fields returns Session fields.
func (Session) Fields() []ent.Field {
	return []ent.Field{
		field.String("device_id").
			Optional(),
	}
}
