package schema

import (
	"entgo.io/ent"
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
