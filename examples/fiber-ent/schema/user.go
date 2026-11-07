package schema

import (
	"entgo.io/ent"
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
