package schema

import (
	"entgo.io/ent"
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
