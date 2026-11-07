package schema

import (
	"entgo.io/ent"
	"github.com/kilip/kagi/adapter/ent/mixin"
)

// Verification holds the schema definition for the Verification entity in the spike harness.
type Verification struct {
	ent.Schema
}

// Mixin returns Verification mixins.
func (Verification) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.VerificationMixin{},
	}
}
