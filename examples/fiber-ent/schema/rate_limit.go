package schema

import (
	"entgo.io/ent"
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
