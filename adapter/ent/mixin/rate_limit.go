package mixin

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// RateLimitMixin defines the required schema fields and indexes for Kagi's RateLimit entity.
type RateLimitMixin struct {
	mixin.Schema
}

// RateLimitAnnotation marks an entity as the Kagi RateLimit schema.
type RateLimitAnnotation struct{}

// Name implements schema.Annotation.
func (RateLimitAnnotation) Name() string {
	return "KagiRateLimit"
}

// Annotations returns the annotations for RateLimitMixin.
func (RateLimitMixin) Annotations() []schema.Annotation {
	return []schema.Annotation{
		RateLimitAnnotation{},
	}
}

// Fields returns the entity fields for RateLimitMixin.
func (RateLimitMixin) Fields() []ent.Field {
	return []ent.Field{
		field.String("key").
			NotEmpty().
			Unique(),
		field.Int("count").
			Default(0),
		field.Time("expires_at"),
	}
}

// Indexes returns the schema indexes for RateLimitMixin.
func (RateLimitMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("expires_at"),
	}
}
