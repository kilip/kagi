package mixin

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// SessionMixin defines the required schema fields and indexes for Kagi's Session entity.
type SessionMixin struct {
	mixin.Schema
}

// SessionAnnotation marks an entity as the Kagi Session schema.
type SessionAnnotation struct{}

// Name implements schema.Annotation.
func (SessionAnnotation) Name() string {
	return "KagiSession"
}

// Annotations returns the annotations for SessionMixin.
func (SessionMixin) Annotations() []schema.Annotation {
	return []schema.Annotation{
		SessionAnnotation{},
	}
}

// Fields returns the entity fields for SessionMixin.
func (SessionMixin) Fields() []ent.Field {
	return []ent.Field{
		field.String("user_id").
			NotEmpty(),
		field.String("token_hash").
			NotEmpty().
			Unique(),
		field.Time("expires_at"),
		field.String("ip_address").
			Optional().
			Default(""),
		field.String("user_agent").
			Optional().
			Default(""),
		field.Bool("pending_2fa").
			Default(false),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes returns the schema indexes for SessionMixin.
func (SessionMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("expires_at"),
		index.Fields("user_id"),
	}
}
