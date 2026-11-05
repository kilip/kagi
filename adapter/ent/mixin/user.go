package mixin

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// UserMixin defines the required schema fields for Kagi's User entity.
type UserMixin struct {
	mixin.Schema
}

// UserAnnotation marks an entity as the Kagi User schema.
type UserAnnotation struct{}

// Name implements schema.Annotation.
func (UserAnnotation) Name() string {
	return "KagiUser"
}

// Annotations returns the annotations for the UserMixin.
func (UserMixin) Annotations() []schema.Annotation {
	return []schema.Annotation{
		UserAnnotation{},
	}
}

// Fields returns the entity fields for UserMixin.
func (UserMixin) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").
			NotEmpty().
			Unique(),
		field.String("name").
			Default(""),
		field.Bool("email_verified").
			Default(false),
		field.Bool("two_factor_enabled").
			Default(false),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}
