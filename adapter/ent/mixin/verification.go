package mixin

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// VerificationMixin defines the required schema fields and indexes for Kagi's Verification entity.
type VerificationMixin struct {
	mixin.Schema
}

// VerificationAnnotation marks an entity as the Kagi Verification schema.
type VerificationAnnotation struct{}

// Name implements schema.Annotation.
func (VerificationAnnotation) Name() string {
	return "KagiVerification"
}

// Annotations returns the annotations for VerificationMixin.
func (VerificationMixin) Annotations() []schema.Annotation {
	return []schema.Annotation{
		VerificationAnnotation{},
	}
}

// Fields returns the entity fields for VerificationMixin.
func (VerificationMixin) Fields() []ent.Field {
	return []ent.Field{
		field.String("target").
			NotEmpty(),
		field.String("type").
			NotEmpty(),
		field.String("code_hash").
			NotEmpty(),
		field.Time("expires_at"),
		field.Int("attempts").
			Default(0),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes returns the schema indexes for VerificationMixin.
func (VerificationMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("expires_at"),
		index.Fields("target", "type"),
	}
}
