package mixin

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// AccountMixin defines the required schema fields and indexes for Kagi's Account entity.
type AccountMixin struct {
	mixin.Schema
}

// AccountAnnotation marks an entity as the Kagi Account schema.
type AccountAnnotation struct{}

// Name implements schema.Annotation.
func (AccountAnnotation) Name() string {
	return "KagiAccount"
}

// Annotations returns the annotations for AccountMixin.
func (AccountMixin) Annotations() []schema.Annotation {
	return []schema.Annotation{
		AccountAnnotation{},
	}
}

// Fields returns the entity fields for AccountMixin.
func (AccountMixin) Fields() []ent.Field {
	return []ent.Field{
		field.String("user_id").
			NotEmpty(),
		field.String("provider").
			NotEmpty(),
		field.String("provider_account_id").
			NotEmpty(),
		field.String("password_hash").
			Optional().
			Default(""),
		field.String("access_token").
			Optional().
			Default(""),
		field.String("refresh_token").
			Optional().
			Default(""),
		field.Time("token_expires_at").
			Optional().
			Nillable(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes returns the schema indexes for AccountMixin.
func (AccountMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("provider", "provider_account_id").
			Unique(),
		index.Fields("user_id"),
	}
}
