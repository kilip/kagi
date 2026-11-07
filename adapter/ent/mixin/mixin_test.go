package mixin_test

import (
	"reflect"
	"testing"

	"entgo.io/ent/schema/field"
	"github.com/kilip/kagi/adapter/ent/mixin"
)

func TestAccountMixin(t *testing.T) {
	m := mixin.AccountMixin{}

	// Annotations
	annotations := m.Annotations()
	if len(annotations) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(annotations))
	}
	if annotations[0].Name() != "KagiAccount" {
		t.Fatalf("expected annotation name 'KagiAccount', got %q", annotations[0].Name())
	}

	// Fields
	fields := m.Fields()
	fieldMap := make(map[string]field.Descriptor)
	for _, f := range fields {
		desc := f.Descriptor()
		fieldMap[desc.Name] = *desc
	}

	expectedFields := []string{
		"user_id",
		"provider",
		"provider_account_id",
		"password_hash",
		"access_token",
		"refresh_token",
		"token_expires_at",
		"created_at",
		"updated_at",
	}

	for _, name := range expectedFields {
		desc, ok := fieldMap[name]
		if !ok {
			t.Errorf("expected field %q to exist in AccountMixin", name)
			continue
		}

		switch name {
		case "user_id", "provider", "provider_account_id":
			if desc.Info.Type != field.TypeString {
				t.Errorf("expected %s type string, got %v", name, desc.Info.Type)
			}
			if len(desc.Validators) == 0 {
				t.Errorf("expected %s to have validators (NotEmpty)", name)
			}
		case "password_hash", "access_token", "refresh_token":
			if desc.Info.Type != field.TypeString {
				t.Errorf("expected %s type string, got %v", name, desc.Info.Type)
			}
			if !desc.Optional {
				t.Errorf("expected %s to be optional", name)
			}
			if desc.Default != "" {
				t.Errorf("expected %s default to be empty string, got %v", name, desc.Default)
			}
		case "token_expires_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected token_expires_at type time, got %v", desc.Info.Type)
			}
			if !desc.Optional {
				t.Errorf("expected token_expires_at to be optional")
			}
			if !desc.Nillable {
				t.Errorf("expected token_expires_at to be nillable")
			}
		case "created_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected created_at type time, got %v", desc.Info.Type)
			}
			if desc.Default == nil {
				t.Errorf("expected created_at to have a default function")
			}
			if !desc.Immutable {
				t.Errorf("expected created_at to be immutable")
			}
		case "updated_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected updated_at type time, got %v", desc.Info.Type)
			}
			if desc.Default == nil {
				t.Errorf("expected updated_at to have a default function")
			}
			if desc.UpdateDefault == nil {
				t.Errorf("expected updated_at to have an update default function")
			}
		}
	}

	// Indexes
	indexes := m.Indexes()
	if len(indexes) != 2 {
		t.Fatalf("expected 2 indexes, got %d", len(indexes))
	}

	idx1 := indexes[0].Descriptor()
	if !reflect.DeepEqual(idx1.Fields, []string{"provider", "provider_account_id"}) {
		t.Errorf("expected first index on [provider, provider_account_id], got %v", idx1.Fields)
	}
	if !idx1.Unique {
		t.Errorf("expected first index to be unique")
	}

	idx2 := indexes[1].Descriptor()
	if !reflect.DeepEqual(idx2.Fields, []string{"user_id"}) {
		t.Errorf("expected second index on [user_id], got %v", idx2.Fields)
	}
	if idx2.Unique {
		t.Errorf("expected second index to not be unique")
	}
}

func TestSessionMixin(t *testing.T) {
	m := mixin.SessionMixin{}

	// Annotations
	annotations := m.Annotations()
	if len(annotations) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(annotations))
	}
	if annotations[0].Name() != "KagiSession" {
		t.Fatalf("expected annotation name 'KagiSession', got %q", annotations[0].Name())
	}

	// Fields
	fields := m.Fields()
	fieldMap := make(map[string]field.Descriptor)
	for _, f := range fields {
		desc := f.Descriptor()
		fieldMap[desc.Name] = *desc
	}

	expectedFields := []string{
		"user_id",
		"token_hash",
		"expires_at",
		"ip_address",
		"user_agent",
		"pending_2fa",
		"created_at",
		"updated_at",
	}

	for _, name := range expectedFields {
		desc, ok := fieldMap[name]
		if !ok {
			t.Errorf("expected field %q to exist in SessionMixin", name)
			continue
		}

		switch name {
		case "user_id":
			if desc.Info.Type != field.TypeString {
				t.Errorf("expected user_id type string, got %v", desc.Info.Type)
			}
			if len(desc.Validators) == 0 {
				t.Errorf("expected user_id to have validators (NotEmpty)")
			}
		case "token_hash":
			if desc.Info.Type != field.TypeString {
				t.Errorf("expected token_hash type string, got %v", desc.Info.Type)
			}
			if len(desc.Validators) == 0 {
				t.Errorf("expected token_hash to have validators (NotEmpty)")
			}
			if !desc.Unique {
				t.Errorf("expected token_hash to be unique")
			}
		case "expires_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected expires_at type time, got %v", desc.Info.Type)
			}
		case "ip_address", "user_agent":
			if desc.Info.Type != field.TypeString {
				t.Errorf("expected %s type string, got %v", name, desc.Info.Type)
			}
			if !desc.Optional {
				t.Errorf("expected %s to be optional", name)
			}
			if desc.Default != "" {
				t.Errorf("expected %s default to be empty string, got %v", name, desc.Default)
			}
		case "pending_2fa":
			if desc.Info.Type != field.TypeBool {
				t.Errorf("expected pending_2fa type bool, got %v", desc.Info.Type)
			}
			if desc.Default != false {
				t.Errorf("expected pending_2fa default to be false, got %v", desc.Default)
			}
		case "created_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected created_at type time, got %v", desc.Info.Type)
			}
			if desc.Default == nil {
				t.Errorf("expected created_at to have a default function")
			}
			if !desc.Immutable {
				t.Errorf("expected created_at to be immutable")
			}
		case "updated_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected updated_at type time, got %v", desc.Info.Type)
			}
			if desc.Default == nil {
				t.Errorf("expected updated_at to have a default function")
			}
			if desc.UpdateDefault == nil {
				t.Errorf("expected updated_at to have an update default function")
			}
		}
	}

	// Indexes
	indexes := m.Indexes()
	if len(indexes) != 2 {
		t.Fatalf("expected 2 indexes, got %d", len(indexes))
	}

	idx1 := indexes[0].Descriptor()
	if !reflect.DeepEqual(idx1.Fields, []string{"expires_at"}) {
		t.Errorf("expected first index on [expires_at], got %v", idx1.Fields)
	}

	idx2 := indexes[1].Descriptor()
	if !reflect.DeepEqual(idx2.Fields, []string{"user_id"}) {
		t.Errorf("expected second index on [user_id], got %v", idx2.Fields)
	}
}

func TestUserMixin(t *testing.T) {
	m := mixin.UserMixin{}

	// Annotations
	annotations := m.Annotations()
	if len(annotations) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(annotations))
	}
	if annotations[0].Name() != "KagiUser" {
		t.Fatalf("expected annotation name 'KagiUser', got %q", annotations[0].Name())
	}

	// Fields
	fields := m.Fields()
	fieldMap := make(map[string]field.Descriptor)
	for _, f := range fields {
		desc := f.Descriptor()
		fieldMap[desc.Name] = *desc
	}

	expectedFields := []string{
		"email",
		"name",
		"email_verified",
		"two_factor_enabled",
		"created_at",
		"updated_at",
	}

	if len(fields) != len(expectedFields) {
		t.Errorf("expected %d fields, got %d", len(expectedFields), len(fields))
	}

	for _, name := range expectedFields {
		desc, ok := fieldMap[name]
		if !ok {
			t.Errorf("expected field %q to exist in UserMixin", name)
			continue
		}

		switch name {
		case "email":
			if desc.Info.Type != field.TypeString {
				t.Errorf("expected email type string, got %v", desc.Info.Type)
			}
			if len(desc.Validators) == 0 {
				t.Errorf("expected email to have validators (NotEmpty)")
			}
			if !desc.Unique {
				t.Errorf("expected email to be unique")
			}
		case "name":
			if desc.Info.Type != field.TypeString {
				t.Errorf("expected name type string, got %v", desc.Info.Type)
			}
			if desc.Default != "" {
				t.Errorf("expected name default to be empty string, got %v", desc.Default)
			}
		case "email_verified":
			if desc.Info.Type != field.TypeBool {
				t.Errorf("expected email_verified type bool, got %v", desc.Info.Type)
			}
			if desc.Default != false {
				t.Errorf("expected email_verified default to be false, got %v", desc.Default)
			}
		case "two_factor_enabled":
			if desc.Info.Type != field.TypeBool {
				t.Errorf("expected two_factor_enabled type bool, got %v", desc.Info.Type)
			}
			if desc.Default != false {
				t.Errorf("expected two_factor_enabled default to be false, got %v", desc.Default)
			}
		case "created_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected created_at type time, got %v", desc.Info.Type)
			}
			if desc.Default == nil {
				t.Errorf("expected created_at to have a default function")
			}
			if !desc.Immutable {
				t.Errorf("expected created_at to be immutable")
			}
		case "updated_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected updated_at type time, got %v", desc.Info.Type)
			}
			if desc.Default == nil {
				t.Errorf("expected updated_at to have a default function")
			}
			if desc.UpdateDefault == nil {
				t.Errorf("expected updated_at to have an update default function")
			}
		}
	}
}

func TestVerificationMixin(t *testing.T) {
	m := mixin.VerificationMixin{}

	// Annotations
	annotations := m.Annotations()
	if len(annotations) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(annotations))
	}
	if annotations[0].Name() != "KagiVerification" {
		t.Fatalf("expected annotation name 'KagiVerification', got %q", annotations[0].Name())
	}

	// Fields
	fields := m.Fields()
	fieldMap := make(map[string]field.Descriptor)
	for _, f := range fields {
		desc := f.Descriptor()
		fieldMap[desc.Name] = *desc
	}

	expectedFields := []string{
		"target",
		"type",
		"code_hash",
		"expires_at",
		"attempts",
		"created_at",
		"updated_at",
	}

	if len(fields) != len(expectedFields) {
		t.Errorf("expected %d fields, got %d", len(expectedFields), len(fields))
	}

	for _, name := range expectedFields {
		desc, ok := fieldMap[name]
		if !ok {
			t.Errorf("expected field %q to exist in VerificationMixin", name)
			continue
		}

		switch name {
		case "target", "type", "code_hash":
			if desc.Info.Type != field.TypeString {
				t.Errorf("expected %s type string, got %v", name, desc.Info.Type)
			}
			if len(desc.Validators) == 0 {
				t.Errorf("expected %s to have validators (NotEmpty)", name)
			}
		case "expires_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected expires_at type time, got %v", desc.Info.Type)
			}
		case "attempts":
			if desc.Info.Type != field.TypeInt {
				t.Errorf("expected attempts type int, got %v", desc.Info.Type)
			}
			if desc.Default != 0 {
				t.Errorf("expected attempts default to be 0, got %v", desc.Default)
			}
		case "created_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected created_at type time, got %v", desc.Info.Type)
			}
			if desc.Default == nil {
				t.Errorf("expected created_at to have a default function")
			}
			if !desc.Immutable {
				t.Errorf("expected created_at to be immutable")
			}
		case "updated_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected updated_at type time, got %v", desc.Info.Type)
			}
			if desc.Default == nil {
				t.Errorf("expected updated_at to have a default function")
			}
			if desc.UpdateDefault == nil {
				t.Errorf("expected updated_at to have an update default function")
			}
		}
	}

	// Indexes
	indexes := m.Indexes()
	if len(indexes) != 2 {
		t.Fatalf("expected 2 indexes, got %d", len(indexes))
	}

	idx1 := indexes[0].Descriptor()
	if !reflect.DeepEqual(idx1.Fields, []string{"expires_at"}) {
		t.Errorf("expected first index on [expires_at], got %v", idx1.Fields)
	}
	if idx1.Unique {
		t.Errorf("expected expires_at index to not be unique")
	}

	idx2 := indexes[1].Descriptor()
	if !reflect.DeepEqual(idx2.Fields, []string{"target", "type"}) {
		t.Errorf("expected second index on [target, type], got %v", idx2.Fields)
	}
	if idx2.Unique {
		t.Errorf("expected target, type index to not be unique")
	}
}

func TestRateLimitMixin(t *testing.T) {
	m := mixin.RateLimitMixin{}

	// Annotations
	annotations := m.Annotations()
	if len(annotations) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(annotations))
	}
	if annotations[0].Name() != "KagiRateLimit" {
		t.Fatalf("expected annotation name 'KagiRateLimit', got %q", annotations[0].Name())
	}

	// Fields
	fields := m.Fields()
	fieldMap := make(map[string]field.Descriptor)
	for _, f := range fields {
		desc := f.Descriptor()
		fieldMap[desc.Name] = *desc
	}

	expectedFields := []string{
		"key",
		"count",
		"expires_at",
	}

	if len(fields) != len(expectedFields) {
		t.Errorf("expected %d fields, got %d", len(expectedFields), len(fields))
	}

	for _, name := range expectedFields {
		desc, ok := fieldMap[name]
		if !ok {
			t.Errorf("expected field %q to exist in RateLimitMixin", name)
			continue
		}

		switch name {
		case "key":
			if desc.Info.Type != field.TypeString {
				t.Errorf("expected key type string, got %v", desc.Info.Type)
			}
			if len(desc.Validators) == 0 {
				t.Errorf("expected key to have validators (NotEmpty)")
			}
			if !desc.Unique {
				t.Errorf("expected key to be unique")
			}
		case "count":
			if desc.Info.Type != field.TypeInt {
				t.Errorf("expected count type int, got %v", desc.Info.Type)
			}
			if desc.Default != 0 {
				t.Errorf("expected count default to be 0, got %v", desc.Default)
			}
		case "expires_at":
			if desc.Info.Type != field.TypeTime {
				t.Errorf("expected expires_at type time, got %v", desc.Info.Type)
			}
		}
	}

	// Indexes
	indexes := m.Indexes()
	if len(indexes) != 1 {
		t.Fatalf("expected 1 index, got %d", len(indexes))
	}

	idx1 := indexes[0].Descriptor()
	if !reflect.DeepEqual(idx1.Fields, []string{"expires_at"}) {
		t.Errorf("expected first index on [expires_at], got %v", idx1.Fields)
	}
	if idx1.Unique {
		t.Errorf("expected expires_at index to not be unique")
	}
}
