package mixin_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
	"entgo.io/ent/entc/load"
)

func TestCustomizationSchemaLoad(t *testing.T) {
	spec, err := (&load.Config{Path: "./internal/testschema"}).Load()
	if err != nil {
		t.Fatalf("failed to load schema spec: %v", err)
	}

	if len(spec.Schemas) != 5 {
		t.Fatalf("expected 5 schemas, got %d", len(spec.Schemas))
	}

	schemaMap := make(map[string]*load.Schema)
	for _, s := range spec.Schemas {
		schemaMap[s.Name] = s
	}

	for _, name := range []string{"User", "Account", "Session", "Verification", "RateLimit"} {
		if _, ok := schemaMap[name]; !ok {
			t.Errorf("expected schema %q in loaded spec", name)
		}
	}
}

func TestCustomizationGraphResolution(t *testing.T) {
	schemaPath := "./internal/testschema"
	cfg := &gen.Config{
		Package: "github.com/kilip/kagi/adapter/ent/mixin/internal/testschema/ent",
	}

	graph, err := entc.LoadGraph(schemaPath, cfg)
	if err != nil {
		t.Fatalf("failed to load graph: %v", err)
	}

	if len(graph.Nodes) != 5 {
		t.Fatalf("expected 5 nodes in graph, got %d", len(graph.Nodes))
	}

	nodeMap := make(map[string]*gen.Type)
	for _, n := range graph.Nodes {
		nodeMap[n.Name] = n
	}

	// Helper to collect field names from a gen.Type.
	fieldNames := func(n *gen.Type) map[string]*gen.Field {
		m := make(map[string]*gen.Field)
		for _, f := range n.Fields {
			m[f.Name] = f
		}
		return m
	}

	// 1. User
	userNode := nodeMap["User"]
	if userNode == nil {
		t.Fatal("missing User node")
	}
	userFields := fieldNames(userNode)
	// Check mixin fields
	for _, f := range []string{"email", "name", "email_verified", "two_factor_enabled", "created_at", "updated_at"} {
		if _, ok := userFields[f]; !ok {
			t.Errorf("User missing mixin field %q", f)
		}
	}
	// Check custom fields
	for _, f := range []string{"tenant_id", "avatar_url"} {
		if _, ok := userFields[f]; !ok {
			t.Errorf("User missing custom field %q", f)
		}
	}
	// Check custom edge
	if len(userNode.Edges) != 1 || userNode.Edges[0].Name != "accounts" {
		t.Fatalf("expected User to have edge 'accounts', got: %v", userNode.Edges)
	}
	if userNode.Edges[0].Type.Name != "Account" {
		t.Errorf("expected User.accounts target 'Account', got %q", userNode.Edges[0].Type.Name)
	}
	// Check custom hook
	if userNode.NumHooks() != 1 {
		t.Errorf("expected User to have 1 hook, got %d", userNode.NumHooks())
	}
	// Check annotation
	if _, ok := userNode.Annotations["KagiUser"]; !ok {
		t.Errorf("expected User to have 'KagiUser' annotation")
	}

	// 2. Account
	accountNode := nodeMap["Account"]
	if accountNode == nil {
		t.Fatal("missing Account node")
	}
	accountFields := fieldNames(accountNode)
	// Check mixin fields
	for _, f := range []string{"user_id", "provider", "provider_account_id", "password_hash", "access_token", "refresh_token", "token_expires_at", "created_at", "updated_at"} {
		if _, ok := accountFields[f]; !ok {
			t.Errorf("Account missing mixin field %q", f)
		}
	}
	// Check custom field
	if _, ok := accountFields["metadata"]; !ok {
		t.Errorf("Account missing custom field 'metadata'")
	}
	// Check custom back-reference edge
	if len(accountNode.Edges) != 1 || accountNode.Edges[0].Name != "user" {
		t.Fatalf("expected Account to have edge 'user', got: %v", accountNode.Edges)
	}
	accEdge := accountNode.Edges[0]
	if accEdge.Type.Name != "User" {
		t.Errorf("expected Account.user target 'User', got %q", accEdge.Type.Name)
	}
	if !accEdge.IsInverse() {
		t.Errorf("expected Account.user to be inverse edge")
	}
	if !accEdge.Unique {
		t.Errorf("expected Account.user edge to be unique")
	}
	if accEdge.Ref == nil || accEdge.Ref.Name != "accounts" {
		t.Errorf("expected Account.user edge to reference 'accounts', got %v", accEdge.Ref)
	}
	// Check custom hook
	if accountNode.NumHooks() != 1 {
		t.Errorf("expected Account to have 1 hook, got %d", accountNode.NumHooks())
	}
	// Check annotation
	if _, ok := accountNode.Annotations["KagiAccount"]; !ok {
		t.Errorf("expected Account to have 'KagiAccount' annotation")
	}

	// 3. Session
	sessionNode := nodeMap["Session"]
	if sessionNode == nil {
		t.Fatal("missing Session node")
	}
	sessionFields := fieldNames(sessionNode)
	for _, f := range []string{"user_id", "token_hash", "expires_at", "ip_address", "user_agent", "pending_2fa", "created_at", "updated_at"} {
		if _, ok := sessionFields[f]; !ok {
			t.Errorf("Session missing mixin field %q", f)
		}
	}
	if _, ok := sessionFields["device_id"]; !ok {
		t.Errorf("Session missing custom field 'device_id'")
	}
	// Check expires_at index
	hasExpiresIndex := false
	for _, idx := range sessionNode.Indexes {
		if len(idx.Columns) == 1 && idx.Columns[0] == "expires_at" {
			hasExpiresIndex = true
			break
		}
	}
	if !hasExpiresIndex {
		t.Errorf("Session missing index on 'expires_at'")
	}
	if _, ok := sessionNode.Annotations["KagiSession"]; !ok {
		t.Errorf("expected Session to have 'KagiSession' annotation")
	}

	// 4. Verification
	verNode := nodeMap["Verification"]
	if verNode == nil {
		t.Fatal("missing Verification node")
	}
	verFields := fieldNames(verNode)
	for _, f := range []string{"target", "type", "code_hash", "expires_at", "attempts", "created_at", "updated_at"} {
		if _, ok := verFields[f]; !ok {
			t.Errorf("Verification missing mixin field %q", f)
		}
	}
	if _, ok := verFields["channel"]; !ok {
		t.Errorf("Verification missing custom field 'channel'")
	}
	// Check expires_at index
	hasExpiresIndex = false
	for _, idx := range verNode.Indexes {
		if len(idx.Columns) == 1 && idx.Columns[0] == "expires_at" {
			hasExpiresIndex = true
			break
		}
	}
	if !hasExpiresIndex {
		t.Errorf("Verification missing index on 'expires_at'")
	}
	if _, ok := verNode.Annotations["KagiVerification"]; !ok {
		t.Errorf("expected Verification to have 'KagiVerification' annotation")
	}

	// 5. RateLimit
	rlNode := nodeMap["RateLimit"]
	if rlNode == nil {
		t.Fatal("missing RateLimit node")
	}
	rlFields := fieldNames(rlNode)
	for _, f := range []string{"key", "count", "expires_at"} {
		if _, ok := rlFields[f]; !ok {
			t.Errorf("RateLimit missing mixin field %q", f)
		}
	}
	if _, ok := rlFields["tier"]; !ok {
		t.Errorf("RateLimit missing custom field 'tier'")
	}
	// Check expires_at index
	hasExpiresIndex = false
	for _, idx := range rlNode.Indexes {
		if len(idx.Columns) == 1 && idx.Columns[0] == "expires_at" {
			hasExpiresIndex = true
			break
		}
	}
	if !hasExpiresIndex {
		t.Errorf("RateLimit missing index on 'expires_at'")
	}
	if _, ok := rlNode.Annotations["KagiRateLimit"]; !ok {
		t.Errorf("expected RateLimit to have 'KagiRateLimit' annotation")
	}
}

func TestCustomizationGenerate(t *testing.T) {
	tempTarget := t.TempDir()
	cfg := &gen.Config{
		Package: "github.com/kilip/kagi/adapter/ent/mixin/internal/testschema/ent",
		Target:  tempTarget,
	}

	err := entc.Generate("./internal/testschema", cfg)
	if err != nil {
		t.Fatalf("failed running entc.Generate on customized schemas: %v", err)
	}

	// Verify key generated files exist
	expectedFiles := []string{
		"client.go",
		"user.go",
		"account.go",
		"session.go",
		"verification.go",
		"ratelimit.go",
		filepath.Join("user", "user.go"),
		filepath.Join("account", "account.go"),
		filepath.Join("session", "session.go"),
		filepath.Join("verification", "verification.go"),
		filepath.Join("ratelimit", "ratelimit.go"),
	}

	for _, rel := range expectedFiles {
		path := filepath.Join(tempTarget, rel)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected generated file %q to exist: %v", rel, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("expected generated file %q to be non-empty", rel)
		}
	}

	// Verify custom fields appear in generated subpackage constants/descriptors
	userPkgContent, err := os.ReadFile(filepath.Join(tempTarget, "user", "user.go"))
	if err != nil {
		t.Fatalf("failed reading generated user/user.go: %v", err)
	}
	userCode := string(userPkgContent)
	for _, expectedToken := range []string{"FieldTenantID", "FieldAvatarURL", "AccountsTable"} {
		if !strings.Contains(userCode, expectedToken) {
			t.Errorf("expected generated user/user.go to contain %q", expectedToken)
		}
	}

	accountPkgContent, err := os.ReadFile(filepath.Join(tempTarget, "account", "account.go"))
	if err != nil {
		t.Fatalf("failed reading generated account/account.go: %v", err)
	}
	accountCode := string(accountPkgContent)
	for _, expectedToken := range []string{"FieldMetadata", "UserTable"} {
		if !strings.Contains(accountCode, expectedToken) {
			t.Errorf("expected generated account/account.go to contain %q", expectedToken)
		}
	}

	sessionPkgContent, err := os.ReadFile(filepath.Join(tempTarget, "session", "session.go"))
	if err != nil {
		t.Fatalf("failed reading generated session/session.go: %v", err)
	}
	sessionCode := string(sessionPkgContent)
	if !strings.Contains(sessionCode, "FieldDeviceID") {
		t.Errorf("expected generated session/session.go to contain 'FieldDeviceID'")
	}

	verPkgContent, err := os.ReadFile(filepath.Join(tempTarget, "verification", "verification.go"))
	if err != nil {
		t.Fatalf("failed reading generated verification/verification.go: %v", err)
	}
	verCode := string(verPkgContent)
	if !strings.Contains(verCode, "FieldChannel") {
		t.Errorf("expected generated verification/verification.go to contain 'FieldChannel'")
	}

	rlPkgContent, err := os.ReadFile(filepath.Join(tempTarget, "ratelimit", "ratelimit.go"))
	if err != nil {
		t.Fatalf("failed reading generated ratelimit/ratelimit.go: %v", err)
	}
	rlCode := string(rlPkgContent)
	if !strings.Contains(rlCode, "FieldTier") {
		t.Errorf("expected generated ratelimit/ratelimit.go to contain 'FieldTier'")
	}
}
