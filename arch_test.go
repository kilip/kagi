package kagi_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kilip/kagi"
)

// TestArch_DomainStructStringIDs enforces ADR-0011:
// All entity IDs and foreign keys in core domain structs must be of type string.
func TestArch_DomainStructStringIDs(t *testing.T) {
	tests := []struct {
		entityName string
		entity     any
		idFields   []string
	}{
		{
			entityName: "User",
			entity:     kagi.User{},
			idFields:   []string{"ID"},
		},
		{
			entityName: "Account",
			entity:     kagi.Account{},
			idFields:   []string{"ID", "UserID"},
		},
		{
			entityName: "Session",
			entity:     kagi.Session{},
			idFields:   []string{"ID", "UserID"},
		},
		{
			entityName: "Verification",
			entity:     kagi.Verification{},
			idFields:   []string{"ID"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.entityName, func(t *testing.T) {
			valType := reflect.TypeOf(tt.entity)
			if valType.Kind() != reflect.Struct {
				t.Fatalf("%s is not a struct, got kind: %v", tt.entityName, valType.Kind())
			}

			for _, fieldName := range tt.idFields {
				field, found := valType.FieldByName(fieldName)
				if !found {
					t.Fatalf("struct %s is missing expected ID field %q", tt.entityName, fieldName)
				}

				if field.Type.Kind() != reflect.String {
					t.Errorf("field %s.%s is of type %v, want string (ADR-0011 violation)",
						tt.entityName, fieldName, field.Type)
				}
			}
		})
	}
}

// TestArch_ZeroAdapterOrThirdPartyImportsInCore enforces ADR-0001 & ADR-0002:
// Package kagi must depend exclusively on the Go standard library, internal packages,
// and golang.org/x/*. It must never import adapters, ORMs, or HTTP routers.
func TestArch_ZeroAdapterOrThirdPartyImportsInCore(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		// Only inspect non-test Go source files in root package
		return !strings.HasSuffix(fi.Name(), "_test.go") && strings.HasSuffix(fi.Name(), ".go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parser.ParseDir failed: %v", err)
	}

	kagiPkg, exists := pkgs["kagi"]
	if !exists {
		t.Fatalf("package 'kagi' not found in current directory")
	}

	for fileName, fileNode := range kagiPkg.Files {
		relFile := filepath.Base(fileName)
		for _, importSpec := range fileNode.Imports {
			// Strip quotes from import path
			importPath := strings.Trim(importSpec.Path.Value, `"`)

			// Rule 1: Zero adapter imports
			if strings.Contains(importPath, "kagi/adapter") {
				t.Errorf("%s imports adapter package %q (ADR-0007 violation: adapters must not leak into core)",
					relFile, importPath)
			}

			// Rule 2: Zero HTTP framework imports
			if strings.Contains(importPath, "fiber") || strings.Contains(importPath, "gin") || strings.Contains(importPath, "chi") {
				t.Errorf("%s imports HTTP framework package %q (ADR-0001 violation: core must be HTTP-agnostic)",
					relFile, importPath)
			}

			// Rule 3: Zero external ORMs/database drivers
			if strings.Contains(importPath, "entgo.io") || strings.Contains(importPath, "gorm.io") || strings.Contains(importPath, "redis") {
				t.Errorf("%s imports storage engine package %q (ADR-0004 & ADR-0007 violation)",
					relFile, importPath)
			}

			// Rule 4: Allowed imports:
			// - Standard library: first path segment contains no dot (e.g. "time", "context", "crypto/rand")
			// - golang.org/x/*: e.g. "golang.org/x/crypto/argon2"
			// - Internal kagi subpackages: e.g. "github.com/kilip/kagi/internal/..."
			isStdLib := !strings.Contains(strings.Split(importPath, "/")[0], ".")
			isGolangX := strings.HasPrefix(importPath, "golang.org/x/")
			isKagiInternal := strings.HasPrefix(importPath, "github.com/kilip/kagi/internal/")

			if !isStdLib && !isGolangX && !isKagiInternal {
				t.Errorf("%s imports unauthorized external package %q; core may only import stdlib, golang.org/x/*, and internal/*",
					relFile, importPath)
			}
		}
	}
}
