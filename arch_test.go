package kagi_test

import (
	"go/ast"
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

// TestArch_ExportedSentinelErrorsConventions asserts that:
// 1. All exported package-level variables in errors.go follow Go naming conventions (start with Err).
// 2. All exported variables in errors.go possess a non-empty godoc comment.
// 3. At least 30 sentinel errors are defined and checked.
func TestArch_ExportedSentinelErrorsConventions(t *testing.T) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "errors.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parser.ParseFile failed for errors.go: %v", err)
	}

	exportedErrorCount := 0
	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}

		for _, spec := range genDecl.Specs {
			valSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for _, name := range valSpec.Names {
				if !name.IsExported() {
					continue
				}

				exportedErrorCount++

				// Convention 1: All exported error variables must start with "Err"
				if !strings.HasPrefix(name.Name, "Err") {
					t.Errorf("exported variable %s in errors.go does not follow 'Err' naming prefix convention", name.Name)
				}

				// Convention 2: Each exported error variable must have godoc
				var docText string
				if valSpec.Doc != nil {
					docText = strings.TrimSpace(valSpec.Doc.Text())
				}
				if docText == "" {
					t.Errorf("exported error %s in errors.go lacks godoc comment", name.Name)
				}
			}
		}
	}

	if exportedErrorCount < 30 {
		t.Errorf("expected at least 30 exported sentinel errors in errors.go, found %d", exportedErrorCount)
	}
}

// TestArch_StoragePortConventions validates ADR-0007, ADR-0010, ADR-0011, and ADR-0014:
//  1. All 6 storage ports exist as exported interfaces in package kagi:
//     UserStore, AccountStore, SessionStore, VerificationStore, RateLimitStore, and SecondaryStorage.
//  2. Every port method takes context.Context as its first parameter and returns error as its final return value.
//  3. Every port interface and exported method possesses non-empty godoc documentation.
//  4. Contract documentation verification via AST doc comments:
//     - Expiry checks on time-bound stores (SessionStore, VerificationStore, RateLimitStore) document "expires_at > now" or "ADR-0010".
//     - Atomic operations (SessionStore.UpdateTokenHash, RateLimitStore.Increment, SecondaryStorage.IncrementRateLimit) document "atomic" or "CAS".
//     - Cache miss semantics on SecondaryStorage.GetSession document "nil, nil".
//     - Multi-tier write ordering on SecondaryStorage documents "primary".
func TestArch_StoragePortConventions(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go") && strings.HasSuffix(fi.Name(), ".go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parser.ParseDir failed: %v", err)
	}

	kagiPkg, exists := pkgs["kagi"]
	if !exists {
		t.Fatalf("package 'kagi' not found in root directory")
	}

	expectedPorts := []string{
		"UserStore",
		"AccountStore",
		"SessionStore",
		"VerificationStore",
		"RateLimitStore",
		"SecondaryStorage",
	}

	type portInfo struct {
		docText string
		iface   *ast.InterfaceType
		file    string
	}
	foundPorts := make(map[string]portInfo)

	for fileName, fileNode := range kagiPkg.Files {
		relFile := filepath.Base(fileName)
		for _, decl := range fileNode.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.TYPE {
				continue
			}
			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				iface, ok := typeSpec.Type.(*ast.InterfaceType)
				if !ok {
					continue
				}

				// Extract doc comment from GenDecl or TypeSpec
				doc := genDecl.Doc
				if doc == nil {
					doc = typeSpec.Doc
				}
				var docText string
				if doc != nil {
					docText = strings.TrimSpace(doc.Text())
				}

				foundPorts[typeSpec.Name.Name] = portInfo{
					docText: docText,
					iface:   iface,
					file:    relFile,
				}
			}
		}
	}

	// 1. Assert all 6 ports exist and have godoc
	for _, portName := range expectedPorts {
		info, ok := foundPorts[portName]
		if !ok {
			t.Errorf("expected storage port interface %s to exist in package kagi", portName)
			continue
		}
		if info.docText == "" {
			t.Errorf("storage port interface %s in %s lacks godoc comment", portName, info.file)
		}

		// Inspect interface methods
		methods := info.iface.Methods.List
		if len(methods) == 0 {
			t.Errorf("storage port interface %s has no methods defined", portName)
		}

		for _, method := range methods {
			funcType, ok := method.Type.(*ast.FuncType)
			if !ok {
				// Embedded interface (if any)
				continue
			}

			for _, methodName := range method.Names {
				mName := methodName.Name

				// 3. Every method possesses non-empty godoc
				var methodDoc string
				if method.Doc != nil {
					methodDoc = strings.TrimSpace(method.Doc.Text())
				}
				if methodDoc == "" {
					t.Errorf("method %s.%s in %s lacks godoc documentation", portName, mName, info.file)
				}

				// 2. First parameter MUST be context.Context
				if funcType.Params == nil || len(funcType.Params.List) == 0 {
					t.Errorf("method %s.%s must accept context.Context as its first parameter, but has no parameters", portName, mName)
				} else {
					firstParam := funcType.Params.List[0]
					if !isContextParam(firstParam.Type) {
						t.Errorf("method %s.%s first parameter must be context.Context", portName, mName)
					}
				}

				// 2. Final return value MUST be error
				if funcType.Results == nil || len(funcType.Results.List) == 0 {
					t.Errorf("method %s.%s must return error as its final return value, but has no return values", portName, mName)
				} else {
					lastResult := funcType.Results.List[len(funcType.Results.List)-1]
					if !isErrorType(lastResult.Type) {
						t.Errorf("method %s.%s final return value must be error", portName, mName)
					}
				}
			}
		}
	}

	// 4. Contract documentation verification
	// Expiry checks on time-bound stores (SessionStore, VerificationStore, RateLimitStore)
	// document "expires_at > now" or "ADR-0010".
	timeBoundStores := []string{"SessionStore", "VerificationStore", "RateLimitStore"}
	for _, storeName := range timeBoundStores {
		info, ok := foundPorts[storeName]
		if !ok {
			continue
		}
		fullDoc := info.docText
		for _, m := range info.iface.Methods.List {
			if m.Doc != nil {
				fullDoc += "\n" + m.Doc.Text()
			}
		}
		hasExpiryKeyword := strings.Contains(fullDoc, "expires_at > now") || strings.Contains(fullDoc, "ADR-0010")
		if !hasExpiryKeyword {
			t.Errorf("%s contract docs must contain 'expires_at > now' or 'ADR-0010'", storeName)
		}
	}

	// Atomic operations document "atomic" or "CAS"
	atomicMethods := []struct {
		port   string
		method string
	}{
		{"SessionStore", "UpdateTokenHash"},
		{"RateLimitStore", "Increment"},
		{"SecondaryStorage", "IncrementRateLimit"},
	}
	for _, am := range atomicMethods {
		info, ok := foundPorts[am.port]
		if !ok {
			continue
		}
		doc := getMethodDoc(info.iface, am.method)
		lowerDoc := strings.ToLower(doc)
		if !strings.Contains(lowerDoc, "atomic") && !strings.Contains(doc, "CAS") {
			t.Errorf("method %s.%s doc must contain 'atomic' or 'CAS', got doc: %s", am.port, am.method, doc)
		}
	}

	// Cache miss semantics on SecondaryStorage.GetSession document "nil, nil"
	if secInfo, ok := foundPorts["SecondaryStorage"]; ok {
		getSessionDoc := getMethodDoc(secInfo.iface, "GetSession")
		if !strings.Contains(getSessionDoc, "nil, nil") {
			t.Errorf("SecondaryStorage.GetSession doc must document 'nil, nil' cache miss semantics")
		}

		// Multi-tier write ordering on SecondaryStorage documents "primary"
		fullSecDoc := secInfo.docText
		for _, m := range secInfo.iface.Methods.List {
			if m.Doc != nil {
				fullSecDoc += "\n" + m.Doc.Text()
			}
		}
		if !strings.Contains(strings.ToLower(fullSecDoc), "primary") {
			t.Errorf("SecondaryStorage doc must document 'primary' write ordering")
		}
	}
}

// TestArch_StoragePortsImportRestrictions enforces zero third-party or adapter imports in
// store.go and secondary.go, permitting only stdlib context and time.
func TestArch_StoragePortsImportRestrictions(t *testing.T) {
	fset := token.NewFileSet()
	files := []string{"store.go", "secondary.go"}

	for _, file := range files {
		node, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parser.ParseFile failed for %s: %v", file, err)
		}

		for _, imp := range node.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			// Only stdlib context and time are permitted
			if importPath != "context" && importPath != "time" {
				t.Errorf("%s imports unauthorized package %q; storage ports may only import 'context' and 'time'",
					file, importPath)
			}
		}
	}
}

// TestArch_CryptoImportRestrictions enforces ADR-0001 & ADR-0002 for internal/crypto:
// Package internal/crypto must depend exclusively on the Go standard library and
// golang.org/x/crypto/argon2 (or subpackages under golang.org/x/crypto/).
// It must never import adapters, ORMs, HTTP frameworks, or external third-party packages.
func TestArch_CryptoImportRestrictions(t *testing.T) {
	fset := token.NewFileSet()
	cryptoDir := filepath.Join("internal", "crypto")

	pkgs, err := parser.ParseDir(fset, cryptoDir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go") && strings.HasSuffix(fi.Name(), ".go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parser.ParseDir failed for %s: %v", cryptoDir, err)
	}

	cryptoPkg, exists := pkgs["crypto"]
	if !exists {
		t.Fatalf("package 'crypto' not found in %s", cryptoDir)
	}

	fileCount := 0
	for fileName, fileNode := range cryptoPkg.Files {
		fileCount++
		relFile := filepath.Base(fileName)
		for _, importSpec := range fileNode.Imports {
			importPath := strings.Trim(importSpec.Path.Value, `"`)

			isStdLib := !strings.Contains(strings.Split(importPath, "/")[0], ".")
			isGolangXCrypto := importPath == "golang.org/x/crypto" || strings.HasPrefix(importPath, "golang.org/x/crypto/")

			if !isStdLib && !isGolangXCrypto {
				t.Errorf("%s imports unauthorized external package %q; internal/crypto may only import stdlib and golang.org/x/crypto/*",
					relFile, importPath)
			}
		}
	}

	if fileCount == 0 {
		t.Errorf("no source files parsed in %s", cryptoDir)
	}
}

// TestArch_CryptoExportedSymbolsDocComments asserts that all exported types,
// functions, variables/errors, and constants in internal/crypto possess non-empty
// godoc comments.
func TestArch_CryptoExportedSymbolsDocComments(t *testing.T) {
	fset := token.NewFileSet()
	cryptoDir := filepath.Join("internal", "crypto")

	pkgs, err := parser.ParseDir(fset, cryptoDir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go") && strings.HasSuffix(fi.Name(), ".go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parser.ParseDir failed for %s: %v", cryptoDir, err)
	}

	cryptoPkg, exists := pkgs["crypto"]
	if !exists {
		t.Fatalf("package 'crypto' not found in %s", cryptoDir)
	}

	exportedSymbolsCount := 0

	for fileName, fileNode := range cryptoPkg.Files {
		relFile := filepath.Base(fileName)
		for _, decl := range fileNode.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				switch d.Tok {
				case token.VAR, token.CONST:
					for _, spec := range d.Specs {
						valSpec, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						doc := ""
						if valSpec.Doc != nil {
							doc = strings.TrimSpace(valSpec.Doc.Text())
						} else if d.Doc != nil {
							doc = strings.TrimSpace(d.Doc.Text())
						}
						for _, name := range valSpec.Names {
							if name.IsExported() {
								exportedSymbolsCount++
								if doc == "" {
									t.Errorf("%s: exported symbol %s lacks godoc comment", relFile, name.Name)
								}
							}
						}
					}
				case token.TYPE:
					for _, spec := range d.Specs {
						typeSpec, ok := spec.(*ast.TypeSpec)
						if !ok {
							continue
						}
						if typeSpec.Name.IsExported() {
							exportedSymbolsCount++
							doc := ""
							if typeSpec.Doc != nil {
								doc = strings.TrimSpace(typeSpec.Doc.Text())
							} else if d.Doc != nil {
								doc = strings.TrimSpace(d.Doc.Text())
							}
							if doc == "" {
								t.Errorf("%s: exported type %s lacks godoc comment", relFile, typeSpec.Name.Name)
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Name.IsExported() {
					exportedSymbolsCount++
					doc := ""
					if d.Doc != nil {
						doc = strings.TrimSpace(d.Doc.Text())
					}
					if doc == "" {
						t.Errorf("%s: exported func %s lacks godoc comment", relFile, d.Name.Name)
					}
				}
			}
		}
	}

	if exportedSymbolsCount == 0 {
		t.Errorf("expected exported symbols in %s, found none", cryptoDir)
	}
}

func isContextParam(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "context" && sel.Sel.Name == "Context"
}

func isErrorType(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "error"
}

func getMethodDoc(iface *ast.InterfaceType, methodName string) string {
	for _, m := range iface.Methods.List {
		for _, n := range m.Names {
			if n.Name == methodName {
				if m.Doc != nil {
					return m.Doc.Text()
				}
				return ""
			}
		}
	}
	return ""
}
