package contract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/config"
	"github.com/KrauzX/vibeguard/pkg/rules"
)

// repoRoot is two levels above internal/contract.
const repoRoot = "../.."

func goSources(t *testing.T, includeTests bool) map[string]string {
	t.Helper()

	sources := make(map[string]string)
	err := filepath.WalkDir(repoRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !includeTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sources[filepath.ToSlash(path)] = string(data)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return sources
}

// TestConfigFieldsAreConsumed fails when a config key has no reader.
func TestConfigFieldsAreConsumed(t *testing.T) {
	sources := goSources(t, false)

	outsideConfig := make(map[string]string)
	for path, body := range sources {
		if strings.Contains(path, "/pkg/config/") {
			continue
		}
		outsideConfig[path] = body
	}

	for _, field := range configFields(t) {
		needle := regexp.MustCompile(`\.` + regexp.QuoteMeta(field) + `\b`)
		if anyMatch(outsideConfig, needle) {
			continue
		}

		accessor := accessorFor(sources, field)
		if accessor == "" {
			t.Errorf("config field %q is never read", field)
			continue
		}

		call := regexp.MustCompile(`\.` + regexp.QuoteMeta(accessor) + `\(`)
		if !anyMatch(outsideConfig, call) {
			t.Errorf("config field %q is only read by %s(), which nothing calls", field, accessor)
		}
	}
}

func configFields(t *testing.T) []string {
	t.Helper()

	var fields []string
	var walk func(reflect.Type)
	seen := make(map[reflect.Type]bool)

	walk = func(typ reflect.Type) {
		if seen[typ] {
			return
		}
		seen[typ] = true

		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.Type.Kind() == reflect.Struct && field.Type != reflect.TypeOf(struct{}{}) {
				walk(field.Type)
				continue
			}
			fields = append(fields, field.Name)
		}
	}

	walk(reflect.TypeOf(*config.DefaultConfig()))
	return fields
}

func accessorFor(sources map[string]string, field string) string {
	fset := token.NewFileSet()
	needle := regexp.MustCompile(`\.` + regexp.QuoteMeta(field) + `\b`)

	for path, body := range sources {
		if !strings.Contains(path, "/pkg/config/") {
			continue
		}

		file, err := parser.ParseFile(fset, path, body, 0)
		if err != nil {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !fn.Name.IsExported() || fn.Body == nil {
				continue
			}
			start := fset.Position(fn.Body.Pos()).Offset
			end := fset.Position(fn.Body.End()).Offset
			if start >= 0 && end <= len(body) && needle.MatchString(body[start:end]) {
				return fn.Name.Name
			}
		}
	}

	return ""
}

func anyMatch(sources map[string]string, needle *regexp.Regexp) bool {
	for _, body := range sources {
		if needle.MatchString(body) {
			return true
		}
	}

	return false
}

// TestEveryRuleHasFix stops a rule from shipping without remediation text.
func TestEveryRuleHasFix(t *testing.T) {
	for _, rule := range rules.GetRules() {
		if rules.FixFor(rule.ID) == rules.FallbackFix {
			t.Errorf("rule %s has no fix text", rule.ID)
		}
	}
}

// TestActionableRulesCarryCWE keeps SARIF help URIs and reports meaningful.
func TestActionableRulesCarryCWE(t *testing.T) {
	cwe := regexp.MustCompile(`^CWE-\d+$`)

	for _, rule := range rules.GetRules() {
		if rule.Severity == rules.SeverityInfo {
			continue
		}
		if !cwe.MatchString(rule.CWE) {
			t.Errorf("rule %s is %s but has CWE %q", rule.ID, rule.Severity, rule.CWE)
		}
	}
}

// TestNoDeadExports fails when an exported function has no caller.
func TestNoDeadExports(t *testing.T) {
	sources := goSources(t, false)
	fset := token.NewFileSet()
	stringNames := regexp.MustCompile(`[A-Z][A-Za-z0-9_]+`)

	declared := make(map[string]string)
	used := make(map[string]bool)

	for path, body := range sources {
		file, err := parser.ParseFile(fset, path, body, 0)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}

		declNames := make(map[*ast.Ident]bool)
		if strings.Contains(path, "/pkg/") {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || !fn.Name.IsExported() {
					continue
				}
				declared[fn.Name.Name] = path
				declNames[fn.Name] = true
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.Ident:
				if !declNames[node] {
					used[node.Name] = true
				}
			case *ast.BasicLit:
				for _, name := range stringNames.FindAllString(node.Value, -1) {
					used[name] = true
				}
			}
			return true
		})
	}

	implicit := map[string]bool{
		"String": true, "Error": true, "Unwrap": true, "ExitCode": true,
		"MarshalJSON": true, "UnmarshalJSON": true, "Len": true, "Less": true,
		"Swap": true, "ServeHTTP": true, "Name": true,
	}

	for name, path := range declared {
		if used[name] || implicit[name] {
			continue
		}
		t.Errorf("exported %s in %s has no caller", name, path)
	}
}
