package analyzer

import (
	"sort"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

type mockAnalyzer struct {
	name     string
	langs    []Language
	findings []Finding
}

func (m *mockAnalyzer) Name() string {
	return m.name
}

func (m *mockAnalyzer) Analyze(ctx *FileContext) ([]Finding, error) {
	return m.findings, nil
}

func (m *mockAnalyzer) SupportedLanguages() []Language {
	return m.langs
}

func TestRegister(t *testing.T) {
	r := NewRegistry()
	a := &mockAnalyzer{
		name:  "test",
		langs: []Language{rules.LanguageGo},
	}
	r.Register("test", a)

	got, ok := r.Get("test")
	if !ok {
		t.Fatal("expected to find analyzer")
	}
	if got.Name() != "test" {
		t.Fatalf("expected name 'test', got %q", got.Name())
	}
}

func TestGetByName(t *testing.T) {
	r := NewRegistry()
	a := &mockAnalyzer{name: "a"}
	r.Register("a", a)

	got, ok := r.Get("a")
	if !ok || got.Name() != "a" {
		t.Fatal("expected to find analyzer 'a'")
	}

	_, ok = r.Get("nonexistent")
	if ok {
		t.Fatal("expected false for nonexistent analyzer")
	}
}

func TestAnalyze(t *testing.T) {
	r := NewRegistry()
	r.Register("a", &mockAnalyzer{
		name:  "a",
		langs: []Language{rules.LanguageGo},
		findings: []Finding{
			{RuleID: "GO-001", Severity: rules.SeverityWarning, File: "main.go", Line: 10, Message: "finding a"},
		},
	})
	r.Register("b", &mockAnalyzer{
		name:  "b",
		langs: []Language{rules.LanguagePython},
		findings: []Finding{
			{RuleID: "PY-001", Severity: rules.SeverityCritical, File: "app.py", Line: 5, Message: "finding b"},
		},
	})
	r.Register("c", &mockAnalyzer{
		name:  "c",
		langs: []Language{rules.LanguageAny},
		findings: []Finding{
			{RuleID: "CFG-001", Severity: rules.SeverityWarning, File: "config.yaml", Line: 1, Message: "finding c"},
		},
	})

	ctx := &FileContext{Path: "main.go", Language: rules.LanguageGo}
	findings := r.Analyze(ctx)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for Go file, got %d", len(findings))
	}

	ruleIDs := []string{}
	for _, f := range findings {
		ruleIDs = append(ruleIDs, f.RuleID)
	}
	sort.Strings(ruleIDs)
	if ruleIDs[0] != "CFG-001" || ruleIDs[1] != "GO-001" {
		t.Fatalf("expected [CFG-001 GO-001], got %v", ruleIDs)
	}
}
