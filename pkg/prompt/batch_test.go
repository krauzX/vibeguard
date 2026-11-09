package prompt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

func TestGenerateBatchCoversEveryFinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.go")
	src := "package main\n\nvar key = \"secret\"\n\nfunc main() {}\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	findings := []rules.Finding{
		{RuleID: "SEC-001", File: path, Line: 3, Message: "Hardcoded Secret", CWE: "CWE-798"},
		{RuleID: "PLH-001", File: path, Line: 5, Message: "Placeholder Code", CWE: "CWE-798"},
	}

	generator := NewBatchGenerator(Generic)
	batch, err := generator.GenerateBatch(path, findings)
	if err != nil {
		t.Fatalf("GenerateBatch() error = %v", err)
	}

	if len(batch.Prompts) != len(findings) {
		t.Fatalf("expected %d prompts, got %d", len(findings), len(batch.Prompts))
	}

	text := generator.FormatBatch(batch)
	for _, want := range []string{filepath.Base(path), "SEC-001", "PLH-001"} {
		if !strings.Contains(text, want) {
			t.Errorf("batch output missing %q:\n%s", want, text)
		}
	}
}

func TestGenerateBatchRejectsEmptyInput(t *testing.T) {
	if _, err := NewBatchGenerator(Generic).GenerateBatch("x.go", nil); err == nil {
		t.Error("expected an error for an empty batch")
	}
}
