package scanner

import (
	"strings"
	"testing"
)

// built at runtime so this fixture is not itself a finding.
var credentialLine = "password" + ` = "hunter2` + `hunter2"`

func scanSource(t *testing.T, name, content string) *Result {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, name, content)
	return scanDir(t, dir, nil)
}

func TestMatchesAtColumnZeroKeepTheirLine(t *testing.T) {
	content := strings.Join([]string{
		credentialLine,
		"x = 1",
		credentialLine,
	}, "\n") + "\n"

	result := scanSource(t, "two.py", content)

	var lines []int
	for _, f := range result.Findings {
		if f.RuleID == "SEC-010" {
			lines = append(lines, f.Line)
		}
	}

	if len(lines) != 2 || lines[0] != 1 || lines[1] != 3 {
		t.Fatalf("expected findings on lines 1 and 3, got %v", lines)
	}
}

func TestEveryLineIsEvaluated(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString("  eval(q);\n")
	}

	result := scanSource(t, "many.js", b.String())

	count := 0
	for _, f := range result.Findings {
		if f.RuleID == "VULN-001" {
			count++
		}
	}

	if count != 200 {
		t.Fatalf("expected 200 findings, got %d", count)
	}
}

func TestLeadingEvalIsDetected(t *testing.T) {
	result := scanSource(t, "start.js", "eval(q);\nconst x = 1;\n")

	if len(result.Findings) == 0 {
		t.Fatal("eval at the start of a line was not detected")
	}
}
