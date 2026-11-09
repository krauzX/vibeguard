package output

import (
	"strings"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"
)

func TestMarkdownSummaryListsFindings(t *testing.T) {
	result := &scanner.Result{
		FilesScanned: 1,
		Findings: []rules.Finding{{
			RuleID:   "SEC-001",
			Severity: rules.SeverityCritical,
			File:     "main.go",
			Line:     7,
			Message:  "Hardcoded Slack Token",
			CWE:      "CWE-798",
		}},
	}

	text := FormatMarkdownSummary(result)
	for _, want := range []string{"# VibeGuard Security Report", "**CRITICAL:** 1", "main.go", "SEC-001", "CWE-798"} {
		if !strings.Contains(text, want) {
			t.Errorf("markdown output missing %q:\n%s", want, text)
		}
	}
}

func TestMarkdownSummaryHandlesCleanScan(t *testing.T) {
	text := FormatMarkdownSummary(&scanner.Result{})
	if !strings.Contains(text, "No issues found") {
		t.Errorf("expected a clean report, got:\n%s", text)
	}
}
