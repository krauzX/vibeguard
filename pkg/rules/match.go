package rules

import (
	"bytes"
	"unicode/utf8"
)

// FoldAnchors reports whether the anchors are lowercase and match a folded buffer.
func (r *Rule) FoldAnchors() bool {
	return r.foldAnchors
}

// MatchLineBytes scans one line and only builds a snippet when the rule hits.
// Callers are expected to have filtered the rule with MayMatch first.
func MatchLineBytes(rule *Rule, line []byte, lineNum int, filename string, maxSnippet int) *Finding {
	idx := rule.Pattern.FindIndex(line)
	if idx == nil {
		return nil
	}

	return &Finding{
		RuleID:    rule.ID,
		Severity:  rule.Severity,
		File:      filename,
		Line:      lineNum,
		Column:    runeColumn(line, idx[0]),
		EndLine:   lineNum,
		EndColumn: runeColumn(line, idx[1]),
		Message:   rule.Name,
		Code:      snippet(line, maxSnippet),
		CWE:       rule.CWE,
		Fix:       rule.Fix,
	}
}

// runeColumn converts a byte offset into the 1-based character column that
// editors, SARIF and GitHub annotations expect.
func runeColumn(line []byte, offset int) int {
	if offset > len(line) {
		offset = len(line)
	}

	return utf8.RuneCount(line[:offset]) + 1
}

func snippet(line []byte, limit int) string {
	line = bytes.TrimSpace(line)
	if limit <= 0 || len(line) <= limit {
		return string(line)
	}

	cut := limit
	for cut > 0 && !utf8.RuneStart(line[cut]) {
		cut--
	}

	return string(line[:cut]) + "..."
}
