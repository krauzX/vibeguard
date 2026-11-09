package rules

import "regexp"

func qualityRules() []*Rule {
	return []*Rule{
		{
			ID:          "PLH-001",
			Name:        "Placeholder Code",
			Description: "TODO/FIXME/placeholder comment — incomplete implementation",
			Severity:    SeverityInfo,
			Pattern:     regexp.MustCompile(`(?i)(?://\s*(?:TODO|FIXME|HACK|XXX|TEMP|PLACEHOLDER|IMPLEMENT|STUB|MOCK)\b|/\*\s*(?:TODO|FIXME|HACK|XXX))`),
			CWE:         "",
			Tags:        []string{"placeholder", "incomplete"},
		},
		{
			ID:          "PLH-002",
			Name:        "Insert Code Placeholder",
			Description: "Marker such as INSERT_CODE_HERE left where logic belongs",
			Severity:    SeverityInfo,
			Pattern:     regexp.MustCompile(`(?i)(?:INSERT(?:ED)?[_\s]?CODE|PLACEHOLDER[_\s]?CODE|INSERT[_\s]?LOGIC[_\s]?HERE|YOUR[_\s]?CODE[_\s]?HERE|ADD[_\s]?YOUR[_\s]?CODE)`),
			CWE:         "",
			Tags:        []string{"placeholder"},
		},
		{
			ID:          "PLH-003",
			Name:        "Snippet Comment Pattern",
			Description: "Comment stub such as a bare ellipsis or a hashed TODO",
			Severity:    SeverityInfo,
			Pattern:     regexp.MustCompile(`(?i)(?://\s*\.\.\.\s*$|/\*\s*\.\.\.\s*\*/|#+\s*(?:TODO|HACK|NOTE)\s*:)`),
			CWE:         "",
			Tags:        []string{"comment", "placeholder"},
		},
		{
			ID:          "PLH-004",
			Name:        "Unresolved Package Reference",
			Description: "Placeholder package name that usually does not resolve",
			Severity:    SeverityWarning,
			Pattern:     regexp.MustCompile(`(?i)(?:faker[-_]library|example[-_]api[-_]v1|mock[-_]service[-_]internal|sample[-_]package|test[-_]fixture|demo[-_]module|placeholder[-_]lib)`),
			CWE:         "CWE-829",
			Tags:        []string{"dependency", "placeholder"},
		},
		{
			ID:          "PLH-005",
			Name:        "Empty Error Handling",
			Description: "Empty catch/except block — errors silently swallowed",
			Severity:    SeverityWarning,
			Pattern:     regexp.MustCompile(`(?:(?:catch|except)\s*(?:\([^)]*\))?\s*\{\s*\}|except\s*:\s*$)`),
			CWE:         "CWE-390",
			Tags:        []string{"error-handling"},
		},
		{
			ID:          "QLT-001",
			Name:        "Console/Print Statement",
			Description: "Debug output left in code — remove before production",
			Severity:    SeverityInfo,
			Pattern:     regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])(?:console\.log|System\.out\.print(?:ln)?|print|puts|Logger\.(?:info|debug))\s*\(|(?:^|[^a-zA-Z0-9_])p\s+['"]`),
			CWE:         "",
			Tags:        []string{"quality", "debug-output"},
		},
		{
			ID:          "QLT-002",
			Name:        "Commented-out Code",
			Description: "Large block of commented-out code — should be removed",
			Severity:    SeverityInfo,
			Pattern:     regexp.MustCompile(`^\s*//\s*(?:if|for|func|return|var|const|let|class|def|import)\s`),
			CWE:         "",
			Tags:        []string{"quality", "dead-code"},
		},
		{
			ID:          "QLT-003",
			Name:        "Magic Number",
			Description: "Hardcoded numeric literal — consider named constant",
			Severity:    SeverityInfo,
			Pattern:     regexp.MustCompile(`(?:(?:==|!=|>=|<=|>|<)\s*\d{4,}|(?:timeout|retry|delay|max|min|limit|size|count|threshold)\s*[:=]\s*\d{4,})`),
			CWE:         "",
			Tags:        []string{"quality", "magic-number"},
		},
		{
			ID:          "QLT-004",
			Name:        "Deeply Nested Code",
			Description: "Code with excessive nesting depth — refactor for readability",
			Severity:    SeverityInfo,
			Pattern:     regexp.MustCompile(`^\t{6,}(?:if|for|while|func|def|class|switch|select)`),
			CWE:         "",
			Tags:        []string{"quality", "complexity"},
		},
	}
}
