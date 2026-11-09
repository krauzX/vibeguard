package rules

import "regexp"

func languageRules() []*Rule {
	return []*Rule{
		{
			ID:          "GO-003",
			Name:        "Goroutine Leak Risk",
			Description: "Unbuffered channel in goroutine — potential deadlock",
			Severity:    SeverityWarning,
			Languages:   []Language{LanguageGo},
			Pattern:     regexp.MustCompile(`(?:make\s*\(\s*chan\s+\w+\s*\))`),
			CWE:         "CWE-672",
			Tags:        []string{"go", "goroutine", "channel"},
		},
		{
			ID:          "PY-001",
			Name:        "Python exec() Usage",
			Description: "Dynamic code execution via exec() — high risk of code injection",
			Severity:    SeverityCritical,
			Languages:   []Language{LanguagePython},
			Pattern:     regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])(?:exec|__import__)\s*\(`),
			CWE:         "CWE-94",
			Tags:        []string{"python", "injection"},
		},
		{
			ID:          "PY-002",
			Name:        "Python eval() Usage",
			Description: "Dynamic code evaluation via eval() — expression injection risk",
			Severity:    SeverityCritical,
			Languages:   []Language{LanguagePython},
			Pattern:     regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])eval\s*\(`),
			CWE:         "CWE-95",
			Tags:        []string{"python", "injection"},
		},
		{
			ID:          "PY-003",
			Name:        "Tempfile Usage",
			Description: "Predictable temporary file — symlink race condition risk",
			Severity:    SeverityWarning,
			Languages:   []Language{LanguagePython},
			Pattern:     regexp.MustCompile(`(?:tempfile\.mktemp|tempfile\.tempfile)\s*\(`),
			CWE:         "CWE-377",
			Tags:        []string{"python", "tempfile"},
		},
		{
			ID:          "PY-004",
			Name:        "Assert in Production",
			Description: "assert statement used for control flow — disabled with -O flag",
			Severity:    SeverityWarning,
			Languages:   []Language{LanguagePython},
			Pattern:     regexp.MustCompile(`^\s*assert\s+`),
			CWE:         "CWE-617",
			Tags:        []string{"python", "assertion"},
		},
	}
}
