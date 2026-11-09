package rules

import "regexp"

func injectionRules() []*Rule {
	return []*Rule{
		{
			ID:          "VULN-001",
			Name:        "Code Injection via eval()",
			Description: "Dynamic code execution via eval() — high risk of RCE",
			Severity:    SeverityCritical,
			Languages:   []Language{LanguageJS, LanguageTS, LanguagePython, LanguagePHP, LanguageRuby},
			Pattern:     regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])eval\s*\(|new\s+Function\s*\(`),
			CWE:         "CWE-94",
			Tags:        []string{"injection", "rce"},
		},
		{
			ID:          "VULN-002",
			Name:        "Command Injection via exec()",
			Description: "System command execution — risk of command injection",
			Severity:    SeverityCritical,
			Languages:   []Language{LanguagePython, LanguageRuby, LanguagePHP},
			Pattern:     regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(`),
			CWE:         "CWE-78",
			Tags:        []string{"injection", "command"},
		},
		{
			ID:          "VULN-003",
			Name:        "Shell Injection via shell=True",
			Description: "Python subprocess with shell=True enables shell injection",
			Severity:    SeverityCritical,
			Languages:   []Language{LanguagePython},
			Pattern:     regexp.MustCompile(`subprocess\.\w+\(.*shell\s*=\s*True`),
			CWE:         "CWE-78",
			Tags:        []string{"injection", "command", "python"},
		},
		{
			ID:          "VULN-004",
			Name:        "Command Injection via child_process",
			Description: "Node.js child_process execution — risk of command injection",
			Severity:    SeverityCritical,
			Languages:   []Language{LanguageJS, LanguageTS},
			Pattern:     regexp.MustCompile(`(?:child_process|node:child_process)\.(?:exec|execSync|execFile)\s*\(`),
			CWE:         "CWE-78",
			Tags:        []string{"injection", "command", "nodejs"},
		},
		{
			ID:          "VULN-005",
			Name:        "SQL Injection via String Formatting",
			Description: "SQL query built with string formatting — risk of SQL injection",
			Severity:    SeverityCritical,
			Languages:   []Language{LanguagePython, LanguageJS, LanguageTS, LanguageJava, LanguageRuby, LanguagePHP},
			Pattern:     regexp.MustCompile(`(?:fmt\.Sprintf|\.format\()\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s`),
			CWE:         "CWE-89",
			Tags:        []string{"injection", "sql"},
		},
		{
			ID:          "VULN-006",
			Name:        "Insecure Deserialization (pickle)",
			Description: "Deserializing untrusted data with pickle — remote code execution risk",
			Severity:    SeverityCritical,
			Languages:   []Language{LanguagePython},
			Pattern:     regexp.MustCompile(`(?:pickle\.loads?\(|shelve\.open|marshal\.loads?\()`),
			CWE:         "CWE-502",
			Tags:        []string{"deserialization", "python"},
		},
		{
			ID:          "VULN-007",
			Name:        "Insecure YAML Deserialization",
			Description: "YAML loading without SafeLoader — code execution risk",
			Severity:    SeverityCritical,
			Languages:   []Language{LanguagePython},
			Pattern:     regexp.MustCompile(`yaml\.(?:load|unsafe_load)\s*\(`),
			CWE:         "CWE-502",
			Tags:        []string{"deserialization", "python", "yaml"},
		},
	}
}
