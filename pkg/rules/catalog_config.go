package rules

import "regexp"

func configRules() []*Rule {
	return []*Rule{
		{
			ID:          "CFG-001",
			Name:        "Debug Mode Enabled",
			Description: "Debug mode enabled — disable in production",
			Severity:    SeverityWarning,
			Pattern:     regexp.MustCompile(`(?:(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|ON|on)|DebugMode\s*[=(])`),
			CWE:         "CWE-489",
			Tags:        []string{"config", "debug"},
		},
		{
			ID:          "CFG-002",
			Name:        "Permissive CORS",
			Description: "CORS allows all origins — potential security risk",
			Severity:    SeverityWarning,
			Pattern:     regexp.MustCompile(`(?:(?:Access-Control-Allow-Origin|allowAllOrigins|AllowAllOrigins)\s*[:=]\s*['"]?\*['"]?|CORS\(\))`),
			CWE:         "CWE-942",
			Tags:        []string{"config", "cors"},
		},
		{
			ID:          "CFG-003",
			Name:        "Insecure File Permissions",
			Description: "Overly permissive file permissions detected",
			Severity:    SeverityWarning,
			Pattern:     regexp.MustCompile(`(?:0777|0666|0777|chmod\s+777|os\.ModePerm)`),
			CWE:         "CWE-732",
			Tags:        []string{"config", "permissions"},
		},
		{
			ID:          "CFG-004",
			Name:        "Hardcoded IP Address",
			Description: "Hardcoded private/internal IP address detected",
			Severity:    SeverityWarning,
			Pattern:     regexp.MustCompile(`(?:(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)\s*[:=]`),
			CWE:         "CWE-200",
			Tags:        []string{"config", "network"},
		},
		{
			ID:          "CFG-005",
			Name:        "Missing HTTPS Enforcement",
			Description: "HTTP endpoint configured without HTTPS",
			Severity:    SeverityWarning,
			Pattern:     regexp.MustCompile(`(?i)(?:url|endpoint|host|base_url|base_url|server)\s*[:=]\s*['"]http://`),
			CWE:         "CWE-319",
			Tags:        []string{"config", "transport"},
		},
		{
			ID:          "CFG-006",
			Name:        "Exposed Stack Trace",
			Description: "Stack trace exposed to client — information disclosure",
			Severity:    SeverityWarning,
			Pattern:     regexp.MustCompile(`(?:(?:stacktrace|stack_trace|traceback|printStackTrace)\s*\(\s*\)|\.stack\s*\(\s*\))`),
			CWE:         "CWE-209",
			Tags:        []string{"config", "info-disclosure"},
		},
		{
			ID:          "CFG-007",
			Name:        "Binding to All Interfaces",
			Description: "Server bound to 0.0.0.0 — accessible from all network interfaces",
			Severity:    SeverityWarning,
			Pattern:     regexp.MustCompile(`(?:(?:0\.0\.0\.0|:::)\s*[:=,]|\.listen\s*\(\s*['"]?0\.0\.0\.0|\.listen\s*\(\s*\d+)`),
			CWE:         "CWE-668",
			Tags:        []string{"config", "network"},
		},
	}
}
