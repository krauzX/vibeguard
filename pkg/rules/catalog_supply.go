package rules

// supplyRules describe findings that come from a vulnerability database rather
// than from matching a line, so they are reported without a pattern.
func supplyRules() []*Rule {
	return []*Rule{
		{
			ID:          "SC-001",
			Name:        "Vulnerable Dependency",
			Description: "A pinned dependency version has a published advisory in OSV",
			Severity:    SeverityCritical,
			CWE:         "CWE-1395",
			Tags:        []string{"supply-chain", "dependencies"},
			ReportOnly:  true,
		},
	}
}
