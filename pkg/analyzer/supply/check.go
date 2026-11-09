package supply

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

// RuleVulnerableDependency is reported for a pinned vulnerable version.
const RuleVulnerableDependency = "SC-001"

// Check reports vulnerable versions; err describes advisories it could not fetch.
func Check(ctx context.Context, root string, client *Client) ([]rules.Finding, int, error) {
	deps := ParseManifests(root)
	if len(deps) == 0 {
		return nil, 0, nil
	}

	vulns, lookupErr := client.Lookup(ctx, deps)
	if vulns == nil {
		return nil, len(deps), lookupErr
	}

	var findings []rules.Finding
	for idx, list := range vulns {
		dep := deps[idx]
		seen := make(map[string]bool, len(list))
		for _, vuln := range list {
			key := canonicalID(vuln)
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, rules.Finding{
				RuleID:   RuleVulnerableDependency,
				Severity: rules.SeverityCritical,
				File:     dep.File,
				Line:     dep.Line,
				EndLine:  dep.Line,
				Message:  message(dep, vuln),
				Code:     fmt.Sprintf("%s %s", dep.Name, dep.Version),
				CWE:      "CWE-1395",
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Message < findings[j].Message
	})

	return findings, len(deps), lookupErr
}

// canonicalID prefers the CVE alias so two advisories for the same flaw are
// reported once.
func canonicalID(vuln Vuln) string {
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return vuln.ID
}

func message(dep Dependency, vuln Vuln) string {
	text := fmt.Sprintf("Vulnerable dependency %s %s: %s", dep.Name, dep.Version, canonicalID(vuln))
	if vuln.Summary != "" {
		text += " — " + vuln.Summary
	}
	if vuln.Fixed != "" {
		text += fmt.Sprintf(" (fixed in %s)", vuln.Fixed)
	}

	return text
}
