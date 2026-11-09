package rules

import "testing"

func TestCatalogsCoverEveryRule(t *testing.T) {
	groups := map[string][]*Rule{
		"secret":    secretRules(),
		"injection": injectionRules(),
		"web":       webRules(),
		"config":    configRules(),
		"quality":   qualityRules(),
		"language":  languageRules(),
		"supply":    supplyRules(),
	}

	total := 0
	for name, group := range groups {
		if len(group) == 0 {
			t.Errorf("catalog %s is empty", name)
		}
		total += len(group)
	}

	if total != len(GetRules()) {
		t.Fatalf("catalogs hold %d rules, registry holds %d", total, len(GetRules()))
	}
}

func TestRuleIDsAreUnique(t *testing.T) {
	seen := make(map[string]bool, len(GetRules()))
	for _, r := range GetRules() {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestEveryRuleIsUsable(t *testing.T) {
	for _, r := range GetRules() {
		switch {
		case r.ID == "":
			t.Error("rule without id")
		case r.Name == "":
			t.Errorf("%s has no name", r.ID)
		case r.Pattern == nil && !r.ReportOnly:
			t.Errorf("%s has no pattern", r.ID)
		case len(r.Tags) == 0:
			t.Errorf("%s has no tags", r.ID)
		case r.CWE == "" && r.Severity == SeverityCritical:
			t.Errorf("%s is critical but maps to no CWE", r.ID)
		}
	}
}

func TestRuleLookupByID(t *testing.T) {
	rule := GetRuleByID("SEC-002")
	if rule == nil {
		t.Fatal("SEC-002 missing from the registry")
	}
	if rule.Severity != SeverityCritical {
		t.Fatalf("SEC-002 severity changed to %v", rule.Severity)
	}
	if len(rule.Anchors) == 0 {
		t.Fatal("SEC-002 lost its anchors")
	}
}
