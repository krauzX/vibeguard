package rules

import (
	"strings"
	"testing"
)

// sample builds fixtures at runtime so the repository self-scan stays clean.
func sample(parts ...string) string {
	return strings.Join(parts, "")
}

func ruleByID(t *testing.T, id string) *Rule {
	t.Helper()
	for _, r := range GetRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return nil
}

func TestPrefilterKeepsMatchingLines(t *testing.T) {
	samples := []struct {
		rule string
		line string
	}{
		{"SEC-001", sample(`token := "xoxb-`, `123456789012-abcdefghijklm"`)},
		{"SEC-002", sample(`key := "AKIA`, `IOSFODNN7EXAMPLE"`)},
		{"SEC-003", sample(`aws_secret_access_key = "`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`)},
		{"SEC-006", sample(`t := "ghp_`, `012345678901234567890123456789012345"`)},
		{"SEC-010", sample(`PASSWORD = `, `"hunter2hunter2"`)},
		{"SEC-011", sample(`db := "postgres`, `://user:pass@localhost/app"`)},
	}

	for _, s := range samples {
		rule := ruleByID(t, s.rule)
		if f := MatchLineBytes(rule, []byte(s.line), 1, "sample.go", 200); f == nil {
			t.Errorf("%s no longer matches %q after prefiltering", s.rule, s.line)
		}
	}
}

func TestPrefilterRejectsUnrelatedLines(t *testing.T) {
	rule := ruleByID(t, "SEC-002")
	for _, line := range []string{
		`func handler(w http.ResponseWriter) {}`,
		`key := "not-a-key"`,
		`const retries = 2`,
	} {
		if f := MatchLineBytes(rule, []byte(line), 1, "sample.go", 200); f != nil {
			t.Errorf("unexpected match on %q", line)
		}
	}
}

func TestAnchorsAreRequiredLiterals(t *testing.T) {
	cases := map[string]string{
		"SEC-001": "xox",
		"SEC-002": "AKIA",
		"SEC-006": "ghp_",
	}

	for id, want := range cases {
		rule := ruleByID(t, id)
		if len(rule.Anchors) == 0 {
			t.Fatalf("%s has no anchors", id)
		}

		found := false
		for _, a := range rule.Anchors {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s anchors %v do not include %q", id, rule.Anchors, want)
		}
	}
}
