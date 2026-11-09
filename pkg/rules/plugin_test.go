package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPluginRuleKeepsItsFix(t *testing.T) {
	dir := t.TempDir()
	loader := NewPluginLoader(dir)
	if err := loader.InitDir(); err != nil {
		t.Fatal(err)
	}

	body := `[{"id":"CUS-001","name":"Custom secret","pattern":"SECRET_[A-Z]{6}","severity":"CRITICAL","fix":"Read it from the environment","enabled":true}]`
	if err := os.WriteFile(filepath.Join(dir, "rules", "custom.json"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := loader.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected one rule, got %d", len(loaded))
	}

	rule := loaded[0]
	if rule.Fix != "Read it from the environment" {
		t.Errorf("fix text was dropped on load: %q", rule.Fix)
	}

	finding := MatchLineBytes(rule, []byte(`value = "SECRET_ABCDEF"`), 1, "app.py", 200)
	if finding == nil {
		t.Fatal("rule did not match")
	}
	if finding.FixText() != "Read it from the environment" {
		t.Errorf("finding lost the rule fix: %q", finding.FixText())
	}

	if err := loader.SaveRule(rule); err != nil {
		t.Fatal(err)
	}
	saved, err := loader.LoadFile(filepath.Join(dir, "rules", "cus-001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 1 || saved[0].Fix != rule.Fix {
		t.Errorf("fix text did not survive a save: %+v", saved)
	}
}

func TestFixTextFallsBackForBuiltins(t *testing.T) {
	finding := Finding{RuleID: "SEC-001"}

	if finding.FixText() != FixFor("SEC-001") {
		t.Errorf("expected the built-in fix, got %q", finding.FixText())
	}
	if FixFor("UNKNOWN-001") != FallbackFix {
		t.Error("unknown rules should get the fallback text")
	}
}
