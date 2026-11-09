package syntax

import (
	"testing"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

func finding(ruleID string, line, column, endColumn int) rules.Finding {
	return rules.Finding{
		RuleID:    ruleID,
		File:      "sample",
		Line:      line,
		Column:    column,
		EndLine:   line,
		EndColumn: endColumn,
	}
}

func TestCommentMatchesAreDropped(t *testing.T) {
	files := map[string]string{
		"a.js":   "// el.innerHTML = input\nel.innerHTML = input;\n",
		"a.py":   "# eval(payload)\nresult = eval(payload)\n",
		"a.go":   "// os.Chmod(path, 0777)\npackage a\n",
		"a.java": "// Runtime.getRuntime().exec(cmd)\nclass A {}\n",
	}
	for name, src := range files {
		got := Filter(name, []byte(src), []rules.Finding{finding("PAT-001", 1, 4, 20)})
		if len(got) != 0 {
			t.Errorf("%s: comment match survived: %+v", name, got)
		}
	}

	got := Filter("a.js", []byte(files["a.js"]), []rules.Finding{finding("PAT-001", 2, 1, 22)})
	if len(got) != 1 {
		t.Fatalf("code match was dropped: %+v", got)
	}
}

func TestStringMatchesNeedSecretRules(t *testing.T) {
	src := []byte("const note = \"never do el.innerHTML = input\";\nconst key = \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\";\n")

	if got := Filter("a.js", src, []rules.Finding{finding("PAT-001", 1, 15, 38)}); len(got) != 0 {
		t.Errorf("string match survived: %+v", got)
	}

	secret := Filter("a.js", src, []rules.Finding{finding("SEC-006", 2, 14, 54)})
	if len(secret) != 1 {
		t.Fatalf("secret inside a string was dropped: %+v", secret)
	}
}

func TestInterpolatedCodeStaysVisible(t *testing.T) {
	src := []byte("payload = input()\nout = f\"{eval(payload)}\"\n")
	if got := Filter("a.py", src, []rules.Finding{finding("VULN-001", 2, 8, 21)}); len(got) != 1 {
		t.Fatalf("interpolated expression was suppressed: %+v", got)
	}
}

func TestUnparsedInputIsUnchanged(t *testing.T) {
	f := []rules.Finding{finding("PAT-001", 1, 1, 10)}
	for _, name := range []string{"a.txt", "a.sh", "a.broken"} {
		if got := Filter(name, []byte("el.innerHTML = input\n"), f); len(got) != 1 {
			t.Errorf("%s: finding dropped without a parser: %+v", name, got)
		}
	}
}

func TestBrokenSourceDoesNotPanic(t *testing.T) {
	src := []byte("function ( { `unterminated\n el.innerHTML = x;\n")
	got := Filter("a.js", src, []rules.Finding{finding("PAT-001", 2, 2, 18)})
	if len(got) > 1 {
		t.Fatalf("unexpected duplication: %+v", got)
	}
}
