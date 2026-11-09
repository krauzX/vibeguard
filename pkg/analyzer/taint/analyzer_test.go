package taint

import (
	"strings"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/analyzer"
	"github.com/KrauzX/vibeguard/pkg/rules"
)

func analyze(t *testing.T, path, src string) []analyzer.Finding {
	t.Helper()

	findings, err := New().Analyze(&analyzer.FileContext{
		Path:     path,
		Content:  []byte(src),
		Language: rules.LanguageGo,
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	return findings
}

func TestCommandInjectionFromFormValue(t *testing.T) {
	src := `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("host")
	exec.Command("ping", "-c", "1", target).Run()
}
`

	findings := analyze(t, "handler.go", src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].RuleID != RuleCommandInjection || findings[0].CWE != "CWE-78" {
		t.Errorf("unexpected finding %+v", findings[0])
	}
	if !strings.Contains(findings[0].Message, "target") {
		t.Errorf("message should name the tainted variable: %q", findings[0].Message)
	}
}

func TestSQLInjectionFromQueryValue(t *testing.T) {
	src := `package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	db.Query(query)
}
`

	findings := analyze(t, "query.go", src)
	if len(findings) != 1 || findings[0].RuleID != RuleSQLInjection {
		t.Fatalf("expected TAINT-001, got %+v", findings)
	}
}

func TestPathTraversalFromArgs(t *testing.T) {
	src := `package main

import (
	"os"
)

func read() {
	name := os.Args[1]
	os.Open(name)
}
`

	findings := analyze(t, "read.go", src)
	if len(findings) != 1 || findings[0].RuleID != RulePathTraversal {
		t.Fatalf("expected TAINT-003, got %+v", findings)
	}
}

func TestSSRFFromHeader(t *testing.T) {
	src := `package main

import (
	"net/http"
)

func fetch(r *http.Request) {
	endpoint := r.Header.Get("X-Target")
	http.Get(endpoint)
}
`

	findings := analyze(t, "fetch.go", src)
	if len(findings) != 1 || findings[0].RuleID != RuleSSRF {
		t.Fatalf("expected TAINT-004, got %+v", findings)
	}
}

func TestLiteralArgumentsAreNotReported(t *testing.T) {
	src := `package main

import (
	"os"
	"os/exec"
)

func run() {
	exec.Command("ls", "-la").Run()
	os.Open("/etc/hosts")
}
`

	if findings := analyze(t, "safe.go", src); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}

func TestNumericConversionClearsTaint(t *testing.T) {
	src := `package main

import (
	"fmt"
	"net/http"
	"strconv"
)

func handler(r *http.Request) {
	raw := r.FormValue("id")
	id, err := strconv.Atoi(raw)
	if err != nil {
		return
	}
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
}
`

	if findings := analyze(t, "safe.go", src); len(findings) != 0 {
		t.Errorf("expected no findings after conversion, got %+v", findings)
	}
}

func TestTaintStopsAtFunctionBoundary(t *testing.T) {
	src := `package main

import "os"

func open(name string) {
	os.Open(name)
}

func caller() {
	open("fixed.txt")
}
`

	if findings := analyze(t, "boundary.go", src); len(findings) != 0 {
		t.Errorf("expected no findings for a literal call chain, got %+v", findings)
	}
}

func TestInvalidSyntaxReturnsError(t *testing.T) {
	_, err := New().Analyze(&analyzer.FileContext{
		Path:     "broken.go",
		Content:  []byte(`package main func (`),
		Language: rules.LanguageGo,
	})
	if err == nil {
		t.Error("expected error for invalid Go syntax")
	}
}

func TestUnsupportedLanguage(t *testing.T) {
	findings, err := New().Analyze(&analyzer.FileContext{
		Path:     "app.py",
		Content:  []byte("os.system(request.args['q'])\n"),
		Language: rules.LanguagePython,
	})
	if err != nil || len(findings) != 0 {
		t.Errorf("expected no findings for Python, got %v %v", findings, err)
	}
}
