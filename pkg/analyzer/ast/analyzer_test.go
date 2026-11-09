package ast

import (
	"testing"

	"github.com/KrauzX/vibeguard/pkg/analyzer"
	"github.com/KrauzX/vibeguard/pkg/rules"
)

func analyze(t *testing.T, src string) []analyzer.Finding {
	t.Helper()

	findings, err := New().Analyze(&analyzer.FileContext{
		Path:     "sample.go",
		Content:  []byte(src),
		Language: rules.LanguageGo,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	return findings
}

func byRule(findings []analyzer.Finding, id RuleID) []analyzer.Finding {
	var matched []analyzer.Finding
	for _, f := range findings {
		if f.RuleID == string(id) {
			matched = append(matched, f)
		}
	}
	return matched
}

const ignoredErrorSource = `package sample

import "errors"

type store struct{}

func load(path string) (string, error) {
	return "", errors.New("missing")
}

func (s *store) save() error {
	return nil
}

func run(s *store) {
	load("config")
	_ = load("cache")
	s.save()
	value, err := load("data")
	if err != nil {
		return
	}
	_ = value
	defer s.save()
}
`

func TestIgnoredErrorIsReported(t *testing.T) {
	findings := byRule(analyze(t, ignoredErrorSource), RuleIgnoredError)

	if len(findings) != 3 {
		t.Fatalf("expected 3 ignored errors, got %d: %+v", len(findings), findings)
	}

	lines := []int{findings[0].Line, findings[1].Line, findings[2].Line}
	if lines[0] != 16 || lines[1] != 17 || lines[2] != 18 {
		t.Fatalf("wrong lines reported: %v", lines)
	}
	if findings[0].CWE != "CWE-252" || findings[0].Severity != rules.SeverityWarning {
		t.Fatalf("unexpected metadata: %+v", findings[0])
	}
}

func TestHandledErrorsAreQuiet(t *testing.T) {
	src := `package sample

import "os"

func open(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	os.Open(path)
}
`
	if findings := byRule(analyze(t, src), RuleIgnoredError); len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

const synchronizedSource = `package sample

import "sync"

func awaited() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		work()
	}()
	wg.Wait()
}

func signalled() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		work()
	}()
	<-done
}

func selected(ch chan int) {
	go func() { ch <- 1 }()
	select {
	case <-ch:
	}
}
`

func TestSynchronizedGoroutinesAreQuiet(t *testing.T) {
	if findings := byRule(analyze(t, synchronizedSource), RuleUnsynchronizedGo); len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestUnsynchronizedGoroutineIsReported(t *testing.T) {
	src := `package sample

type server struct {
	wg sync.WaitGroup
}

func start() {
	go work()
}

func (s *server) serve() {
	go work()
}

func (s *server) run() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		work()
	}()
	s.wg.Wait()
}
`
	findings := byRule(analyze(t, src), RuleUnsynchronizedGo)

	if len(findings) != 2 {
		t.Fatalf("expected 2 goroutines, got %d: %+v", len(findings), findings)
	}
	if findings[0].Line != 8 || findings[1].Line != 12 {
		t.Fatalf("wrong lines reported: %d, %d", findings[0].Line, findings[1].Line)
	}
}

func TestUnsupportedLanguageIsSkipped(t *testing.T) {
	findings, err := New().Analyze(&analyzer.FileContext{
		Path:     "sample.py",
		Content:  []byte("go work()\n"),
		Language: rules.LanguagePython,
	})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected no findings, got %v %+v", err, findings)
	}
}

func TestBrokenGoIsAnError(t *testing.T) {
	_, err := New().Analyze(&analyzer.FileContext{
		Path:     "broken.go",
		Content:  []byte("func (\n"),
		Language: rules.LanguageGo,
	})
	if err == nil {
		t.Fatal("expected a parse error")
	}
}
