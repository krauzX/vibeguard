package diff

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"
)

const tenLines = "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n"

func gitRepo(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	dir := t.TempDir()
	git(t, dir, "init", "-q")
	git(t, dir, "config", "user.email", "test@example.com")
	git(t, dir, "config", "user.name", "Test")
	git(t, dir, "config", "core.autocrlf", "false")

	return dir
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}

	return string(out)
}

func writeFile(t *testing.T, dir, rel, content string) string {
	t.Helper()

	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func commitAll(t *testing.T, dir, message string) {
	t.Helper()

	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", message)
}

func TestChangedLinesOnlyIncludesEditedLines(t *testing.T) {
	dir := gitRepo(t)
	writeFile(t, dir, "main.go", tenLines)
	commitAll(t, dir, "base")

	edited := "one\ntwo\nthree\nFOUR\nfive\nsix\nseven\neight\nNINE\nten\n"
	writeFile(t, dir, "main.go", edited)

	ranges, err := ChangedLines(dir, "HEAD")
	if err != nil {
		t.Fatalf("ChangedLines: %v", err)
	}

	if got := len(ranges["main.go"]); got != 2 {
		t.Fatalf("expected 2 hunks, got %d: %v", got, ranges["main.go"])
	}
	for _, line := range []int{4, 9} {
		if !ranges.Contains("main.go", line) {
			t.Errorf("line %d should be reported as changed", line)
		}
	}
	for _, line := range []int{1, 3, 5, 8, 10} {
		if ranges.Contains("main.go", line) {
			t.Errorf("line %d was not touched but is reported as changed", line)
		}
	}
}

func TestChangedLinesIncludesUntrackedFiles(t *testing.T) {
	dir := gitRepo(t)
	writeFile(t, dir, "main.go", tenLines)
	commitAll(t, dir, "base")

	writeFile(t, dir, "pkg/new.go", "package pkg\n\nfunc New() {}\n")

	ranges, err := ChangedLines(dir, "HEAD")
	if err != nil {
		t.Fatalf("ChangedLines: %v", err)
	}

	if !ranges.Contains("pkg/new.go", 3) {
		t.Fatalf("untracked file lines must count as changed, got %v", ranges)
	}
	if ranges.Contains("main.go", 3) {
		t.Fatal("an untouched file must not be reported as changed")
	}
}

func TestChangedLinesUsesExplicitBase(t *testing.T) {
	dir := gitRepo(t)
	writeFile(t, dir, "main.go", tenLines)
	commitAll(t, dir, "base")
	first := git(t, dir, "rev-parse", "HEAD")
	first = first[:len(first)-1]

	writeFile(t, dir, "main.go", "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nTEN\n")
	commitAll(t, dir, "second")

	ranges, err := ChangedLines(dir, first)
	if err != nil {
		t.Fatalf("ChangedLines: %v", err)
	}

	if !ranges.Contains("main.go", 10) {
		t.Fatalf("line changed since %s should be reported, got %v", first, ranges["main.go"])
	}
	if ranges.Contains("main.go", 9) {
		t.Fatal("line 9 is identical in both commits")
	}
}

func TestChangedLinesWithoutCommitsTreatsTrackedFilesAsNew(t *testing.T) {
	dir := gitRepo(t)
	writeFile(t, dir, "main.go", tenLines)
	git(t, dir, "add", "main.go")

	ranges, err := ChangedLines(dir, "HEAD")
	if err != nil {
		t.Fatalf("a repository without commits must still be scannable: %v", err)
	}

	if !ranges.Contains("main.go", 7) {
		t.Fatalf("every line of a new file is changed, got %v", ranges)
	}
}

func TestChangedLinesHandlesQuotedPaths(t *testing.T) {
	dir := gitRepo(t)
	writeFile(t, dir, "docs/read me.go", tenLines)
	writeFile(t, dir, "docs/ünïcode.go", tenLines)
	commitAll(t, dir, "base")

	writeFile(t, dir, "docs/read me.go", "one\ntwo\nthree\nFOUR\nfive\nsix\nseven\neight\nnine\nten\n")
	writeFile(t, dir, "docs/ünïcode.go", "one\ntwo\nthree\nFOUR\nfive\nsix\nseven\neight\nnine\nten\n")

	ranges, err := ChangedLines(dir, "HEAD")
	if err != nil {
		t.Fatalf("ChangedLines: %v", err)
	}

	for _, path := range []string{"docs/read me.go", "docs/ünïcode.go"} {
		if !ranges.Contains(path, 4) {
			t.Errorf("%s: changed line 4 not reported, got keys %v", path, keys(ranges))
		}
	}
}

func TestChangedLinesRelativeToNestedRoot(t *testing.T) {
	dir := gitRepo(t)
	writeFile(t, dir, "app/main.go", tenLines)
	writeFile(t, dir, "other/main.go", tenLines)
	commitAll(t, dir, "base")

	writeFile(t, dir, "app/main.go", "one\ntwo\nthree\nFOUR\nfive\nsix\nseven\neight\nnine\nten\n")

	sub := filepath.Join(dir, "app")
	ranges, err := ChangedLines(sub, "HEAD")
	if err != nil {
		t.Fatalf("ChangedLines: %v", err)
	}

	if !ranges.Contains("main.go", 4) {
		t.Fatalf("paths must be relative to the scanned root, got %v", keys(ranges))
	}
	if ranges.Contains("other/main.go", 4) {
		t.Fatal("files outside the root must not be reported")
	}
}

func TestChangedLinesRejectsNonRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	dir := t.TempDir()
	if _, err := ChangedLines(dir, "HEAD"); err == nil {
		t.Skip("temporary directory is inside a git work tree")
	}

	_, err := ChangedLines(dir, "HEAD")
	if !errors.Is(err, ErrNotRepository) {
		t.Fatalf("expected ErrNotRepository, got %v", err)
	}
}

func TestFilterKeepsOnlyTouchedFindings(t *testing.T) {
	dir := gitRepo(t)
	writeFile(t, dir, "main.go", tenLines)
	commitAll(t, dir, "base")

	writeFile(t, dir, "main.go", "one\ntwo\nthree\nfour\nFIVE\nsix\nseven\neight\nnine\nten\n")

	ranges, err := ChangedLines(dir, "HEAD")
	if err != nil {
		t.Fatalf("ChangedLines: %v", err)
	}

	path := filepath.Join(dir, "main.go")
	result := &scanner.Result{
		Root: dir,
		Findings: []rules.Finding{
			{RuleID: "SEC-001", File: path, Line: 5, EndLine: 5},
			{RuleID: "SEC-001", File: path, Line: 1, EndLine: 1},
			{RuleID: "SEC-001", File: path, Line: 8, EndLine: 9},
		},
	}

	kept := ranges.Filter(result)
	if len(kept) != 1 || kept[0].Line != 5 {
		t.Fatalf("expected only the finding on the changed line, got %+v", kept)
	}
}

func TestFilterMatchesMultiLineSpans(t *testing.T) {
	dir := gitRepo(t)
	writeFile(t, dir, "main.go", "a\nb\nc\nd\ne\n")
	commitAll(t, dir, "base")

	writeFile(t, dir, "main.go", "a\nb\nc\nd\nE\nF\n")

	ranges, err := ChangedLines(dir, "HEAD")
	if err != nil {
		t.Fatalf("ChangedLines: %v", err)
	}

	result := &scanner.Result{
		Root: dir,
		Findings: []rules.Finding{
			{RuleID: "SEC-002", File: filepath.Join(dir, "main.go"), Line: 3, EndLine: 5},
			{RuleID: "SEC-002", File: filepath.Join(dir, "main.go"), Line: 1, EndLine: 3},
		},
	}

	kept := ranges.Filter(result)
	if len(kept) != 1 || kept[0].Line != 3 || kept[0].EndLine != 5 {
		t.Fatalf("a finding reaching into a changed hunk must be kept, got %+v", kept)
	}
}

func TestParseHunk(t *testing.T) {
	cases := []struct {
		header string
		span   Span
		ok     bool
	}{
		{"@@ -1,3 +4,2 @@", Span{Start: 4, End: 5}, true},
		{"@@ -7 +9 @@", Span{Start: 9, End: 9}, true},
		{"@@ -1,2 +0,0 @@", Span{}, false},
		{"@@ malformed @@", Span{}, false},
	}

	for _, c := range cases {
		span, ok := parseHunk(c.header)
		if ok != c.ok || span != c.span {
			t.Errorf("parseHunk(%q) = %v, %v; want %v, %v", c.header, span, ok, c.span, c.ok)
		}
	}
}

func TestMergeJoinsAdjacentSpansOnly(t *testing.T) {
	spans := merge([]Span{{Start: 5, End: 6}, {Start: 1, End: 2}, {Start: 3, End: 3}, {Start: 10, End: 12}, {Start: 13, End: 15}})

	want := []Span{{Start: 1, End: 3}, {Start: 5, End: 6}, {Start: 10, End: 15}}
	if len(spans) != len(want) {
		t.Fatalf("got %v, want %v", spans, want)
	}
	for i := range want {
		if spans[i] != want[i] {
			t.Fatalf("got %v, want %v", spans, want)
		}
	}
}

func keys(r Ranges) []string {
	out := make([]string, 0, len(r))
	for key := range r {
		out = append(out, key)
	}

	return out
}
