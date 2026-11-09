package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func writeIgnore(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRootPatterns(t *testing.T) {
	dir := t.TempDir()
	writeIgnore(t, dir, ".gitignore", "node_modules/\n*.log\n/dist\nbuild/**\n!keep.log\n")

	m := New(dir)
	cases := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"node_modules", true, true},
		{"node_modules", false, false},
		{"a/b/node_modules", true, true},
		{"deep/a/error.log", false, true},
		{"a/keep.log", false, false},
		{"dist", true, true},
		{"a/dist", true, false},
		{"build", true, false},
		{"build/out/x.js", false, true},
		{"src/main.go", false, false},
	}

	for _, c := range cases {
		if got := m.Match(c.path, c.isDir); got != c.want {
			t.Errorf("Match(%q, isDir=%v) = %v, want %v", c.path, c.isDir, got, c.want)
		}
	}
}

func TestNestedFileIsScopedToItsDirectory(t *testing.T) {
	dir := t.TempDir()
	writeIgnore(t, dir, ".gitignore", "*.tmp\n")
	writeIgnore(t, dir, "svc/.gitignore", "generated/\n!keep.tmp\n")

	m := New(dir)
	m.Load("svc")

	if !m.Match("other/file.tmp", false) {
		t.Error("root pattern stopped applying")
	}
	if !m.Match("svc/generated", true) {
		t.Error("nested directory pattern not applied")
	}
	if !m.Match("svc/a.tmp", false) {
		t.Error("nested negation did not re-include")
	}
	if m.Match("other/generated", true) {
		t.Error("nested pattern leaked outside its directory")
	}
}

func TestMalformedAndEmptyPatterns(t *testing.T) {
	dir := t.TempDir()
	writeIgnore(t, dir, ".gitignore", "# comment\n\n[\n\\#literal\n")

	m := New(dir)
	if len(m.patterns) != 2 {
		t.Fatalf("expected the literal patterns to survive, got %d", len(m.patterns))
	}
	if !m.Match("[", false) {
		t.Error("unbalanced bracket should be matched literally")
	}
	if !m.Match("#literal", false) {
		t.Error("escaped hash should match literally")
	}
}

func TestMissingIgnoreFile(t *testing.T) {
	m := New(t.TempDir())
	if m.Match("anything", false) {
		t.Fatal("empty matcher ignored a path")
	}
}
