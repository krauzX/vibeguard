package scanner

import (
	"path/filepath"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/config"
)

const secretLine = "password = \"hunter2hunter2\"\n"

func filesWithFindings(result *Result) map[string]bool {
	seen := make(map[string]bool)
	for _, f := range result.Findings {
		seen[filepath.Base(f.File)] = true
	}
	return seen
}

func TestGitignoreExcludesFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".gitignore", "generated/\n*.snap\n")
	writeFile(t, dir, "generated/out.py", secretLine)
	writeFile(t, dir, "build/api.snap", secretLine)
	writeFile(t, dir, "app.py", secretLine)

	result := scanDir(t, dir, nil)
	seen := filesWithFindings(result)

	if !seen["app.py"] {
		t.Fatal("tracked file was not scanned")
	}
	if seen["out.py"] || seen["api.snap"] {
		t.Fatalf("ignored files were scanned: %v", seen)
	}
	if result.FilesSkipped < 2 {
		t.Fatalf("ignored files were not counted, skipped=%d", result.FilesSkipped)
	}
}

func TestGitignoreCanBeTurnedOff(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".gitignore", "generated/\n")
	writeFile(t, dir, "generated/out.py", secretLine)

	result := scanDir(t, dir, func(cfg *config.Config) { cfg.Scanner.RespectGitignore = false })
	if !filesWithFindings(result)["out.py"] {
		t.Fatal("ignored file was skipped even though respect_gitignore is off")
	}
}

func TestMinifiedAndLockfilesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.min.js", "const x=1;"+secretLine)
	writeFile(t, dir, "package-lock.json", "{"+secretLine+"}")
	writeFile(t, dir, "app.js", secretLine)

	result := scanDir(t, dir, nil)
	seen := filesWithFindings(result)

	if !seen["app.js"] {
		t.Fatal("normal source file was not scanned")
	}
	if seen["bundle.min.js"] || seen["package-lock.json"] {
		t.Fatalf("generated files were scanned: %v", seen)
	}
}

func TestNoiseSkippingCanBeTurnedOff(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.min.js", "const x=1;"+secretLine)

	result := scanDir(t, dir, func(cfg *config.Config) {
		cfg.Scanner.SkipMinified = false
		cfg.Scanner.SkipLockfiles = false
	})
	if !filesWithFindings(result)["bundle.min.js"] {
		t.Fatal("minified file was skipped even though skip_minified is off")
	}
}

func TestNestedGitignore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "svc/.gitignore", "fixtures/\n")
	writeFile(t, dir, "svc/fixtures/fake.py", secretLine)
	writeFile(t, dir, "svc/real.py", secretLine)

	result := scanDir(t, dir, nil)
	seen := filesWithFindings(result)

	if !seen["real.py"] {
		t.Fatal("nested directory scan lost the real file")
	}
	if seen["fake.py"] {
		t.Fatal("nested ignore rule was not applied")
	}
}
