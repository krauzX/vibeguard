package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "vibeguard-cli")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	binaryPath = filepath.Join(dir, "vibeguard")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}

	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s\n", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func runCLI(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
	out, _ := cmd.CombinedOutput()
	return string(out), cmd.ProcessState.ExitCode()
}

func writeTemp(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCriticalFindingFailsTheBuild(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", "password = \"hunter2hunter2\"\n")

	out, code := runCLI(t, dir, "scan", ".", "--no-color")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out)
	}
}

func TestCleanTreePasses(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", "def add(a, b):\n    return a + b\n")

	out, code := runCLI(t, dir, "scan", ".", "--no-color")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}
}

func TestIgnoredFileDoesNotFailTheBuild(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, ".gitignore", "secrets/\n")
	writeTemp(t, dir, "secrets/prod.py", "password = \"hunter2hunter2\"\n")

	if out, code := runCLI(t, dir, "scan", ".", "--no-color"); code != 0 {
		t.Fatalf("ignored file failed the scan: %d\n%s", code, out)
	}
}

func TestUnknownFormatIsAToolFailure(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", "print(1)\n")

	out, code := runCLI(t, dir, "scan", ".", "--format", "nope")
	if code != 2 {
		t.Fatalf("expected exit 2 for a usage error, got %d\n%s", code, out)
	}
	if !contains(out, "unsupported output format") {
		t.Fatalf("expected a format error, got:\n%s", out)
	}
}

func TestMissingPathIsAToolFailure(t *testing.T) {
	out, code := runCLI(t, t.TempDir(), "scan", "does-not-exist")
	if code != 2 {
		t.Fatalf("expected exit 2 for a missing path, got %d\n%s", code, out)
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
