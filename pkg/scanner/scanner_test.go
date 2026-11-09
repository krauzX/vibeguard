package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/config"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func scanDir(t *testing.T, dir string, mutate func(*config.Config)) *Result {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Dependencies.CheckVulnerabilities = false
	if mutate != nil {
		mutate(cfg)
	}
	result, err := New(cfg).Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestScanOrderIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 20; i++ {
		writeFile(t, dir, filepath.Join("pkg", string(rune('a'+i))+".py"), "import subprocess\nsubprocess.call(cmd, shell=True)\n")
	}

	first := scanDir(t, dir, nil)
	for run := 0; run < 5; run++ {
		again := scanDir(t, dir, nil)
		if len(again.Findings) != len(first.Findings) {
			t.Fatalf("finding count changed between runs: %d vs %d", len(first.Findings), len(again.Findings))
		}
		for i := range first.Findings {
			if first.Findings[i] != again.Findings[i] {
				t.Fatalf("finding %d differs between runs:\n%+v\n%+v", i, first.Findings[i], again.Findings[i])
			}
		}
	}
}

func TestWorkerCountDoesNotChangeFindings(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 40; i++ {
		body := "password = \"hunter2hunter2\"\nimport subprocess\nsubprocess.call(cmd, shell=True)\n"
		writeFile(t, dir, filepath.Join("pkg", fmt.Sprintf("f%02d.py", i)), body)
	}

	single := scanDir(t, dir, func(cfg *config.Config) { cfg.Scanner.Workers = 1 })
	parallel := scanDir(t, dir, func(cfg *config.Config) { cfg.Scanner.Workers = 8 })

	if len(single.Findings) == 0 {
		t.Fatal("fixture produced no findings")
	}
	if len(parallel.Findings) != len(single.Findings) {
		t.Fatalf("finding count changed with workers: %d vs %d", len(single.Findings), len(parallel.Findings))
	}
	for i := range single.Findings {
		if single.Findings[i] != parallel.Findings[i] {
			t.Fatalf("finding %d differs:\n%+v\n%+v", i, single.Findings[i], parallel.Findings[i])
		}
	}
}

func TestLongLinesAreMatchedInFull(t *testing.T) {
	dir := t.TempDir()
	key := "AKIA" + "IOSFODNN7EXAMPLE"
	writeFile(t, dir, "minified.js", "const pad=\""+strings.Repeat("x", 4000)+"\"; const k=\""+key+"\";\n")

	result := scanDir(t, dir, func(cfg *config.Config) { cfg.Rules.MaxLineLength = 40 })
	if len(result.Findings) == 0 {
		t.Fatal("secret at end of a long line was not detected")
	}
	if len(result.Findings[0].Code) > 64 {
		t.Fatalf("reported snippet not truncated: %d bytes", len(result.Findings[0].Code))
	}
}

func TestEnvFileRuleIsScopedAndReportedOnce(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "prod.env", "AWS_SECRET_ACCESS_KEY=abc\nDB_PASSWORD=root\nAPI_TOKEN=xyz\n")
	writeFile(t, dir, "app.py", "AWS_SECRET_ACCESS_KEY=abc\nDB_PASSWORD=root\n")

	result := scanDir(t, dir, nil)

	counts := map[string]int{}
	for _, f := range result.Findings {
		if f.RuleID == "FILE-001" {
			counts[filepath.Base(f.File)]++
		}
	}

	if counts["prod.env"] != 1 {
		t.Fatalf("expected one FILE-001 for prod.env, got %d", counts["prod.env"])
	}
	if counts["app.py"] != 0 {
		t.Fatalf("FILE-001 leaked into a non-env file")
	}
}

func TestOversizedFilesAreCountedAsFailures(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "big.py", "password = \"hunter2secret\"\n"+strings.Repeat("#", 2048))
	writeFile(t, dir, "small.py", "password = \"hunter2secret\"\n")

	result := scanDir(t, dir, func(cfg *config.Config) { cfg.Scanner.MaxFileSize = 1024 })

	if result.ErrorCount() != 1 {
		t.Fatalf("expected 1 failed file, got %d", result.ErrorCount())
	}
	if len(result.FileErrors) != 1 {
		t.Fatalf("expected the failure to be reported, got %v", result.FileErrors)
	}
	if result.FilesScanned != 1 {
		t.Fatalf("expected 1 successfully scanned file, got %d", result.FilesScanned)
	}
}
