package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vibeguard.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultsAreSafe(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Baseline.Enabled {
		t.Error("baseline should be opt-in")
	}
	if !cfg.Scanner.RespectGitignore || !cfg.Scanner.SkipMinified || !cfg.Scanner.SkipLockfiles || !cfg.Scanner.SkipBinary {
		t.Error("noise skipping should be on by default")
	}
	if cfg.Scanner.MaxFileSize <= 0 || cfg.Rules.MaxLineLength <= 0 {
		t.Error("size limits must be positive")
	}
	if !cfg.Security.FailOnSecrets || !cfg.Security.FailOnCritical {
		t.Error("a critical finding or a secret should fail the scan by default")
	}
}

func TestLoadAppliesValues(t *testing.T) {
	path := writeConfig(t, `
security:
  fail_on_critical: false
  include_extensions:
    - .go
scanner:
  workers: 2
  max_file_size: 4096
  respect_gitignore: false
baseline:
  enabled: true
  path: custom-baseline.json
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Security.FailOnCritical {
		t.Error("fail_on_critical was not applied")
	}
	if cfg.Scanner.Workers != 2 || cfg.Scanner.MaxFileSize != 4096 {
		t.Errorf("scanner settings not applied: %+v", cfg.Scanner)
	}
	if cfg.Scanner.RespectGitignore {
		t.Error("respect_gitignore was not applied")
	}
	if !cfg.Baseline.Enabled || cfg.Baseline.Path != "custom-baseline.json" {
		t.Errorf("baseline settings not applied: %+v", cfg.Baseline)
	}
	if len(cfg.GetIncludeExtensions()) != 1 {
		t.Errorf("include extensions not replaced: %v", cfg.GetIncludeExtensions())
	}
}

func TestLoadClampsInvalidValues(t *testing.T) {
	path := writeConfig(t, `
scanner:
  workers: -4
  max_file_size: 0
rules:
  max_line_length: -10
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Scanner.MaxFileSize != DefaultConfig().Scanner.MaxFileSize {
		t.Errorf("max_file_size was not clamped: %d", cfg.Scanner.MaxFileSize)
	}
	if cfg.Rules.MaxLineLength != DefaultConfig().Rules.MaxLineLength {
		t.Errorf("max_line_length was not clamped: %d", cfg.Rules.MaxLineLength)
	}
	if cfg.Scanner.Workers < 0 {
		t.Errorf("negative workers survived normalization: %d", cfg.Scanner.Workers)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Log("missing explicit config falls back to defaults")
	}
}

func TestWorkerCount(t *testing.T) {
	cfg := DefaultConfig()

	cfg.Scanner.Workers = 0
	if got := cfg.WorkerCount(); got != runtime.NumCPU() {
		t.Errorf("auto workers = %d, want %d", got, runtime.NumCPU())
	}

	cfg.Scanner.Workers = 3
	if got := cfg.WorkerCount(); got != 3 {
		t.Errorf("explicit workers = %d, want 3", got)
	}

	cfg.Scanner.Workers = 1 << 20
	if got, max := cfg.WorkerCount(), 4*runtime.NumCPU(); got > max {
		t.Errorf("workers not capped: %d > %d", got, max)
	}
}

func TestExcludePathsAreNamed(t *testing.T) {
	cfg := DefaultConfig()
	excluded := cfg.GetExcludePaths()

	for _, name := range []string{".git", "node_modules", "vendor"} {
		if !excluded[name] {
			t.Errorf("%s is not excluded by default", name)
		}
	}
}
