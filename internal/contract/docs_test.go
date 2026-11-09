package contract

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/config"
	"github.com/KrauzX/vibeguard/pkg/output"
)

func readRepoFile(t *testing.T, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(repoRoot, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	return string(data)
}

// TestReadmeDocumentsEveryFormat keeps the readme and formats in sync.
func TestReadmeDocumentsEveryFormat(t *testing.T) {
	readme := readRepoFile(t, "README.md")

	for _, format := range output.Formats() {
		documented := strings.Contains(readme, "--format "+format) ||
			strings.Contains(readme, "--"+format) ||
			strings.Contains(readme, "`"+format+"`")
		if !documented {
			t.Errorf("README does not document the %q format", format)
		}
	}
}

// TestReadmeDocumentsExitCodes pins the three documented outcomes.
func TestReadmeDocumentsExitCodes(t *testing.T) {
	readme := readRepoFile(t, "README.md")

	for _, row := range []string{"| `0` |", "| `1` |", "| `2` |"} {
		if !strings.Contains(readme, row) {
			t.Errorf("README exit code table is missing %s", row)
		}
	}
}

// TestSampleConfigIsComplete requires vibeguard.yaml to name every setting.
func TestSampleConfigIsComplete(t *testing.T) {
	sample := readRepoFile(t, "vibeguard.yaml")

	for _, key := range configKeys(t) {
		line := regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(key) + `:`)
		if !line.MatchString(sample) {
			t.Errorf("vibeguard.yaml does not document the %q setting", key)
		}
	}
}

// TestSampleConfigLoads proves the shipped file parses and keeps safe defaults.
func TestSampleConfigLoads(t *testing.T) {
	path, err := filepath.Abs(filepath.Join(repoRoot, "vibeguard.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("vibeguard.yaml does not load: %v", err)
	}

	if !cfg.Security.FailOnCritical || !cfg.Security.FailOnSecrets {
		t.Error("sample config must keep both default failure policies enabled")
	}
	if cfg.Dependencies.Offline {
		t.Error("sample config must not disable network lookups by default")
	}
	if cfg.Dependencies.Timeout <= 0 {
		t.Error("sample config must set a positive advisory timeout")
	}
}

func configKeys(t *testing.T) []string {
	t.Helper()

	var keys []string
	seen := make(map[reflect.Type]bool)

	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		if seen[typ] {
			return
		}
		seen[typ] = true

		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.Type.Kind() == reflect.Struct {
				walk(field.Type)
				continue
			}

			key := strings.Split(field.Tag.Get("mapstructure"), ",")[0]
			if key == "" || key == "-" {
				continue
			}
			keys = append(keys, key)
		}
	}

	walk(reflect.TypeOf(*config.DefaultConfig()))

	return keys
}
