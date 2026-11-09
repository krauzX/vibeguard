package supply

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseGoMod(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", `module example.com/app

go 1.22

require github.com/gorilla/mux v1.8.0

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	golang.org/x/crypto v0.15.0
)
`)

	deps := ParseManifests(root)
	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d: %v", len(deps), deps)
	}

	byName := map[string]Dependency{}
	for _, dep := range deps {
		byName[dep.Name] = dep
	}

	if got := byName["github.com/dgrijalva/jwt-go"]; got.Version != "3.2.0" || got.Ecosystem != "Go" || got.Line == 0 {
		t.Errorf("jwt-go parsed as %+v", got)
	}
	if _, ok := byName["golang.org/x/crypto"]; !ok {
		t.Error("missing golang.org/x/crypto")
	}
	if _, ok := byName["github.com/gorilla/mux"]; !ok {
		t.Error("missing single-line require")
	}
}

func TestParseLockfileWinsOverRanges(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"dependencies": {"lodash": "^4.17.0"}}`)
	write(t, root, "package-lock.json", `{"lockfileVersion": 3, "packages": {
		"": {"name": "app"},
		"node_modules/lodash": {"version": "4.17.20"}
	}}`)

	deps := ParseManifests(root)
	if len(deps) != 1 || deps[0].Version != "4.17.20" {
		t.Fatalf("expected exact lockfile version, got %+v", deps)
	}
	if deps[0].Line == 0 {
		t.Error("expected a line number for the lockfile entry")
	}
}

func TestParsePackageJSONSkipsRanges(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"dependencies": {"axios": "^1.6.0", "left-pad": "1.3.0"}}`)

	deps := ParseManifests(root)
	if len(deps) != 1 || deps[0].Name != "left-pad" {
		t.Fatalf("expected only the pinned dependency, got %+v", deps)
	}
}

func TestParseRequirements(t *testing.T) {
	root := t.TempDir()
	write(t, root, "requirements.txt", `# comment
requests==2.31.0
flask>=2.3.0
django==4.2.4 ; python_version > "3.8"
`)

	deps := ParseManifests(root)
	if len(deps) != 2 {
		t.Fatalf("expected 2 pinned dependencies, got %d: %v", len(deps), deps)
	}
	for _, dep := range deps {
		if dep.Ecosystem != "PyPI" || dep.Version == "" {
			t.Errorf("unexpected dependency %+v", dep)
		}
	}
}

func TestCheckReportsOSVAdvisory(t *testing.T) {
	var queries int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var body struct {
				Queries []osvQuery `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			queries = len(body.Queries)
			json.NewEncoder(w).Encode(map[string]any{
				"results": []any{
					map[string]any{"vulns": []any{map[string]any{"id": "GHSA-test-1234"}}},
					map[string]any{},
				},
			})
		case "/v1/vulns/GHSA-test-1234":
			json.NewEncoder(w).Encode(map[string]any{
				"id":      "GHSA-test-1234",
				"summary": "Test advisory",
				"aliases": []string{"CVE-2024-0001"},
				"affected": []any{map[string]any{
					"ranges": []any{map[string]any{
						"events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": "3.2.1"}},
					}},
				}},
			})
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	root := t.TempDir()
	write(t, root, "go.mod", `module example.com/app

go 1.22

require (
	github.com/bad/pkg v3.2.0
	github.com/good/pkg v1.0.0
)
`)

	client := &Client{HTTP: server.Client(), BaseURL: server.URL, Cache: filepath.Join(t.TempDir(), "osv.json")}
	findings, deps, err := Check(context.Background(), root, client)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if deps != 2 || queries != 2 {
		t.Fatalf("expected 2 dependencies queried, got deps=%d queries=%d", deps, queries)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.RuleID != RuleVulnerableDependency || finding.Line == 0 {
		t.Errorf("unexpected finding %+v", finding)
	}
	for _, want := range []string{"CVE-2024-0001", "Test advisory", "fixed in 3.2.1"} {
		if !strings.Contains(finding.Message, want) {
			t.Errorf("message %q missing %q", finding.Message, want)
		}
	}
}

func TestCheckWithoutManifestsMakesNoRequest(t *testing.T) {
	client := &Client{HTTP: http.DefaultClient, BaseURL: "http://127.0.0.1:1"}
	findings, deps, err := Check(context.Background(), t.TempDir(), client)
	if err != nil || deps != 0 || len(findings) != 0 {
		t.Fatalf("expected a quiet result, got findings=%d deps=%d err=%v", len(findings), deps, err)
	}
}

func TestCheckReportsUnreachableDatabase(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module example.com/app\n\ngo 1.22\n\nrequire github.com/bad/pkg v1.0.0\n")

	client := &Client{HTTP: &http.Client{Timeout: time.Second}, BaseURL: "http://127.0.0.1:1"}
	findings, deps, err := Check(context.Background(), root, client)
	if err == nil {
		t.Fatal("expected an error from an unreachable database")
	}
	if deps != 1 || len(findings) != 0 {
		t.Errorf("expected the dependency counted and no findings, got deps=%d findings=%d", deps, len(findings))
	}
}

func write(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
