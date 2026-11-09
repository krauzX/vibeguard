package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"
)

const secretLine = "password = \"hunter2hunter2\"\n"

type finding struct {
	ID       string `json:"id"`
	RuleID   string `json:"rule_id"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	EndLine  int    `json:"end_line"`
	Fix      string `json:"fix"`
	Severity string `json:"severity"`
}

type report struct {
	SchemaVersion string `json:"schema_version"`
	Root          string `json:"root"`
	Summary       struct {
		TotalIssues int `json:"total_issues"`
	} `json:"summary"`
	Findings []finding `json:"findings"`
}

func runCLIStdin(t *testing.T, dir, stdin string, args ...string) (string, int) {
	t.Helper()

	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	out, _ := cmd.CombinedOutput()

	return string(out), cmd.ProcessState.ExitCode()
}

func runCLIStdout(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()

	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &bytes.Buffer{}
	_ = cmd.Run()

	return stdout.String(), cmd.ProcessState.ExitCode()
}

func decodeReport(t *testing.T, raw string) report {
	t.Helper()

	start := strings.Index(raw, "{")
	if start < 0 {
		t.Fatalf("no JSON in output:\n%s", raw)
	}

	var parsed report
	if err := json.NewDecoder(strings.NewReader(raw[start:])).Decode(&parsed); err != nil {
		t.Fatalf("invalid JSON (%v):\n%s", err, raw)
	}

	return parsed
}

func TestStdinScanStreamsJSONToStdout(t *testing.T) {
	dir := t.TempDir()

	out, code := runCLIStdin(t, dir, secretLine, "scan", "-", "--stdin-name", "app.py", "--format", "json", "--quiet")
	if code != 1 {
		t.Fatalf("expected exit 1 for a critical finding, got %d\n%s", code, out)
	}

	report := decodeReport(t, out)
	if report.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want 2", report.SchemaVersion)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding from stdin, got %d\n%s", len(report.Findings), out)
	}
	if report.Findings[0].File != "app.py" {
		t.Errorf("finding file = %q, want app.py", report.Findings[0].File)
	}
	if report.Findings[0].ID == "" {
		t.Error("stdin findings need a stable id")
	}
	if _, err := os.Stat(filepath.Join(dir, "vibeguard-report.json")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a piped scan must not leave a report file behind")
	}
}

func TestStdoutReportIsNotMixedWithTheHumanReport(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", secretLine)

	out, code := runCLIStdout(t, dir, "scan", ".", "--format", "json", "--output", "-")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out)
	}

	var parsed report
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("stdout is not pure JSON (%v):\n%s", err, out)
	}
	if parsed.Summary.TotalIssues != 1 {
		t.Errorf("total_issues = %d, want 1", parsed.Summary.TotalIssues)
	}
}

func TestPromptVerificationUsesTheVerifyCommand(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", secretLine)

	out, code := runCLI(t, dir, "prompt", "app.py", "--format", "generic")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}
	if !contains(out, "vibeguard verify app.py") {
		t.Errorf("prompt does not tell the reader to run verify:\n%s", out)
	}
	if contains(out, "--verify") {
		t.Errorf("prompt still uses a flag scan does not have:\n%s", out)
	}
}

func TestStdinScanWarnsAboutUnknownExtension(t *testing.T) {
	out, code := runCLIStdin(t, t.TempDir(), secretLine, "scan", "-", "--stdin-name", "notes.txt")

	if code != 1 {
		t.Fatalf("credential rules apply to every language, want exit 1, got %d\n%s", code, out)
	}
	if !contains(out, "no known extension") {
		t.Fatalf("expected a warning about the unknown extension, got:\n%s", out)
	}
}

func TestOutputDashWritesSelectedFormatToStdout(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", secretLine)

	out, code := runCLI(t, dir, "scan", ".", "--format", "sarif", "--output", "-", "--quiet")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out)
	}

	if !contains(out, `"version": "2.1.0"`) {
		t.Fatalf("expected SARIF 2.1.0 on stdout, got:\n%s", out)
	}
}

func TestNoTimestampIsByteReproducible(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	writeTemp(t, src, "app.py", secretLine)

	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")

	for _, path := range []string{first, second} {
		if out, code := runCLI(t, dir, "scan", "src", "--format", "json", "--no-timestamp", "--output", path, "--quiet"); code != 1 {
			t.Fatalf("scan failed: %d\n%s", code, out)
		}
	}

	one, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	two, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Fatal("--no-timestamp reports differ between identical scans")
	}
	if contains(string(one), `"timestamp"`) || contains(string(one), `"duration"`) {
		t.Fatal("--no-timestamp must omit timestamp and duration")
	}
}

func TestFailOnSelectsTheBreach(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", secretLine)

	cases := []struct {
		policy string
		code   int
	}{
		{"none", 0},
		{"any", 1},
		{"secret", 1},
		{"bogus", 2},
	}

	for _, c := range cases {
		out, code := runCLI(t, dir, "scan", ".", "--quiet", "--fail-on", c.policy)
		if code != c.code {
			t.Errorf("--fail-on %s: exit %d, want %d\n%s", c.policy, code, c.code, out)
		}
	}
}

func gitAvailable(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

func initRepo(t *testing.T, dir string) {
	t.Helper()

	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test"},
		{"config", "core.autocrlf", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func commitRepo(t *testing.T, dir string) {
	t.Helper()

	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestDiffModeReportsOnlyChangedLines(t *testing.T) {
	gitAvailable(t)

	dir := t.TempDir()
	initRepo(t, dir)

	writeTemp(t, dir, "app.py", "def load():\n    token = \"AKIAIOSFODNN7EXAMPLE\"\n    return token\n")
	commitRepo(t, dir)

	writeTemp(t, dir, "app.py", "def load():\n    token = \"AKIAIOSFODNN7EXAMPLE\"\n    return token\n\n\ndef save():\n    password = \"hunter2hunter2\"\n")

	out, code := runCLI(t, dir, "scan", ".", "--diff", "--format", "json", "--output", "-", "--quiet")
	if code != 1 {
		t.Fatalf("expected the new finding to fail the build, got %d\n%s", code, out)
	}

	report := decodeReport(t, out)
	if len(report.Findings) != 1 {
		t.Fatalf("diff mode must drop findings on untouched lines, got %d:\n%s", len(report.Findings), out)
	}
	if report.Findings[0].Line != 7 {
		t.Errorf("reported line %d, want the added line 7", report.Findings[0].Line)
	}
}

func TestDiffModeOutsideGitReportsEverything(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", secretLine)

	out, code := runCLI(t, dir, "scan", ".", "--diff", "--quiet", "--format", "json", "--output", "-")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out)
	}
	if !contains(out, "reporting the whole tree") {
		t.Fatalf("expected a fallback warning, got:\n%s", out)
	}

	if got := len(decodeReport(t, out).Findings); got != 1 {
		t.Fatalf("expected the full tree to be reported, got %d finding(s)", got)
	}
}

func TestVerifyJSONReportsRemainingFindings(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", secretLine)

	out, code := runCLI(t, dir, "verify", ".", "--json")
	if code != 1 {
		t.Fatalf("expected exit 1 when findings remain, got %d\n%s", code, out)
	}

	var parsed struct {
		SchemaVersion string    `json:"schema_version"`
		OK            bool      `json:"ok"`
		Remaining     []finding `json:"remaining"`
	}
	start := strings.Index(out, "{")
	if start < 0 {
		t.Fatalf("no JSON in verify output:\n%s", out)
	}
	if err := json.NewDecoder(strings.NewReader(out[start:])).Decode(&parsed); err != nil {
		t.Fatalf("invalid verify JSON: %v\n%s", err, out)
	}

	if parsed.OK {
		t.Error("ok must be false while findings remain")
	}
	if parsed.SchemaVersion != "2" || len(parsed.Remaining) != 1 {
		t.Fatalf("unexpected verify report: %+v", parsed)
	}
}

func TestVerifyJSONOnCleanTree(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", "def add(a, b):\n    return a + b\n")

	out, code := runCLI(t, dir, "verify", ".", "--json")
	if code != 0 {
		t.Fatalf("expected exit 0 for a clean tree, got %d\n%s", code, out)
	}
	if !contains(out, `"ok": true`) {
		t.Fatalf("expected ok true, got:\n%s", out)
	}
}

func TestBaselineAddAndRemoveByID(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", secretLine)
	writeTemp(t, dir, "vibeguard.yaml", "baseline:\n  enabled: true\n  path: .vibeguard-baseline.json\n")

	out, code := runCLI(t, dir, "scan", ".", "--format", "json", "--output", "-", "--quiet")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out)
	}

	id := decodeReport(t, out).Findings[0].ID
	if id == "" {
		t.Fatal("finding has no id to accept")
	}

	if out, code := runCLI(t, dir, "baseline", "add", "--id", id, "--reason", "rotated later"); code != 0 {
		t.Fatalf("baseline add --id failed: %d\n%s", code, out)
	}

	if out, code := runCLI(t, dir, "scan", ".", "--quiet"); code != 0 {
		t.Fatalf("accepted finding still fails the build: %d\n%s", code, out)
	}

	if out, code := runCLI(t, dir, "baseline", "remove", "--id", id); code != 0 {
		t.Fatalf("baseline remove --id failed: %d\n%s", code, out)
	}

	if out, code := runCLI(t, dir, "scan", ".", "--quiet"); code != 1 {
		t.Fatalf("finding did not return after removal: %d\n%s", code, out)
	}
}

func TestBaselineSurvivesLineShift(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "app.py", "import os\n\n"+secretLine)
	writeTemp(t, dir, "vibeguard.yaml", "baseline:\n  enabled: true\n  path: .vibeguard-baseline.json\n")

	out, code := runCLI(t, dir, "scan", ".", "--format", "json", "--output", "-", "--quiet")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out)
	}
	if out, code := runCLI(t, dir, "baseline", "add", "--id", decodeReport(t, out).Findings[0].ID, "--reason", "known"); code != 0 {
		t.Fatalf("baseline add failed: %d\n%s", code, out)
	}

	writeTemp(t, dir, "app.py", "import os\nimport sys\n\n"+secretLine)

	out, code = runCLI(t, dir, "scan", ".", "--no-color")
	if code != 0 {
		t.Fatalf("accepted finding came back after moving three lines: %d\n%s", code, out)
	}
	if !contains(out, "Suppressed:") {
		t.Fatalf("expected a suppression count, got:\n%s", out)
	}
}

func TestPartialScanIsAToolFailure(t *testing.T) {
	result := &scanner.Result{
		FileErrors: []scanner.FileError{{File: "locked.go", Message: "access is denied"}},
	}

	if code := exitCodeFor([]string{"none"}, result); code != 2 {
		t.Fatalf("a partial scan must exit 2, got %d", code)
	}
	if err := scanOutcome([]string{"none"}, result); err == nil {
		t.Fatal("a partial scan must report an error even when every policy is off")
	}
}

func TestExitCodeMatrix(t *testing.T) {
	critical := []rules.Finding{{RuleID: "SEC-001", Severity: rules.SeverityCritical}}
	info := []rules.Finding{{RuleID: "QUA-001", Severity: rules.SeverityInfo}}

	cases := []struct {
		name   string
		policy []string
		result *scanner.Result
		code   int
	}{
		{"clean", []string{"any"}, &scanner.Result{}, 0},
		{"critical breach", []string{"critical"}, &scanner.Result{Findings: critical}, 1},
		{"info counts for any", []string{"any"}, &scanner.Result{Findings: info}, 1},
		{"policy off", []string{"none"}, &scanner.Result{Findings: critical}, 0},
		{"partial scan wins", []string{"none"}, &scanner.Result{FileErrors: []scanner.FileError{{File: "locked.go"}}}, 2},
	}

	for _, c := range cases {
		if code := exitCodeFor(c.policy, c.result); code != c.code {
			t.Errorf("%s: exit %d, want %d", c.name, code, c.code)
		}
	}
}

func TestRulesLanguageFilterIsExact(t *testing.T) {
	out, code := runCLI(t, t.TempDir(), "rules", "java")
	if code != 0 {
		t.Fatalf("rules java exited %d:\n%s", code, out)
	}
	if strings.Contains(out, "PAT-001") || strings.Contains(out, "PAT-005") {
		t.Error("java filter listed javascript-only rules")
	}
	if !strings.Contains(out, "PAT-006") || !strings.Contains(out, "PAT-007") {
		t.Error("java filter dropped a java rule")
	}
}

func TestBaselineRejectsPositionalArguments(t *testing.T) {
	if out, code := runCLI(t, t.TempDir(), "baseline", "add", "SEC-001", "app.py", "3"); code != 2 {
		t.Fatalf("positional baseline add exited %d, want 2:\n%s", code, out)
	}
	if out, code := runCLI(t, t.TempDir(), "baseline", "remove", "SEC-001"); code != 2 {
		t.Fatalf("positional baseline remove exited %d, want 2:\n%s", code, out)
	}
}

func TestFixGuideHonoursNoTimestamp(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "src/app.py", secretLine)

	first, code := runCLI(t, dir, "fix", "src", "--no-timestamp", "--offline")
	if code != 0 {
		t.Fatalf("fix exited %d:\n%s", code, first)
	}
	if strings.Contains(first, "Generated:") {
		t.Error("no-timestamp guide still carried a generated stamp")
	}

	second, _ := runCLI(t, dir, "fix", "src", "--no-timestamp", "--offline")
	if first != second {
		t.Error("fix guide is not reproducible with --no-timestamp")
	}
}

func TestSBOMIsReproducible(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "go.mod", "module example.com/app\n\ngo 1.22\n\nrequire github.com/spf13/cobra v1.10.2\n")

	first, code := runCLI(t, dir, "sbom", ".", "--no-timestamp")
	if code != 0 {
		t.Fatalf("sbom exited %d:\n%s", code, first)
	}
	second, _ := runCLI(t, dir, "sbom", ".", "--no-timestamp")
	if first != second {
		t.Error("sbom is not reproducible with --no-timestamp")
	}
	if !strings.Contains(first, `"serialNumber"`) || !strings.Contains(first, "github.com/spf13/cobra") {
		t.Errorf("unexpected sbom document:\n%s", first)
	}
}

func TestCustomRuleFixReachesReports(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, ".vibeguard/rules/custom.json", `[{"id":"CUS-001","name":"Custom secret","pattern":"SECRET_[A-Z]{6}","severity":"CRITICAL","fix":"Read it from the environment","enabled":true}]`)
	writeTemp(t, dir, "app.py", "token = \"SECRET_ABCDEF\"\n")

	out, code := runCLI(t, dir, "scan", ".", "--format", "json", "--output", "-", "--quiet", "--offline")
	if code != 1 {
		t.Fatalf("scan exited %d, want a policy breach:\n%s", code, out)
	}

	parsed := decodeReport(t, out)
	var custom *finding
	for i := range parsed.Findings {
		if parsed.Findings[i].RuleID == "CUS-001" {
			custom = &parsed.Findings[i]
		}
	}
	if custom == nil {
		t.Fatalf("custom rule did not report:\n%s", out)
	}
	if custom.Fix != "Read it from the environment" {
		t.Errorf("custom fix text was lost: %q", custom.Fix)
	}
}

func TestBaselineAcceptsFindingsFromAReportedSubdirectory(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "vibeguard.yaml", "baseline:\n  enabled: true\n  path: .vibeguard-baseline.json\n")
	writeTemp(t, dir, "sub/app.py", secretLine)

	out, code := runCLI(t, dir, "scan", "sub", "--format", "json", "--output", "-", "--quiet")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out)
	}

	id := decodeReport(t, out).Findings[0].ID
	if out, code := runCLI(t, dir, "baseline", "add", "--id", id, "--reason", "known"); code != 0 {
		t.Fatalf("baseline add failed: %d\n%s", code, out)
	}

	out, code = runCLI(t, dir, "scan", "sub", "--format", "json", "--output", "-", "--quiet")
	if code != 0 {
		t.Fatalf("accepted finding still fails a subdirectory scan: %d\n%s", code, out)
	}
	if total := decodeReport(t, out).Summary.TotalIssues; total != 0 {
		t.Errorf("total_issues = %d, want 0", total)
	}
}
