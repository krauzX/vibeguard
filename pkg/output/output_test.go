package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"
)

func sampleResult() *scanner.Result {
	return &scanner.Result{
		FilesScanned: 12,
		FilesSkipped: 3,
		FileErrors:   []scanner.FileError{{File: "big.js", Message: "file exceeds limit"}},
		Suppressed:   2,
		Duration:     1500 * time.Millisecond,
		Findings: []rules.Finding{
			{
				RuleID:    "SEC-010",
				Severity:  rules.SeverityCritical,
				File:      `pkg/odd,name "quoted".go`,
				Line:      7,
				Column:    3,
				EndLine:   7,
				EndColumn: 24,
				Message:   `Hardcoded <password> & token`,
				Code:      "password = \"a,b\" <tag>",
				Source:    "password = \"a,b\" <tag>",
				CWE:       "CWE-798",
			},
			{
				RuleID:   "QLT-001",
				Severity: rules.SeverityWarning,
				File:     "app.py",
				Line:     2,
				Column:   1,
				EndLine:  2,
				Message:  "Console statement",
				Code:     "print(1)",
				Source:   "print(1)",
			},
		},
	}
}

func tempFile(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

func TestJSONReportShape(t *testing.T) {
	path := tempFile(t, "report.json")
	if err := WriteJSON(sampleResult(), path, Options{}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}

	if report.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", report.SchemaVersion, SchemaVersion)
	}
	if report.Summary.TotalIssues != 2 || report.Summary.Critical != 1 {
		t.Fatalf("summary does not match findings: %+v", report.Summary)
	}
	if report.Summary.FilesFailed != 1 || len(report.Errors) != 1 {
		t.Fatalf("failed files were not reported: %+v", report.Summary)
	}
	if report.Errors[0].File != "big.js" || report.Errors[0].Message == "" {
		t.Fatalf("failed file detail is missing: %+v", report.Errors[0])
	}
	if report.Findings[0].File != `pkg/odd,name "quoted".go` {
		t.Fatalf("file path was altered: %q", report.Findings[0].File)
	}
	if report.Version == "" || report.Timestamp == "" {
		t.Fatal("version or timestamp missing")
	}

	finding := report.Findings[0]
	if finding.ID == "" || len(finding.ID) != 16 {
		t.Fatalf("finding id is not a content fingerprint: %q", finding.ID)
	}
	if finding.Fix == "" {
		t.Fatal("finding has no remediation text")
	}
	if finding.EndLine != 7 || finding.EndColumn != 24 {
		t.Fatalf("span was dropped: end=%d:%d", finding.EndLine, finding.EndColumn)
	}
	if report.Findings[1].EndColumn != 0 {
		t.Fatalf("unknown end column should be omitted, got %d", report.Findings[1].EndColumn)
	}
}

func TestJSONIdsSurviveLineShifts(t *testing.T) {
	before := sampleResult()
	after := sampleResult()
	after.Findings[0].Line = 70
	after.Findings[0].EndLine = 70

	first := NewJSONFinding(before, before.Findings[0])
	second := NewJSONFinding(after, after.Findings[0])
	if first.ID != second.ID {
		t.Fatalf("id changed when the line moved: %q != %q", first.ID, second.ID)
	}

	edited := sampleResult()
	edited.Findings[0].Source = `password = "different" <tag>`
	if NewJSONFinding(edited, edited.Findings[0]).ID == first.ID {
		t.Fatal("id did not change when the code changed")
	}
}

func TestJSONIsByteIdenticalWithoutTimestamp(t *testing.T) {
	first := tempFile(t, "first.json")
	second := tempFile(t, "second.json")

	if err := WriteJSON(sampleResult(), first, Options{NoTimestamp: true}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := WriteJSON(sampleResult(), second, Options{NoTimestamp: true}); err != nil {
		t.Fatal(err)
	}

	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two identical scans produced different reports")
	}

	var report JSONReport
	if err := json.Unmarshal(a, &report); err != nil {
		t.Fatal(err)
	}
	if report.Timestamp != "" || report.Summary.Duration != "" {
		t.Fatalf("volatile fields survived: timestamp=%q duration=%q", report.Timestamp, report.Summary.Duration)
	}
}

func TestSARIFIsValidAndVersioned(t *testing.T) {
	path := tempFile(t, "report.sarif")
	if err := WriteSARIF(sampleResult(), path, Options{ExitCode: 2}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name           string `json:"name"`
					InformationURI string `json:"informationUri"`
					Rules          []struct {
						ID      string `json:"id"`
						HelpURI string `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				Level               string            `json:"level"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Locations           []struct {
					PhysicalLocation struct {
						Region struct {
							StartLine int `json:"startLine"`
							EndLine   int `json:"endLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
				ExitCode            int  `json:"exitCode"`
				Notifications       []struct {
					Level string `json:"level"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("sarif is not valid JSON: %v", err)
	}

	if doc.Version != "2.1.0" {
		t.Fatalf("unexpected sarif version %q", doc.Version)
	}
	if len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "vibeguard" {
		t.Fatalf("unexpected driver metadata: %+v", doc.Runs)
	}
	if doc.Runs[0].Tool.Driver.InformationURI == "" {
		t.Fatal("informationUri is empty")
	}
	if len(doc.Runs[0].Results) != 2 || doc.Runs[0].Results[0].Level != "error" {
		t.Fatalf("unexpected results: %+v", doc.Runs[0].Results)
	}

	invocation := doc.Runs[0].Invocations[0]
	if invocation.ExecutionSuccessful {
		t.Fatal("a partial scan was reported as successful")
	}
	if invocation.ExitCode != 2 {
		t.Fatalf("exitCode = %d, want 2", invocation.ExitCode)
	}
	if len(invocation.Notifications) != 1 || invocation.Notifications[0].Level != "error" {
		t.Fatalf("unreadable file was not reported: %+v", invocation.Notifications)
	}

	result := doc.Runs[0].Results[0]
	if result.PartialFingerprints[sarifFingerprintKey] == "" {
		t.Fatalf("missing partial fingerprint: %+v", result)
	}
	if result.Locations[0].PhysicalLocation.Region.EndLine != 7 {
		t.Fatalf("endLine was not carried: %+v", result.Locations[0])
	}

	uriSeen := regexp.MustCompile(`definitions/\.html`)
	if uriSeen.Match(data) {
		t.Fatal("rule without a CWE produced a broken helpUri")
	}
	for _, rule := range doc.Runs[0].Tool.Driver.Rules {
		if rule.ID == "QLT-001" && rule.HelpURI != "" {
			t.Fatalf("QLT-001 has no CWE but helpUri = %q", rule.HelpURI)
		}
		if rule.ID == "SEC-010" && !strings.Contains(rule.HelpURI, "798") {
			t.Fatalf("SEC-010 helpUri = %q", rule.HelpURI)
		}
	}
}

func TestSARIFMarksCleanRunSuccessful(t *testing.T) {
	path := tempFile(t, "clean.sarif")
	result := sampleResult()
	result.FileErrors = nil

	if err := WriteSARIF(result, path, Options{}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("a complete scan was reported as failed")
	}
}

func TestCSVRoundTripsHostileFields(t *testing.T) {
	path := tempFile(t, "report.csv")
	if err := WriteCSV(sampleResult(), path); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("csv does not parse: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected a header and two rows, got %d", len(rows))
	}

	joined := strings.Join(rows[1], "|")
	if !strings.Contains(joined, `a,b`) {
		t.Fatalf("comma inside a field was not quoted: %q", joined)
	}
}

func TestJUnitMatchesFindingCount(t *testing.T) {
	path := tempFile(t, "report.xml")
	if err := WriteJUnit(sampleResult(), path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var suites struct {
		Tests    int `xml:"tests,attr"`
		Failures int `xml:"failures,attr"`
		Errors   int `xml:"errors,attr"`
		Suites   []struct {
			Time  string `xml:"time,attr"`
			Cases []struct {
				Name string `xml:"name,attr"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(data, &suites); err != nil {
		t.Fatalf("junit is not valid XML: %v", err)
	}

	cases := 0
	for _, s := range suites.Suites {
		cases += len(s.Cases)
		if s.Time == "" {
			t.Errorf("suite %q has no time attribute", s.Cases)
		}
	}

	if suites.Tests != 2 || suites.Failures != 1 || suites.Errors != 1 || cases != 2 {
		t.Fatalf("junit totals disagree with findings: tests=%d failures=%d errors=%d cases=%d",
			suites.Tests, suites.Failures, suites.Errors, cases)
	}
}

func TestHTMLEscapesFindingText(t *testing.T) {
	path := tempFile(t, "report.html")
	if err := WriteHTML(sampleResult(), path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	body := string(data)
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatal("report is not an html document")
	}
	if strings.Contains(body, "<password>") {
		t.Fatal("finding text was not escaped")
	}
	if !strings.Contains(body, "&lt;password&gt;") {
		t.Fatal("escaped finding text is missing")
	}
}

func TestTerminalReportSummarisesFailures(t *testing.T) {
	out := FormatTerminal(sampleResult(), true)

	for _, want := range []string{"Files scanned: 12", "Files failed:", "big.js", "Suppressed:", "1 critical finding(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal report is missing %q", want)
		}
	}
}

func TestTerminalDoesNotClaimCleanOnPartialScan(t *testing.T) {
	result := sampleResult()
	result.Findings = nil

	out := FormatTerminal(result, true)
	if strings.Contains(out, "No issues found") {
		t.Fatalf("a partial scan claimed to be clean:\n%s", out)
	}
	if !strings.Contains(out, "Incomplete") {
		t.Fatalf("partial scan was not called out:\n%s", out)
	}
}

func TestFormatsCoverEveryWriter(t *testing.T) {
	known := map[string]bool{
		"terminal": true, "json": true, "sarif": true, "html": true,
		"markdown": true, "junit": true, "csv": true, "github": true,
	}
	for _, format := range Formats() {
		if !known[format] {
			t.Fatalf("format %q has no writer in the test list", format)
		}
		delete(known, format)
	}
	if len(known) > 0 {
		t.Fatalf("writers are not advertised: %v", known)
	}
	if IsValidFormat("nope") || !IsValidFormat("json") {
		t.Fatal("IsValidFormat disagrees with Formats")
	}
}
