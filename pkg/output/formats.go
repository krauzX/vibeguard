package output

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strconv"

	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"
)

// Formats lists every output format the CLI accepts, in discovery order.
func Formats() []string {
	return []string{"terminal", "json", "sarif", "html", "markdown", "junit", "csv", "github"}
}

// IsValidFormat reports whether name is a supported output format.
func IsValidFormat(name string) bool {
	for _, format := range Formats() {
		if format == name {
			return true
		}
	}

	return false
}

type JUnitReport struct {
	XMLName    xml.Name     `xml:"testsuites"`
	Name       string       `xml:"name,attr"`
	Tests      int          `xml:"tests,attr"`
	Failures   int          `xml:"failures,attr"`
	Errors     int          `xml:"errors,attr"`
	Skipped    int          `xml:"skipped,attr"`
	Time       string       `xml:"time,attr"`
	TestSuites []JUnitSuite `xml:"testsuite"`
}

type JUnitSuite struct {
	Name      string      `xml:"name,attr"`
	Tests     int         `xml:"tests,attr"`
	Failures  int         `xml:"failures,attr"`
	Errors    int         `xml:"errors,attr"`
	Skipped   int         `xml:"skipped,attr"`
	Time      string      `xml:"time,attr"`
	TestCases []JUnitCase `xml:"testcase"`
}

type JUnitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
	Error     *JUnitError   `xml:"error,omitempty"`
}

type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

type JUnitError struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

func WriteJUnit(result *scanner.Result, outputPath string) error {
	report := JUnitReport{
		Name:     "vibeguard",
		Tests:    len(result.Findings),
		Failures: result.WarningCount(),
		Errors:   result.CriticalCount(),
		Skipped:  result.InfoCount(),
		Time:     result.Duration.String(),
	}

	suitesByFile := make(map[string][]rules.Finding)
	for _, f := range result.Findings {
		suitesByFile[f.File] = append(suitesByFile[f.File], f)
	}

	for file, findings := range suitesByFile {
		suite := JUnitSuite{
			Name: file,
			Time: "0s",
		}

		for _, f := range findings {
			tc := JUnitCase{
				Name:      fmt.Sprintf("[%s] %s", f.RuleID, f.Message),
				Classname: file,
				Time:      "0s",
			}

			detail := fmt.Sprintf("File: %s\nLine: %d\nRule: %s\nCWE: %s\nCode: %s",
				f.File, f.Line, f.RuleID, f.CWE, f.Code)

			switch f.Severity {
			case rules.SeverityCritical:
				tc.Error = &JUnitError{
					Message: f.Message,
					Type:    "security-vulnerability",
					Content: detail,
				}
				suite.Errors++
			case rules.SeverityWarning:
				tc.Failure = &JUnitFailure{
					Message: f.Message,
					Type:    "security-warning",
					Content: detail,
				}
				suite.Failures++
			default:
				tc.Failure = &JUnitFailure{
					Message: f.Message,
					Type:    "code-quality",
					Content: detail,
				}
				suite.Skipped++
			}

			suite.TestCases = append(suite.TestCases, tc)
			suite.Tests++
		}

		report.TestSuites = append(report.TestSuites, suite)
	}

	data, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JUnit XML: %w", err)
	}

	if err := createReport(outputPath, func(w io.Writer) error {
		if _, err := w.Write([]byte(xml.Header)); err != nil {
			return err
		}
		_, err := w.Write(data)
		return err
	}); err != nil {
		return fmt.Errorf("failed to write JUnit report: %w", err)
	}

	return nil
}

func WriteGitHubAnnotations(result *scanner.Result) {
	for _, f := range result.Findings {
		level := "warning"
		if f.Severity == rules.SeverityCritical {
			level = "error"
		} else if f.Severity == rules.SeverityInfo {
			level = "notice"
		}

		fmt.Printf("::%s file=%s,line=%d,endLine=%d,col=%d,endColumn=%d::[%s] %s (CWE: %s)\n",
			level, filepath.ToSlash(f.File), f.Line, endLine(f), f.Column, f.EndColumn, f.RuleID, f.Message, f.CWE)
	}
}

func WriteCSV(result *scanner.Result, outputPath string) error {
	err := createReport(outputPath, func(out io.Writer) error {
		w := csv.NewWriter(out)

		if err := w.Write([]string{"rule_id", "severity", "file", "line", "column", "message", "cwe", "code"}); err != nil {
			return err
		}

		for _, f := range result.Findings {
			code := f.Code
			if len(code) > 100 {
				code = code[:100] + "..."
			}
			record := []string{
				f.RuleID, f.Severity.String(), f.File,
				strconv.Itoa(f.Line), strconv.Itoa(f.Column),
				f.Message, f.CWE, code,
			}
			if err := w.Write(record); err != nil {
				return err
			}
		}

		w.Flush()
		return w.Error()
	})
	if err != nil {
		return fmt.Errorf("failed to write CSV report: %w", err)
	}

	return nil
}
