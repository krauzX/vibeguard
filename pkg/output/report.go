package output

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/KrauzX/vibeguard/pkg/analyzer"
	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"
)

// Version is the tool version stamped into every report.
var Version = "1.0.0"

// SchemaVersion gates the JSON contract; reject unknown major versions.
const SchemaVersion = "2"

// Options holds reproducibility switches and the exit code SARIF records.
type Options struct {
	NoTimestamp bool
	ExitCode    int
}

type JSONReport struct {
	SchemaVersion string              `json:"schema_version"`
	Version       string              `json:"version"`
	Timestamp     string              `json:"timestamp,omitempty"`
	Root          string              `json:"root"`
	Summary       JSONSummary         `json:"summary"`
	Findings      []JSONFinding       `json:"findings"`
	Errors        []scanner.FileError `json:"errors,omitempty"`
	Rules         []JSONRule          `json:"rules,omitempty"`
	DepInfo       *JSONDependencyInfo `json:"dependencies,omitempty"`
}

type JSONSummary struct {
	FilesScanned int    `json:"files_scanned"`
	FilesSkipped int    `json:"files_skipped"`
	FilesFailed  int    `json:"files_failed"`
	Suppressed   int    `json:"suppressed"`
	Duration     string `json:"duration,omitempty"`
	TotalIssues  int    `json:"total_issues"`
	Critical     int    `json:"critical"`
	Warning      int    `json:"warning"`
	Info         int    `json:"info"`
}

type JSONFinding struct {
	ID          string `json:"id"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	EndLine     int    `json:"end_line"`
	EndColumn   int    `json:"end_column,omitempty"`
	Message     string `json:"message"`
	Description string `json:"description,omitempty"`
	Code        string `json:"code,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	Fix         string `json:"fix"`
}

type JSONRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CWE         string   `json:"cwe,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type JSONDependencyInfo struct {
	Cycles     [][]string          `json:"cycles,omitempty"`
	Orphans    []string            `json:"orphans,omitempty"`
	Stats      analyzer.GraphStats `json:"stats"`
	Packages   int                 `json:"packages_checked"`
	Vulnerable int                 `json:"vulnerable"`
	Note       string              `json:"note,omitempty"`
}

func WriteJSON(result *scanner.Result, outputPath string, opts Options) error {
	report := JSONReport{
		SchemaVersion: SchemaVersion,
		Version:       Version,
		Root:          filepath.ToSlash(result.Root),
		Summary: JSONSummary{
			FilesScanned: int(result.FilesScanned),
			FilesSkipped: int(result.FilesSkipped),
			FilesFailed:  result.ErrorCount(),
			Suppressed:   int(result.Suppressed),
			TotalIssues:  len(result.Findings),
			Critical:     result.CriticalCount(),
			Warning:      result.WarningCount(),
			Info:         result.InfoCount(),
		},
		Findings: BuildFindings(result),
		Errors:   result.FileErrors,
		Rules:    convertRules(rules.GetRules()),
	}

	if !opts.NoTimestamp {
		report.Timestamp = time.Now().UTC().Format(time.RFC3339)
		report.Summary.Duration = result.Duration.String()
	}

	if result.DependencyInfo != nil {
		report.DepInfo = &JSONDependencyInfo{
			Cycles:     result.DependencyInfo.Cycles,
			Orphans:    result.DependencyInfo.Orphans,
			Stats:      result.DependencyInfo.Stats,
			Packages:   result.DependencyInfo.Packages,
			Vulnerable: result.DependencyInfo.Vulnerable,
			Note:       result.DependencyInfo.Note,
		}
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := createReport(outputPath, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	}); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	return nil
}

// BuildFindings converts scanner findings into the stable report shape shared
// by `scan --format json` and `verify --json`.
func BuildFindings(result *scanner.Result) []JSONFinding {
	findings := make([]JSONFinding, len(result.Findings))
	for i, f := range result.Findings {
		findings[i] = NewJSONFinding(result, f)
	}

	return findings
}

func NewJSONFinding(result *scanner.Result, f rules.Finding) JSONFinding {
	rel := result.RelPath(f.File)
	rule := rules.GetRuleByID(f.RuleID)

	endLine := f.EndLine
	if endLine == 0 {
		endLine = f.Line
	}

	finding := JSONFinding{
		ID:        f.Fingerprint(rel),
		RuleID:    f.RuleID,
		Severity:  f.Severity.String(),
		File:      rel,
		Line:      f.Line,
		Column:    f.Column,
		EndLine:   endLine,
		EndColumn: f.EndColumn,
		Message:   f.Message,
		Code:      f.Code,
		CWE:       f.CWE,
		Fix:       f.FixText(),
	}

	if rule != nil && rule.Description != f.Message {
		finding.Description = rule.Description
	}

	return finding
}

func convertRules(allRules []*rules.Rule) []JSONRule {
	result := make([]JSONRule, len(allRules))
	for i, r := range allRules {
		result[i] = JSONRule{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			Severity:    r.Severity.String(),
			CWE:         r.CWE,
			Tags:        r.Tags,
		}
	}
	return result
}
