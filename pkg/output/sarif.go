package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"
)

const sarifFingerprintKey = "vibeguard/v2"

type SARIF struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool        SARIFTool     `json:"tool"`
	Results     []SARIFResult `json:"results"`
	Invocations []Invocation  `json:"invocations,omitempty"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationUri string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription SARIFMessage `json:"shortDescription"`
	FullDescription  SARIFMessage `json:"fullDescription,omitempty"`
	DefaultConfig    SARIFConfig  `json:"defaultConfiguration"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type SARIFConfig struct {
	Level string `json:"level"`
}

type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             SARIFMessage      `json:"message"`
	Locations           []SARIFLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type Invocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ExitCode                   int                 `json:"exitCode"`
	StartTimeUtc               string              `json:"startTimeUtc,omitempty"`
	EndTimeUtc                 string              `json:"endTimeUtc,omitempty"`
	ToolExecutionNotifications []SARIFNotification `json:"toolExecutionNotifications,omitempty"`
}

// SARIFNotification reports work the scanner could not complete, so a consumer
// of the SARIF file cannot mistake a partial run for a clean one.
type SARIFNotification struct {
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

func WriteSARIF(result *scanner.Result, outputPath string, opts Options) error {
	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:           "vibeguard",
				Version:        Version,
				InformationUri: "https://github.com/KrauzX/vibeguard",
				Rules:          buildSARIFRules(),
			},
		},
		Results: buildSARIFResults(result),
		Invocations: []Invocation{{
			ExecutionSuccessful:        result.ErrorCount() == 0,
			ExitCode:                   opts.ExitCode,
			ToolExecutionNotifications: buildSARIFNotifications(result),
		}},
	}

	if !opts.NoTimestamp {
		now := time.Now().UTC().Format(time.RFC3339)
		run.Invocations[0].StartTimeUtc = now
		run.Invocations[0].EndTimeUtc = now
	}

	sarif := SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []SARIFRun{run},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	if err := createReport(outputPath, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	}); err != nil {
		return fmt.Errorf("failed to write SARIF report: %w", err)
	}

	return nil
}

func buildSARIFRules() []SARIFRule {
	allRules := rules.GetRules()
	result := make([]SARIFRule, len(allRules))

	for i, r := range allRules {
		result[i] = SARIFRule{
			ID:   r.ID,
			Name: r.Name,
			ShortDescription: SARIFMessage{
				Text: r.Name,
			},
			FullDescription: SARIFMessage{
				Text: r.Description,
			},
			DefaultConfig: SARIFConfig{
				Level: sarifLevel(r.Severity),
			},
			HelpURI: cweURI(r.CWE),
		}
	}

	return result
}

func buildSARIFResults(result *scanner.Result) []SARIFResult {
	sarifResults := make([]SARIFResult, 0, len(result.Findings))

	for _, f := range result.Findings {
		sarifResults = append(sarifResults, SARIFResult{
			RuleID: f.RuleID,
			Level:  sarifLevel(f.Severity),
			Message: SARIFMessage{
				Text: f.Message,
			},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: result.RelPath(f.File),
					},
					Region: SARIFRegion{
						StartLine:   f.Line,
						StartColumn: f.Column,
						EndLine:     endLine(f),
						EndColumn:   f.EndColumn,
					},
				},
			}},
			PartialFingerprints: map[string]string{
				sarifFingerprintKey: f.Fingerprint(result.RelPath(f.File)),
			},
		})
	}

	return sarifResults
}

func buildSARIFNotifications(result *scanner.Result) []SARIFNotification {
	notifications := make([]SARIFNotification, 0, len(result.FileErrors))
	for _, failure := range result.FileErrors {
		notifications = append(notifications, SARIFNotification{
			Level: "error",
			Message: SARIFMessage{
				Text: failure.Message,
			},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: result.RelPath(failure.File)},
					Region:           SARIFRegion{StartLine: 1},
				},
			}},
		})
	}

	return notifications
}

func endLine(f rules.Finding) int {
	if f.EndLine == 0 {
		return f.Line
	}

	return f.EndLine
}

func sarifLevel(sev rules.Severity) string {
	switch sev {
	case rules.SeverityCritical:
		return "error"
	case rules.SeverityInfo:
		return "note"
	}

	return "warning"
}

func cweURI(cwe string) string {
	if !strings.HasPrefix(cwe, "CWE-") {
		return ""
	}

	id := strings.TrimPrefix(cwe, "CWE-")
	if id == "" {
		return ""
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return ""
		}
	}

	return "https://cwe.mitre.org/data/definitions/" + id + ".html"
}
