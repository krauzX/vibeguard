package scanner

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/KrauzX/vibeguard/pkg/analyzer"
	"github.com/KrauzX/vibeguard/pkg/rules"
)

type Result struct {
	Root           string
	Findings       []rules.Finding
	FilesScanned   int64
	FilesSkipped   int64
	FileErrors     []FileError
	Suppressed     int64
	Duration       time.Duration
	DependencyInfo *DependencyInfo
}

// FileError records a file that could not be scanned. Its presence means the
// run is partial and must not be reported as a clean pass.
type FileError struct {
	File    string `json:"file"`
	Message string `json:"message"`
}

func (r *Result) ErrorCount() int {
	return len(r.FileErrors)
}

// RelPath returns path relative to the scanned root so reports stay portable
// and byte-stable across machines.
func (r *Result) RelPath(path string) string {
	return relativePath(r.Root, path)
}

// relativePath anchors a path to root; baseline ids and reports must hash the
// same string or an accepted finding comes back.
func relativePath(root, path string) string {
	if root == "" {
		return filepath.ToSlash(path)
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}

	return filepath.ToSlash(rel)
}

type DependencyInfo struct {
	Graph      *analyzer.ImportGraph
	Cycles     [][]string
	Orphans    []string
	Stats      analyzer.GraphStats
	Packages   int
	Vulnerable int
	Note       string
}

func (r *Result) CriticalCount() int {
	count := 0
	for _, f := range r.Findings {
		if f.Severity == rules.SeverityCritical {
			count++
		}
	}
	return count
}

func (r *Result) WarningCount() int {
	count := 0
	for _, f := range r.Findings {
		if f.Severity == rules.SeverityWarning {
			count++
		}
	}
	return count
}

func (r *Result) InfoCount() int {
	count := 0
	for _, f := range r.Findings {
		if f.Severity == rules.SeverityInfo {
			count++
		}
	}
	return count
}

func (r *Result) HasCritical() bool {
	return r.CriticalCount() > 0
}

// CountAtLeast returns the number of findings with severity >= sev.
func (r *Result) CountAtLeast(sev rules.Severity) int {
	count := 0
	for _, f := range r.Findings {
		if f.Severity >= sev {
			count++
		}
	}

	return count
}

func (r *Result) Summary() string {
	critical := r.CriticalCount()
	warning := r.WarningCount()
	info := r.InfoCount()

	parts := []string{}
	if critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", critical))
	}
	if warning > 0 {
		parts = append(parts, fmt.Sprintf("%d warning", warning))
	}
	if info > 0 {
		parts = append(parts, fmt.Sprintf("%d info", info))
	}

	if len(parts) == 0 {
		return "No issues found"
	}

	return strings.Join(parts, ", ")
}

func (r *Result) FindingsByFile() map[string][]rules.Finding {
	byFile := make(map[string][]rules.Finding)
	for _, f := range r.Findings {
		byFile[f.File] = append(byFile[f.File], f)
	}
	return byFile
}
