package output

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"
)

func FormatTerminal(result *scanner.Result, noColor bool) string {
	var b strings.Builder
	c := NewColorizer(noColor)

	fmt.Fprintf(&b, "  %sFiles scanned:%s %d\n", c.Bold, c.Reset, result.FilesScanned)
	if result.FilesSkipped > 0 {
		fmt.Fprintf(&b, "  %sFiles skipped:%s %d\n", c.Dim, c.Reset, result.FilesSkipped)
	}
	if result.ErrorCount() > 0 {
		fmt.Fprintf(&b, "  %sFiles failed:%s  %d\n", c.Red, c.Reset, result.ErrorCount())
		for _, failure := range result.FileErrors {
			fmt.Fprintf(&b, "    %s%s: %s%s\n", c.Dim, failure.File, failure.Message, c.Reset)
		}
	}
	fmt.Fprintf(&b, "  %sFindings:%s      %d\n", c.Bold, c.Reset, len(result.Findings))
	if result.Suppressed > 0 {
		fmt.Fprintf(&b, "  %sSuppressed:%s    %d\n", c.Dim, c.Reset, result.Suppressed)
	}
	fmt.Fprintf(&b, "  %sDuration:%s      %s\n\n", c.Dim, c.Reset, result.Duration.Round(time.Millisecond))

	if len(result.Findings) == 0 {
		if result.ErrorCount() > 0 {
			fmt.Fprintf(&b, "  %sIncomplete: %d file(s) could not be read, so this is not a clean pass.%s\n\n", c.Red, result.ErrorCount(), c.Reset)
			return b.String()
		}
		fmt.Fprintf(&b, "  %sNo issues found.%s\n\n", c.Green, c.Reset)
		return b.String()
	}

	critical := result.CriticalCount()
	warning := result.WarningCount()
	info := result.InfoCount()

	if critical > 0 {
		fmt.Fprintf(&b, "  %sCRITICAL:%s %d\n", c.Red, c.Reset, critical)
	}
	if warning > 0 {
		fmt.Fprintf(&b, "  %sWARNING:%s  %d\n", c.Yellow, c.Reset, warning)
	}
	if info > 0 {
		fmt.Fprintf(&b, "  %sINFO:%s     %d\n", c.Cyan, c.Reset, info)
	}
	b.WriteString("\n")

	findingsByFile := result.FindingsByFile()
	files := make([]string, 0, len(findingsByFile))
	for f := range findingsByFile {
		files = append(files, f)
	}
	sort.Strings(files)

	for _, f := range files {
		fmt.Fprintf(&b, "  %s%s%s\n", c.Bold, f, c.Reset)
		for _, finding := range findingsByFile[f] {
			sevColor := c.Yellow
			if finding.Severity == rules.SeverityCritical {
				sevColor = c.Red
			} else if finding.Severity == rules.SeverityInfo {
				sevColor = c.Cyan
			}
			fmt.Fprintf(&b, "    %s[%s]%s line %d: %s\n", sevColor, finding.Severity, c.Reset, finding.Line, finding.Message)
			if finding.CWE != "" {
				fmt.Fprintf(&b, "      %s%s%s\n", c.Dim, finding.CWE, c.Reset)
			}
		}
		b.WriteString("\n")
	}

	if critical > 0 {
		fmt.Fprintf(&b, "  %s%d critical finding(s)%s\n", c.Red, critical, c.Reset)
	} else if warning > 0 {
		fmt.Fprintf(&b, "  %s%d warning(s)%s\n", c.Yellow, warning, c.Reset)
	} else {
		fmt.Fprintf(&b, "  %sno critical or warning findings%s\n", c.Green, c.Reset)
	}

	if result.DependencyInfo != nil {
		b.WriteString(formatDependencyReport(result.DependencyInfo, c))
	}

	return b.String()
}

func formatDependencyReport(dep *scanner.DependencyInfo, c *Colorizer) string {
	var b strings.Builder

	fmt.Fprintf(&b, "\n  %sDependencies%s\n", c.Bold, c.Reset)
	fmt.Fprintf(&b, "  %s────────────%s\n\n", c.Dim, c.Reset)

	stats := dep.Stats
	fmt.Fprintf(&b, "    Packages:    %s%d%s\n", c.Bold, stats.TotalPackages, c.Reset)
	fmt.Fprintf(&b, "    Files:       %s%d%s\n", c.Bold, stats.TotalFiles, c.Reset)
	fmt.Fprintf(&b, "    Lines:       %s%d%s\n", c.Bold, stats.TotalLines, c.Reset)
	fmt.Fprintf(&b, "    Edges:       %s%d%s\n", c.Bold, stats.TotalEdges, c.Reset)
	fmt.Fprintf(&b, "    Avg imports: %s%.1f%s\n", c.Bold, stats.AvgImportsPerPkg, c.Reset)
	fmt.Fprintf(&b, "    Max imports: %s%d%s\n", c.Bold, stats.MaxImports, c.Reset)
	fmt.Fprintf(&b, "    Checked:     %s%d%s pinned dependencies\n", c.Bold, dep.Packages, c.Reset)
	if dep.Vulnerable > 0 {
		fmt.Fprintf(&b, "    %sVulnerable: %d%s\n", c.Red, dep.Vulnerable, c.Reset)
	}
	if dep.Note != "" {
		fmt.Fprintf(&b, "    %s%s%s\n", c.Dim, dep.Note, c.Reset)
	}
	b.WriteString("\n")

	if len(dep.Cycles) > 0 {
		fmt.Fprintf(&b, "    %sCycles: %d%s\n", c.Yellow, len(dep.Cycles), c.Reset)
		for i, cycle := range dep.Cycles {
			if i >= 3 {
				fmt.Fprintf(&b, "       ... and %d more\n", len(dep.Cycles)-3)
				break
			}
			fmt.Fprintf(&b, "       %s%s%s\n", c.Yellow, strings.Join(cycle, " -> "), c.Reset)
		}
		b.WriteString("\n")
	}

	if len(dep.Orphans) > 0 {
		fmt.Fprintf(&b, "    %sOrphan packages: %d%s\n", c.Cyan, len(dep.Orphans), c.Reset)
		for i, orphan := range dep.Orphans {
			if i >= 3 {
				fmt.Fprintf(&b, "       ... and %d more\n", len(dep.Orphans)-3)
				break
			}
			fmt.Fprintf(&b, "       %s%s%s\n", c.Dim, orphan, c.Reset)
		}
		b.WriteString("\n")
	}

	return b.String()
}
