package output

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"
)

type HTMLData struct {
	Version    string
	Result     *scanner.Result
	Rules      []*rules.Rule
	ByFile     map[string][]rules.Finding
	BySeverity map[string][]rules.Finding
	RuleStats  map[string]int
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VibeGuard Security Report</title>
<style>
:root {
  --bg: #0d1117;
  --bg-secondary: #161b22;
  --bg-tertiary: #21262d;
  --border: #30363d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --red: #f85149;
  --red-bg: rgba(248,81,73,0.1);
  --yellow: #d29922;
  --yellow-bg: rgba(210,153,34,0.1);
  --green: #3fb950;
  --green-bg: rgba(63,185,80,0.1);
  --cyan: #58a6ff;
  --cyan-bg: rgba(88,166,255,0.1);
  --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  --mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: var(--font); background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
.container { max-width: 1200px; margin: 0 auto; }
header { text-align: center; margin-bottom: 2rem; padding: 2rem; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; }
header h1 { font-size: 2rem; margin-bottom: 0.5rem; }
header .subtitle { color: var(--text-muted); }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.summary-card { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; text-align: center; }
.summary-card .value { font-size: 2rem; font-weight: bold; }
.summary-card .label { color: var(--text-muted); font-size: 0.875rem; }
.summary-card.critical { border-color: var(--red); }
.summary-card.critical .value { color: var(--red); }
.summary-card.warning { border-color: var(--yellow); }
.summary-card.warning .value { color: var(--yellow); }
.summary-card.info { border-color: var(--cyan); }
.summary-card.info .value { color: var(--cyan); }
.summary-card.success { border-color: var(--green); }
.summary-card.success .value { color: var(--green); }
.status-bar { padding: 1rem 1.5rem; border-radius: 8px; margin-bottom: 2rem; font-weight: bold; font-size: 1.1rem; }
.status-bar.failed { background: var(--red-bg); border: 1px solid var(--red); color: var(--red); }
.status-bar.debt { background: var(--yellow-bg); border: 1px solid var(--yellow); color: var(--yellow); }
.status-bar.passed { background: var(--green-bg); border: 1px solid var(--green); color: var(--green); }
.status-bar.immaculate { background: var(--green-bg); border: 1px solid var(--green); color: var(--green); }
section { margin-bottom: 2rem; }
section h2 { font-size: 1.25rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
.finding { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; margin-bottom: 0.75rem; }
.finding.critical { border-left: 3px solid var(--red); }
.finding.warning { border-left: 3px solid var(--yellow); }
.finding.info { border-left: 3px solid var(--cyan); }
.finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
.finding-title { font-weight: 600; }
.finding-meta { font-size: 0.8rem; color: var(--text-muted); }
.severity-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
.severity-badge.critical { background: var(--red-bg); color: var(--red); }
.severity-badge.warning { background: var(--yellow-bg); color: var(--yellow); }
.severity-badge.info { background: var(--cyan-bg); color: var(--cyan); }
.code-block { background: var(--bg-tertiary); border-radius: 4px; padding: 0.75rem; margin-top: 0.5rem; font-family: var(--mono); font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
.file-header { background: var(--bg-tertiary); padding: 0.75rem 1rem; border-radius: 6px 6px 0 0; font-family: var(--mono); font-size: 0.9rem; border: 1px solid var(--border); border-bottom: none; }
.file-group { margin-bottom: 1.5rem; }
.file-findings { border: 1px solid var(--border); border-radius: 0 0 6px 6px; padding: 0.75rem; }
table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }
th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
th { background: var(--bg-tertiary); font-weight: 600; }
.rule-tag { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 0.7rem; background: var(--bg-tertiary); margin: 1px; }
footer { text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.875rem; border-top: 1px solid var(--border); margin-top: 2rem; }
.dep-section { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; }
.dep-stat { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid var(--border); }
.dep-stat:last-child { border-bottom: none; }
.cycle-item { background: var(--bg-tertiary); padding: 0.75rem; border-radius: 4px; margin-bottom: 0.5rem; font-family: var(--mono); font-size: 0.85rem; color: var(--yellow); }
</style>
</head>
<body>
<div class="container">
<header>
  <h1>🛡️ VibeGuard Security Report</h1>
  <p class="subtitle">Generated {{.Result.Duration.Round 1000000}} | {{.Result.FilesScanned}} files scanned</p>
</header>

<div class="summary-grid">
  <div class="summary-card">
    <div class="value">{{len .Result.Findings}}</div>
    <div class="label">Total Issues</div>
  </div>
  <div class="summary-card critical">
    <div class="value">{{.Result.CriticalCount}}</div>
    <div class="label">Critical</div>
  </div>
  <div class="summary-card warning">
    <div class="value">{{.Result.WarningCount}}</div>
    <div class="label">Warnings</div>
  </div>
  <div class="summary-card info">
    <div class="value">{{.Result.InfoCount}}</div>
    <div class="label">Info</div>
  </div>
</div>

{{if .Result.HasCritical}}
<div class="status-bar failed">FAILED — {{.Result.CriticalCount}} critical finding(s)</div>
{{else if gt .Result.WarningCount 0}}
<div class="status-bar debt">REVIEW — {{.Result.WarningCount}} warning(s)</div>
{{else if eq (len .Result.Findings) 0}}
<div class="status-bar immaculate">PASSED — no issues found</div>
{{else}}
<div class="status-bar passed">PASSED — informational findings only</div>
{{end}}

<section>
<h2>Findings by File</h2>
{{range $file, $findings := .ByFile}}
<div class="file-group">
  <div class="file-header">{{$file}} ({{len $findings}} findings)</div>
  <div class="file-findings">
    {{range $findings}}
    <div class="finding {{if eq .Severity.String "CRITICAL"}}critical{{else if eq .Severity.String "WARNING"}}warning{{else}}info{{end}}">
      <div class="finding-header">
        <span class="finding-title">{{.RuleID}}: {{.Message}}</span>
        <span class="severity-badge {{if eq .Severity.String "CRITICAL"}}critical{{else if eq .Severity.String "WARNING"}}warning{{else}}info{{end}}">{{.Severity}}</span>
      </div>
      <div class="finding-meta">Line {{.Line}}{{if .CWE}} | CWE: {{.CWE}}{{end}}</div>
      {{if .Code}}<div class="code-block">{{.Code}}</div>{{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}
</section>

{{if .Result.DependencyInfo}}
<section>
<h2>Dependency Analysis</h2>
<div class="dep-section">
  {{if .Result.DependencyInfo.Cycles}}
  <h3 style="margin: 1rem 0 0.5rem; color: var(--yellow);">Circular dependencies ({{len .Result.DependencyInfo.Cycles}})</h3>
  {{range .Result.DependencyInfo.Cycles}}
  <div class="cycle-item">{{range $i, $pkg := .}}{{if gt $i 0}} → {{end}}{{$pkg}}{{end}}</div>
  {{end}}
  {{end}}
  {{if .Result.DependencyInfo.Orphans}}
  <h3 style="margin: 1rem 0 0.5rem; color: var(--cyan);">🔸 Orphan Packages ({{len .Result.DependencyInfo.Orphans}})</h3>
  {{range .Result.DependencyInfo.Orphans}}
  <div style="padding: 0.25rem 0; color: var(--text-muted); font-family: var(--mono); font-size: 0.85rem;">{{.}}</div>
  {{end}}
  {{end}}
</div>
</section>
{{end}}

<section>
<h2>Rule Coverage</h2>
<table>
<thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>CWE</th><th>Tags</th></tr></thead>
<tbody>
{{range .Rules}}
<tr>
  <td style="font-family: var(--mono);">{{.ID}}</td>
  <td>{{.Name}}</td>
  <td><span class="severity-badge {{if eq .Severity.String "CRITICAL"}}critical{{else if eq .Severity.String "WARNING"}}warning{{else}}info{{end}}">{{.Severity}}</span></td>
  <td>{{.CWE}}</td>
  <td>{{range .Tags}}<span class="rule-tag">{{.}}</span> {{end}}</td>
</tr>
{{end}}
</tbody>
</table>
</section>

<footer>
  <p>VibeGuard v{{.Version}}</p>
  <p>Scan duration: {{.Result.Duration.Round 1000000}} | Rules: {{len .Rules}}</p>
</footer>
</div>
</body>
</html>`

func WriteHTML(result *scanner.Result, outputPath string) error {
	byFile := result.FindingsByFile()
	bySeverity := make(map[string][]rules.Finding)
	for _, f := range result.Findings {
		key := f.Severity.String()
		bySeverity[key] = append(bySeverity[key], f)
	}

	ruleStats := make(map[string]int)
	for _, f := range result.Findings {
		ruleStats[f.RuleID]++
	}

	data := HTMLData{
		Version:    Version,
		Result:     result,
		Rules:      rules.GetRules(),
		ByFile:     byFile,
		BySeverity: bySeverity,
		RuleStats:  ruleStats,
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"seq": func(n int) []int {
			s := make([]int, n)
			for i := range s {
				s[i] = i + 1
			}
			return s
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	if err := createReport(outputPath, func(w io.Writer) error {
		return tmpl.Execute(w, data)
	}); err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	return nil
}

func FormatMarkdownSummary(result *scanner.Result) string {
	var b strings.Builder

	b.WriteString("# VibeGuard Security Report\n\n")
	b.WriteString(fmt.Sprintf("**Scan Time:** %s  \n", result.Duration.Round(1e6)))
	b.WriteString(fmt.Sprintf("**Files Scanned:** %d  \n", result.FilesScanned))
	b.WriteString(fmt.Sprintf("**Total Issues:** %d  \n\n", len(result.Findings)))

	if len(result.Findings) == 0 {
		b.WriteString("## No issues found\n")
		return b.String()
	}

	critical := result.CriticalCount()
	warning := result.WarningCount()
	info := result.InfoCount()

	if critical > 0 {
		b.WriteString("## Findings\n\n")
		b.WriteString(fmt.Sprintf("- **CRITICAL:** %d\n", critical))
	} else if warning > 0 {
		b.WriteString("## Findings\n\n")
	} else {
		b.WriteString("## Findings\n\n")
	}

	if warning > 0 {
		b.WriteString(fmt.Sprintf("- **WARNING:** %d\n", warning))
	}
	if info > 0 {
		b.WriteString(fmt.Sprintf("- **INFO:** %d\n", info))
	}
	b.WriteString("\n")

	findingsByFile := result.FindingsByFile()
	for file, findings := range findingsByFile {
		b.WriteString(fmt.Sprintf("## %s\n\n", file))
		b.WriteString("| Line | Severity | Rule | Message | CWE |")
		b.WriteString("\n|------|----------|------|---------|-----|\n")
		for _, f := range findings {
			b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n",
				f.Line, f.Severity, f.RuleID, f.Message, f.CWE))
		}
		b.WriteString("\n")
	}

	return b.String()
}
