package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/KrauzX/vibeguard/pkg/analyzer/supply"
	"github.com/KrauzX/vibeguard/pkg/baseline"
	"github.com/KrauzX/vibeguard/pkg/config"
	"github.com/KrauzX/vibeguard/pkg/diff"
	"github.com/KrauzX/vibeguard/pkg/output"
	"github.com/KrauzX/vibeguard/pkg/prompt"
	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"

	"github.com/spf13/cobra"
)

// Exit codes separate a policy breach from a tool failure.
const (
	exitFindings = 1
	exitFailure  = 2
)

var version = output.Version

var (
	cfgFile        string
	noColor        bool
	outputFmt      string
	outputFile     string
	quiet          bool
	verbose        bool
	skipDeps       bool
	offline        bool
	timeoutBudget  time.Duration
	noTimestamp    bool
	workers        int
	jsonFmt        bool
	htmlFmt        bool
	junitFmt       bool
	csvFmt         bool
	sarifFmt       bool
	githubFmt      bool
	markdownFmt    bool
	promptFormat   string
	compactMode    bool
	batchMode      bool
	failOn         string
	diffBase       string
	stdinName      string
	verifyJSON     bool
	baselineID     string
	baselineReason string
	pluginFix      string
)

type policyError struct {
	message string
}

func (e *policyError) Error() string {
	return e.message
}

func (e *policyError) ExitCode() int {
	return exitFindings
}

var rootCmd = &cobra.Command{
	Use:   "vibeguard",
	Short: "Security scanner for source repositories",
	Long: `VibeGuard scans a codebase for security defects and code quality issues,
maps every finding to its CWE, gives each finding a stable id, and writes the
remediation you can hand to a reviewer or an agent.

Exit codes:
  0  no finding matched the failure policy
  1  the policy was breached (see --fail-on)
  2  the tool could not complete the work, or the scan was partial

Features:
  - 63 rules with CWE mapping, each with a one-line fix
  - AST-based Go analysis and intraprocedural taint tracking
  - OSV dependency advisories, import graph, cycles and orphan detection
  - CycloneDX bill of materials for every manifest in the tree
  - Content-addressed baseline for accepted findings
  - Terminal, JSON, SARIF, HTML, Markdown, JUnit, CSV and GitHub output
  - Diff-scoped scanning so a review only sees what changed

Commands:
  vibeguard scan      Scan a codebase for vulnerabilities
  vibeguard verify    Check that findings are gone
  vibeguard prompt    Generate fix prompts for findings
  vibeguard fix       Write a fix guide covering every finding
  vibeguard sbom      Write a CycloneDX bill of materials
  vibeguard rules     List all security rules
  vibeguard baseline  Manage suppressed findings
  vibeguard plugin    Manage custom rules

Languages: Go, Python, JavaScript, TypeScript, Java, Ruby, PHP, Shell.`,
	Version:      version,
	SilenceUsage: true,
}

var scanCmd = &cobra.Command{
	Use:   "scan [path|-]",
	Short: "Scan a directory, or a single file from stdin, for security issues",
	Long: `Scan a directory tree. Pass "-" to scan a buffer from stdin, naming it with
--stdin-name so language-specific rules apply.`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

var rulesCmd = &cobra.Command{
	Use:   "rules [language]",
	Short: "List all available security rules",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRules,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("vibeguard %s\n", version)
		fmt.Printf("go %s\n", runtime.Version())
		fmt.Printf("platform %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("cpus %d\n", runtime.NumCPU())
		fmt.Printf("schema %s\n", output.SchemaVersion)
	},
}

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage scan baselines for false positive suppression",
}

var baselineAddCmd = &cobra.Command{
	Use:   "add --id <id> [--reason text]",
	Short: "Accept a finding by the id a report gave you",
	Long: `Suppress one finding. The id comes from a scan report and is derived from the
rule, the file and the flagged source, so the entry keeps matching after the
code moves.`,
	Args: cobra.NoArgs,
	RunE: runBaselineAdd,
}

var baselineShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current baseline suppressions",
	RunE:  runBaselineShow,
}

var baselineRemoveCmd = &cobra.Command{
	Use:   "remove --id <id>",
	Short: "Revoke an accepted finding",
	Args:  cobra.NoArgs,
	RunE:  runBaselineRemove,
}

var promptCmd = &cobra.Command{
	Use:   "prompt [path]",
	Short: "Generate fix prompts for security findings",
	Args:  cobra.ExactArgs(1),
	RunE:  runPrompt,
}

var fixCmd = &cobra.Command{
	Use:   "fix [path]",
	Short: "Generate a fix document covering all findings",
	Args:  cobra.ExactArgs(1),
	RunE:  runFix,
}

var verifyCmd = &cobra.Command{
	Use:   "verify [path]",
	Short: "Verify security fixes were applied correctly",
	Long: `Re-scan a path and fail when findings remain. Use --json to get the same
findings shape as scan reports, which makes the fix loop machine-checkable.`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage custom rule plugins",
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed custom rules",
	RunE:  runPluginList,
}

var pluginInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize plugin directory",
	RunE:  runPluginInit,
}

var pluginCreateCmd = &cobra.Command{
	Use:   "create [id] [name] [pattern]",
	Short: "Create a new custom rule",
	Args:  cobra.ExactArgs(3),
	RunE:  runPluginCreate,
}

var pluginDeleteCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Delete a custom rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginDelete,
}

var sbomCmd = &cobra.Command{
	Use:   "sbom [path]",
	Short: "Write a CycloneDX bill of materials for the dependencies in a tree",
	Args:  cobra.ExactArgs(1),
	RunE:  runSBOM,
}

func init() {
	persistent := rootCmd.PersistentFlags()
	persistent.StringVarP(&cfgFile, "config", "c", "", "Config file path (default: vibeguard.yaml)")
	persistent.BoolVar(&skipDeps, "skip-deps", false, "Skip dependency analysis")
	persistent.BoolVar(&offline, "offline", false, "Skip network lookups, including advisory data")
	persistent.DurationVar(&timeoutBudget, "timeout", 0, "Budget for network lookups, e.g. 20s (0 = config value)")
	persistent.BoolVar(&noTimestamp, "no-timestamp", false, "Omit timestamps and durations so reports are byte-reproducible")

	scanCmd.Flags().StringVarP(&outputFmt, "format", "f", "", "Output format: "+strings.Join(output.Formats(), ", "))
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path, or - for stdout")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	scanCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress non-essential output")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 0, "Number of parallel workers (0 = auto)")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "Exit 1 when these findings exist: none, any, warning, critical, secret (comma separated)")
	scanCmd.Flags().StringVar(&diffBase, "diff", "", "Only report findings on lines changed since this git revision")
	scanCmd.Flags().StringVar(&stdinName, "stdin-name", "stdin", "File name used for language detection when reading stdin")

	scanCmd.Flags().Lookup("diff").NoOptDefVal = "HEAD"
	scanCmd.Flags().BoolVar(&jsonFmt, "json", false, "Output as JSON")
	scanCmd.Flags().BoolVar(&htmlFmt, "html", false, "Output as HTML report")
	scanCmd.Flags().BoolVar(&junitFmt, "junit", false, "Output as JUnit XML")
	scanCmd.Flags().BoolVar(&csvFmt, "csv", false, "Output as CSV")
	scanCmd.Flags().BoolVar(&sarifFmt, "sarif", false, "Output as SARIF")
	scanCmd.Flags().BoolVar(&githubFmt, "github", false, "Output as GitHub Actions annotations")
	scanCmd.Flags().BoolVar(&markdownFmt, "markdown", false, "Output as Markdown")

	promptCmd.Flags().StringVarP(&promptFormat, "format", "f", "generic", "Prompt format: claude, gpt, copilot, generic")
	promptCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")
	promptCmd.Flags().BoolVar(&compactMode, "compact", false, "Compact output")
	promptCmd.Flags().BoolVar(&batchMode, "batch", false, "One prompt per file instead of per finding")

	fixCmd.Flags().StringVarP(&promptFormat, "format", "f", "generic", "Prompt format: claude, gpt, copilot, generic")
	fixCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")
	fixCmd.Flags().BoolVar(&compactMode, "compact", false, "Compact output")

	verifyCmd.Flags().BoolVar(&verifyJSON, "json", false, "Print remaining findings as JSON")

	baselineAddCmd.Flags().StringVar(&baselineID, "id", "", "Finding id reported by a scan")
	baselineAddCmd.Flags().StringVar(&baselineReason, "reason", "", "Why the finding is accepted")
	baselineRemoveCmd.Flags().StringVar(&baselineID, "id", "", "Fingerprint id reported by a scan")

	baselineCmd.AddCommand(baselineAddCmd)
	baselineCmd.AddCommand(baselineShowCmd)
	baselineCmd.AddCommand(baselineRemoveCmd)

	pluginCreateCmd.Flags().StringVar(&pluginFix, "fix", "", "Remediation text shown in reports and prompts")

	pluginCmd.AddCommand(pluginListCmd)
	pluginCmd.AddCommand(pluginInitCmd)
	pluginCmd.AddCommand(pluginCreateCmd)
	pluginCmd.AddCommand(pluginDeleteCmd)

	sbomCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(sbomCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(baselineCmd)
	rootCmd.AddCommand(promptCmd)
	rootCmd.AddCommand(fixCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(pluginCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	start := time.Now()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	applyFlagOverrides(cfg)

	format := determineOutputFormat(cfg)
	if !output.IsValidFormat(format) {
		return fmt.Errorf("unsupported output format %q (known: %s)", format, strings.Join(output.Formats(), ", "))
	}

	policy, err := failOnList(cfg)
	if err != nil {
		return err
	}

	if args[0] == "-" {
		return scanStdin(cfg, format, policy, start)
	}

	absRoot, err := existingPath(args[0])
	if err != nil {
		return err
	}

	if !cfg.Reporting.Quiet && format != "github" && resolveOutputPath(cfg, format, false) != output.StdoutPath {
		printBanner(absRoot, cfg)
	}

	result, err := scanner.New(cfg).Scan(absRoot)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if cmd.Flags().Changed("diff") {
		filtered, filterErr := applyDiffFilter(result, diffBase)
		if filterErr != nil {
			fmt.Fprintf(os.Stderr, "warning: %v; reporting the whole tree\n", filterErr)
		} else {
			result.Findings = filtered
			scanner.SortFindings(result.Findings)
		}
	}

	return emitResult(cfg, result, format, policy, start, false)
}

func scanStdin(cfg *config.Config, format string, policy []string, start time.Time) error {
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}

	name := stdinName
	if name == "" {
		name = "stdin"
	}
	if rules.LanguageForExt(filepath.Ext(name)) == rules.LanguageAny {
		fmt.Fprintf(os.Stderr, "warning: %q has no known extension; language-specific rules and analyzers are skipped\n", name)
	}

	result := scanner.New(cfg).ScanContent(name, content)

	return emitResult(cfg, result, format, policy, start, true)
}

func emitResult(cfg *config.Config, result *scanner.Result, format string, policy []string, start time.Time, fromStdin bool) error {
	outputFile = resolveOutputPath(cfg, format, fromStdin)

	// A machine format written to stdout owns the stream; keep the human report out of it.
	if !cfg.Reporting.Quiet && outputFile != output.StdoutPath {
		fmt.Print(output.FormatTerminal(result, cfg.Reporting.NoColor))
	}

	opts := output.Options{NoTimestamp: noTimestamp, ExitCode: exitCodeFor(policy, result)}

	if err := writeOutput(result, format, outputFile, opts); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	if !cfg.Reporting.Quiet {
		fmt.Fprintf(os.Stderr, "scanned %d file(s) in %s\n", result.FilesScanned, time.Since(start).Round(time.Millisecond))
	}

	return scanOutcome(policy, result)
}

// resolveOutputPath picks the report destination once so the banner, the human
// report and the writer all agree on whether stdout belongs to the report.
func resolveOutputPath(cfg *config.Config, format string, fromStdin bool) string {
	path := outputFile
	if path == "" && cfg.Reporting.Output != "" {
		path = cfg.Reporting.Output
	}
	if path != "" {
		return path
	}

	switch {
	case fromStdin && pipesToStdout(format):
		return output.StdoutPath
	case pipesToStdout(format):
		return defaultReportPath(format)
	}

	return ""
}

// pipesToStdout skips formats already printed during the scan.
func pipesToStdout(format string) bool {
	return format != "terminal" && format != "github"
}

func applyDiffFilter(result *scanner.Result, base string) ([]rules.Finding, error) {
	if base == "" {
		base = "HEAD"
	}

	ranges, err := diff.ChangedLines(result.Root, base)
	if err != nil {
		return nil, err
	}

	filtered := ranges.Filter(result)
	if !quiet && len(filtered) != len(result.Findings) {
		fmt.Fprintf(os.Stderr, "diff vs %s: reporting %d of %d finding(s) on changed lines\n", base, len(filtered), len(result.Findings))
	}

	return filtered, nil
}

func scanOutcome(policy []string, result *scanner.Result) error {
	if result.ErrorCount() > 0 {
		return fmt.Errorf("scan incomplete: %d file(s) could not be read", result.ErrorCount())
	}

	for _, name := range policy {
		if name == "none" {
			return nil
		}
	}

	checks := []struct {
		name  string
		count func() int
	}{
		{"critical", result.CriticalCount},
		{"secret", func() int { return secretCount(result) }},
		{"warning", func() int { return result.CountAtLeast(rules.SeverityWarning) }},
		{"any", func() int { return len(result.Findings) }},
	}

	for _, check := range checks {
		if !policyIncludes(policy, check.name) {
			continue
		}
		if n := check.count(); n > 0 {
			return &policyError{message: fmt.Sprintf("%d %s finding(s)", n, check.name)}
		}
	}

	return nil
}

func exitCodeFor(policy []string, result *scanner.Result) int {
	if result.ErrorCount() > 0 {
		return exitFailure
	}
	if scanOutcome(policy, result) != nil {
		return exitFindings
	}

	return 0
}

func failOnList(cfg *config.Config) ([]string, error) {
	if failOn == "" {
		var names []string
		if cfg.Security.FailOnCritical {
			names = append(names, "critical")
		}
		if cfg.Security.FailOnSecrets {
			names = append(names, "secret")
		}
		if len(names) == 0 {
			return []string{"none"}, nil
		}
		return names, nil
	}

	var names []string
	for _, raw := range strings.Split(failOn, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case "":
			continue
		case "none", "any", "warning", "critical", "secret":
			names = append(names, name)
		default:
			return nil, fmt.Errorf("invalid --fail-on value %q (known: none, any, warning, critical, secret)", raw)
		}
	}

	if len(names) == 0 {
		return []string{"none"}, nil
	}

	return names, nil
}

func policyIncludes(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}

	return false
}

func secretCount(result *scanner.Result) int {
	count := 0
	for _, f := range result.Findings {
		rule := rules.GetRuleByID(f.RuleID)
		if rule == nil {
			continue
		}
		for _, tag := range rule.Tags {
			if tag == "secret" || tag == "secrets" {
				count++
				break
			}
		}
	}
	return count
}

func runRules(cmd *cobra.Command, args []string) error {
	allRules := rules.GetRules()

	catalogLanguages := ruleLanguages(allRules)

	langFilter := ""
	if len(args) > 0 {
		langFilter = strings.ToLower(args[0])
		aliases := map[string]string{"js": "javascript", "ts": "typescript", "bash": "shell"}
		if full, ok := aliases[langFilter]; ok {
			langFilter = full
		}
		if !hasName(catalogLanguages, langFilter) {
			return fmt.Errorf("unknown language %q (known: %s)", langFilter, strings.Join(catalogLanguages, ", "))
		}
	}

	shown := 0
	for _, r := range allRules {
		if langFilter == "" || ruleHasLanguage(r, langFilter) {
			shown++
		}
	}
	fmt.Printf("security rules (%d)\n\n", shown)

	currentSeverity := rules.Severity(-1)
	for _, r := range allRules {
		langs := "all"
		if len(r.Languages) > 0 {
			names := make([]string, len(r.Languages))
			for i, l := range r.Languages {
				names[i] = string(l)
			}
			langs = strings.Join(names, ", ")
		}

		if langFilter != "" && !ruleHasLanguage(r, langFilter) {
			continue
		}

		if r.Severity != currentSeverity {
			currentSeverity = r.Severity
			fmt.Printf("%s\n", r.Severity)
		}

		fmt.Printf("  %-10s %-34s", r.ID, r.Name)
		if r.CWE != "" {
			fmt.Printf(" %s", r.CWE)
		}
		fmt.Printf("  [%s]\n", langs)
	}

	fmt.Println()
	return nil
}

func ruleLanguages(all []*rules.Rule) []string {
	seen := make(map[string]bool)
	var names []string
	for _, r := range all {
		for _, lang := range r.Languages {
			if lang == rules.LanguageAny || seen[string(lang)] {
				continue
			}
			seen[string(lang)] = true
			names = append(names, string(lang))
		}
	}
	sort.Strings(names)
	return names
}

func ruleHasLanguage(r *rules.Rule, want string) bool {
	if len(r.Languages) == 0 {
		return true
	}
	for _, lang := range r.Languages {
		if string(lang) == want {
			return true
		}
	}
	return false
}

func hasName(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

func printBanner(root string, cfg *config.Config) {
	c := output.NewColorizer(cfg.Reporting.NoColor)

	fmt.Printf("%svibeguard %s%s\n", c.Bold, version, c.Reset)

	if cfg.Reporting.Verbose {
		fmt.Printf("  target   %s\n", root)
		fmt.Printf("  workers  %d\n", cfg.WorkerCount())
		fmt.Printf("  max file %d KB\n", cfg.Scanner.MaxFileSize/1024)
		fmt.Printf("  timeout  %s\n", cfg.Dependencies.Timeout)
		fmt.Printf("  offline  %v\n", cfg.Dependencies.Offline)
		fmt.Printf("  rules    go=%v python=%v js=%v java=%v\n",
			cfg.Rules.EnableGo, cfg.Rules.EnablePython,
			cfg.Rules.EnableJS, cfg.Rules.EnableJava)
	}

	fmt.Println()
}

func determineOutputFormat(cfg *config.Config) string {
	if outputFmt != "" {
		return strings.ToLower(outputFmt)
	}
	switch {
	case jsonFmt:
		return "json"
	case htmlFmt:
		return "html"
	case junitFmt:
		return "junit"
	case csvFmt:
		return "csv"
	case sarifFmt:
		return "sarif"
	case githubFmt:
		return "github"
	case markdownFmt:
		return "markdown"
	}

	if cfg.Reporting.Format != "" {
		return strings.ToLower(cfg.Reporting.Format)
	}

	if outputFile == "" {
		return "terminal"
	}

	switch strings.ToLower(filepath.Ext(outputFile)) {
	case ".sarif":
		return "sarif"
	case ".html":
		return "html"
	case ".xml":
		return "junit"
	case ".csv":
		return "csv"
	case ".md", ".markdown":
		return "markdown"
	default:
		return "json"
	}
}

func defaultReportPath(format string) string {
	switch format {
	case "sarif":
		return "vibeguard-report.sarif"
	case "html":
		return "vibeguard-report.html"
	case "junit":
		return "vibeguard-report.xml"
	case "csv":
		return "vibeguard-report.csv"
	case "markdown":
		return "vibeguard-report.md"
	default:
		return "vibeguard-report.json"
	}
}

func writeOutput(result *scanner.Result, format, path string, opts output.Options) error {
	if format == "github" {
		output.WriteGitHubAnnotations(result)
		return nil
	}

	if path == "" {
		return nil
	}

	switch format {
	case "terminal":
		text := output.FormatTerminal(result, true)
		if path == output.StdoutPath {
			fmt.Print(text)
			return nil
		}
		if err := os.WriteFile(path, []byte(text), 0644); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		return nil
	case "json":
		return output.WriteJSON(result, path, opts)
	case "sarif":
		return output.WriteSARIF(result, path, opts)
	case "html":
		return output.WriteHTML(result, path)
	case "junit":
		return output.WriteJUnit(result, path)
	case "csv":
		return output.WriteCSV(result, path)
	case "markdown":
		text := output.FormatMarkdownSummary(result)
		if path == output.StdoutPath {
			fmt.Print(text)
			return nil
		}
		if err := os.WriteFile(path, []byte(text), 0644); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func existingPath(raw string) (string, error) {
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("path does not exist: %s", abs)
	}

	return abs, nil
}

func applyFlagOverrides(cfg *config.Config) {
	if noColor {
		cfg.Reporting.NoColor = true
	}
	if workers > 0 {
		cfg.Scanner.Workers = workers
	}
	if quiet {
		cfg.Reporting.Quiet = true
	}
	if verbose {
		cfg.Reporting.Verbose = true
	}
	if skipDeps {
		cfg.Dependencies.CheckVulnerabilities = false
	}
	if offline {
		cfg.Dependencies.Offline = true
	}
	if timeoutBudget > 0 {
		cfg.Dependencies.Timeout = timeoutBudget
	}
}

func baselinePath() (string, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return "", fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Baseline.Path != "" {
		return cfg.Baseline.Path, nil
	}

	return ".vibeguard-baseline.json", nil
}

func loadBaseline() (*baseline.Baseline, error) {
	path, err := baselinePath()
	if err != nil {
		return nil, err
	}

	b := baseline.New(path)
	if err := b.Load(); err != nil {
		return nil, err
	}

	return b, nil
}

func runBaselineAdd(cmd *cobra.Command, args []string) error {
	if baselineID == "" {
		return fmt.Errorf("usage: vibeguard baseline add --id <id from a report> [--reason text]")
	}

	b, err := loadBaseline()
	if err != nil {
		return err
	}

	reason := baselineReason
	if reason == "" {
		reason = "accepted"
	}

	if err := b.Add(baseline.SuppressedFinding{ID: baselineID, Reason: reason}); err != nil {
		return err
	}
	fmt.Printf("accepted %s\n", baselineID)

	cfg, err := config.Load(cfgFile)
	if err == nil && !cfg.Baseline.Enabled {
		fmt.Println("note: baseline.enabled is false in config, so scans will not apply it")
	}

	return nil
}

func runBaselineRemove(cmd *cobra.Command, args []string) error {
	if baselineID == "" {
		return fmt.Errorf("usage: vibeguard baseline remove --id <id from baseline show>")
	}

	b, err := loadBaseline()
	if err != nil {
		return err
	}

	removed, err := b.Remove(baselineID)
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("no baseline entry with id %s", baselineID)
	}

	fmt.Printf("removed %s\n", baselineID)
	return nil
}

func runBaselineShow(cmd *cobra.Command, args []string) error {
	b, err := loadBaseline()
	if err != nil {
		return err
	}

	suppressions := b.Suppressions()
	if len(suppressions) == 0 {
		fmt.Println("no suppressions in baseline")
		return nil
	}

	fmt.Printf("baseline suppressions (%d)\n\n", len(suppressions))
	for _, s := range suppressions {
		fmt.Printf("  %s %s\n", s.ID, s.Reason)
	}

	return nil
}

func runPrompt(cmd *cobra.Command, args []string) error {
	absPath, err := existingPath(args[0])
	if err != nil {
		return err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("cannot stat %s: %w", absPath, err)
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	applyFlagOverrides(cfg)

	result, err := scanner.New(cfg).Scan(absPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if len(result.Findings) == 0 {
		fmt.Println("no security issues found")
		return nil
	}

	optimizer := prompt.NewTokenOptimizer(prompt.PromptFormat(promptFormat), compactMode)

	var out strings.Builder
	if !compactMode && info.IsDir() {
		fmt.Fprintf(&out, "# VibeGuard fix prompts\n\n")
		fmt.Fprintf(&out, "Scanned: %s\n", absPath)
		fmt.Fprintf(&out, "Findings: %d\n\n", len(result.Findings))
	}

	if compactMode {
		out.WriteString(prompt.CompactBatchFormat(result.Findings, absPath))
		out.WriteString("\n")
	}

	byFile := result.FindingsByFile()

	if batchMode {
		generator := prompt.NewBatchGenerator(prompt.PromptFormat(promptFormat))
		for _, file := range sortedFiles(byFile) {
			batch, err := generator.GenerateBatch(file, byFile[file])
			if err != nil {
				continue
			}
			out.WriteString(generator.FormatBatch(batch))
			out.WriteString("\n")
		}
	} else {
		for _, finding := range result.Findings {
			ctx, err := prompt.CollectContext(finding.File, finding)
			if err != nil {
				continue
			}

			out.WriteString(optimizer.OptimizePrompt(ctx))
			out.WriteString("\n\n")
		}
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(out.String()), 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("prompts written to %s\n", outputFile)
		return nil
	}

	fmt.Print(out.String())
	return nil
}

func runFix(cmd *cobra.Command, args []string) error {
	absPath, err := existingPath(args[0])
	if err != nil {
		return err
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	applyFlagOverrides(cfg)

	result, err := scanner.New(cfg).Scan(absPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if len(result.Findings) == 0 {
		fmt.Println("no security issues found")
		return nil
	}

	gen := prompt.NewGenerator(prompt.PromptFormat(promptFormat))

	var out strings.Builder
	out.WriteString("# VibeGuard security fix guide\n\n")
	if !noTimestamp {
		fmt.Fprintf(&out, "Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	}
	fmt.Fprintf(&out, "Scan path: %s\n", absPath)
	fmt.Fprintf(&out, "Total issues: %d\n\n", len(result.Findings))
	out.WriteString("## Summary\n\n")
	out.WriteString("| Severity | Count |\n|----------|-------|\n")
	fmt.Fprintf(&out, "| Critical | %d |\n", result.CriticalCount())
	fmt.Fprintf(&out, "| Warning | %d |\n", result.WarningCount())
	fmt.Fprintf(&out, "| Info | %d |\n", result.InfoCount())
	fmt.Fprintf(&out, "| **Total** | **%d** |\n\n", len(result.Findings))

	byFile := result.FindingsByFile()
	for _, file := range sortedFiles(byFile) {
		findings := byFile[file]
		fmt.Fprintf(&out, "## %s\n\n", filepath.Base(file))
		fmt.Fprintf(&out, "File: `%s`\n\n", file)

		for _, finding := range findings {
			ctx, err := prompt.CollectContext(file, finding)
			if err != nil {
				continue
			}

			prompt := gen.Generate(ctx)
			fmt.Fprintf(&out, "### Line %d: %s\n\n", finding.Line, finding.Message)
			out.WriteString(prompt.CodeBlock)
			out.WriteString("\n\n")
			out.WriteString(prompt.Instructions)
			out.WriteString("\n\n")
		}
	}

	out.WriteString("## Verification\n\n")
	out.WriteString("After applying the fixes:\n\n")
	out.WriteString("```bash\n")
	fmt.Fprintf(&out, "vibeguard verify %s\n", absPath)
	out.WriteString("```\n")

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(out.String()), 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("fix guide written to %s\n", outputFile)
		return nil
	}

	fmt.Print(out.String())
	return nil
}

type verifyReport struct {
	SchemaVersion string               `json:"schema_version"`
	OK            bool                 `json:"ok"`
	Root          string               `json:"root"`
	Remaining     []output.JSONFinding `json:"remaining"`
	Errors        []scanner.FileError  `json:"errors,omitempty"`
}

func runVerify(cmd *cobra.Command, args []string) error {
	absPath, err := existingPath(args[0])
	if err != nil {
		return err
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	applyFlagOverrides(cfg)

	result, err := scanner.New(cfg).Scan(absPath)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	clean := len(result.Findings) == 0 && result.ErrorCount() == 0

	if verifyJSON {
		report := verifyReport{
			SchemaVersion: output.SchemaVersion,
			OK:            clean,
			Root:          filepath.ToSlash(absPath),
			Remaining:     output.BuildFindings(result),
			Errors:        result.FileErrors,
		}
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to encode verification report: %w", err)
		}
		fmt.Println(string(data))
	} else {
		if clean {
			fmt.Printf("all checks passed in %s\n", absPath)
		} else {
			fmt.Printf("%d finding(s) remaining in %s\n", len(result.Findings), absPath)
			for _, f := range result.Findings {
				fmt.Printf("  %s:%d [%s] %s\n", f.File, f.Line, f.RuleID, f.Message)
			}
		}
		for _, failure := range result.FileErrors {
			fmt.Fprintf(os.Stderr, "  unreadable %s: %s\n", failure.File, failure.Message)
		}
	}

	if result.ErrorCount() > 0 {
		return fmt.Errorf("verification incomplete: %d file(s) could not be read", result.ErrorCount())
	}

	if len(result.Findings) > 0 {
		return &policyError{message: fmt.Sprintf("%d finding(s) remaining", len(result.Findings))}
	}

	return nil
}

func runSBOM(cmd *cobra.Command, args []string) error {
	absPath, err := existingPath(args[0])
	if err != nil {
		return err
	}

	sbom := supply.BuildSBOM(absPath, version, noTimestamp)
	data, err := sbom.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to encode SBOM: %w", err)
	}

	data = append(data, '\n')
	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write SBOM: %w", err)
		}
		fmt.Printf("%d component(s) written to %s\n", len(sbom.Components), outputFile)
		return nil
	}

	fmt.Print(string(data))
	return nil
}

func runPluginList(cmd *cobra.Command, args []string) error {
	files, err := rules.NewPluginLoader(rules.GetProjectPluginDir()).ListRules()
	if err != nil {
		return err
	}

	if len(files) == 0 {
		fmt.Println("no custom rules installed")
		fmt.Println("create one with: vibeguard plugin create <id> <name> <pattern>")
		return nil
	}

	fmt.Printf("custom rules (%d)\n\n", len(files))
	for _, f := range files {
		fmt.Printf("  %s\n", f)
	}

	return nil
}

func runPluginInit(cmd *cobra.Command, args []string) error {
	if err := rules.NewPluginLoader(rules.GetProjectPluginDir()).InitDir(); err != nil {
		return err
	}

	fmt.Println("plugin directory initialized at .vibeguard/rules/")
	return nil
}

func runPluginDelete(cmd *cobra.Command, args []string) error {
	if err := rules.NewPluginLoader(rules.GetProjectPluginDir()).DeleteRule(args[0]); err != nil {
		return err
	}

	fmt.Printf("deleted rule %s\n", args[0])
	return nil
}

func runPluginCreate(cmd *cobra.Command, args []string) error {
	id := args[0]
	name := args[1]
	pattern := args[2]

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	loader := rules.NewPluginLoader(rules.GetProjectPluginDir())
	if err := loader.InitDir(); err != nil {
		return err
	}

	rule := &rules.Rule{
		ID:          strings.ToUpper(id),
		Name:        name,
		Description: fmt.Sprintf("Custom rule: %s", name),
		Severity:    rules.SeverityWarning,
		Pattern:     compiled,
		Fix:         pluginFix,
		Tags:        []string{"custom"},
	}

	if err := loader.SaveRule(rule); err != nil {
		return err
	}

	fmt.Printf("created rule %s\n", rule.ID)
	fmt.Printf("pattern: %s\n", pattern)
	fmt.Printf("file: .vibeguard/rules/%s.json\n", strings.ToLower(id))
	return nil
}

func sortedFiles(byFile map[string][]rules.Finding) []string {
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}

func main() {
	err := rootCmd.Execute()
	if err == nil {
		return
	}

	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		os.Exit(coded.ExitCode())
	}

	os.Exit(exitFailure)
}
