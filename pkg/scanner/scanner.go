package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KrauzX/vibeguard/pkg/analyzer"
	goast "github.com/KrauzX/vibeguard/pkg/analyzer/ast"
	"github.com/KrauzX/vibeguard/pkg/analyzer/supply"
	"github.com/KrauzX/vibeguard/pkg/analyzer/taint"
	"github.com/KrauzX/vibeguard/pkg/config"
	"github.com/KrauzX/vibeguard/pkg/ignore"
	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/syntax"
)

type Scanner struct {
	cfg          *config.Config
	rules        []*rules.Rule
	excludePaths map[string]bool
	includeExts  map[string]bool
	wd           string
	langRules    sync.Map
	analyzers    *analyzer.Registry
}

func New(cfg *config.Config) *Scanner {
	langRules := buildLanguageRules(cfg)
	if custom, err := rules.NewPluginLoader(rules.GetProjectPluginDir()).LoadAll(); err == nil {
		langRules = append(langRules, custom...)
	}

	wd, _ := os.Getwd()

	return &Scanner{
		cfg:          cfg,
		rules:        langRules,
		excludePaths: cfg.GetExcludePaths(),
		includeExts:  cfg.GetIncludeExtensions(),
		wd:           wd,
		analyzers:    buildAnalyzers(),
	}
}

func buildAnalyzers() *analyzer.Registry {
	registry := analyzer.NewRegistry()
	registry.Register("go-ast", goast.New())
	registry.Register("taint", taint.New())
	return registry
}

func buildLanguageRules(cfg *config.Config) []*rules.Rule {
	enabled := map[rules.Language]bool{
		rules.LanguageGo:     cfg.Rules.EnableGo,
		rules.LanguagePython: cfg.Rules.EnablePython,
		rules.LanguageJS:     cfg.Rules.EnableJS,
		rules.LanguageTS:     cfg.Rules.EnableJS,
		rules.LanguageJava:   cfg.Rules.EnableJava,
		rules.LanguageShell:  cfg.Rules.EnableShell,
		rules.LanguageRuby:   cfg.Rules.EnableRuby,
		rules.LanguagePHP:    cfg.Rules.EnablePHP,
	}

	allRules := rules.GetRules()
	filtered := make([]*rules.Rule, 0, len(allRules))

	for _, r := range allRules {
		if len(r.Languages) == 0 {
			filtered = append(filtered, r)
			continue
		}
		for _, lang := range r.Languages {
			if enabled[lang] {
				filtered = append(filtered, r)
				break
			}
		}
	}

	return filtered
}

func (s *Scanner) Scan(rootPath string) (*Result, error) {
	start := time.Now()
	workerCount := s.cfg.WorkerCount()

	fileCh := make(chan string, workerCount*2)
	findingsCh := make(chan []rules.Finding, workerCount*2)

	var filesScanned atomic.Int64
	var filesSkipped atomic.Int64
	var errorsSkipped atomic.Int64

	failures := make(chan FileError, workerCount)
	var failed []FileError
	var failedMu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range failures {
			failedMu.Lock()
			failed = append(failed, msg)
			failedMu.Unlock()
		}
	}()

	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(fileCh, findingsCh, &filesScanned, &errorsSkipped, failures)
		}()
	}

	matcher := ignore.New(rootPath)
	if !s.cfg.Scanner.RespectGitignore {
		matcher = nil
	}

	go func() {
		s.walkFiles(rootPath, matcher, fileCh, &filesSkipped)
		close(fileCh)
	}()

	go func() {
		wg.Wait()
		close(findingsCh)
		close(failures)
	}()

	var allFindings []rules.Finding
	for f := range findingsCh {
		allFindings = append(allFindings, f...)
	}

	<-done
	sort.Slice(failed, func(i, j int) bool { return failed[i].File < failed[j].File })

	SortFindings(allFindings)

	result := &Result{
		Root:         rootPath,
		Findings:     allFindings,
		FilesScanned: filesScanned.Load(),
		FilesSkipped: filesSkipped.Load(),
		FileErrors:   failed,
		Duration:     time.Since(start),
	}

	if s.cfg.Dependencies.CheckVulnerabilities {
		findings, info := s.checkDependencies(rootPath)
		result.Findings = append(result.Findings, findings...)
		SortFindings(result.Findings)
		result.DependencyInfo = info
	}

	if s.cfg.Baseline.Enabled {
		result.Findings, result.Suppressed = s.applyBaseline(result.Findings, result.Root)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// SortFindings keeps reports stable between runs.
func SortFindings(findings []rules.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Message < b.Message
	})
}

func (s *Scanner) worker(fileCh <-chan string, findingsCh chan<- []rules.Finding, filesScanned, errorsSkipped *atomic.Int64, failures chan<- FileError) {
	for path := range fileCh {
		findings, err := s.scanFile(path)
		if len(findings) > 0 {
			findingsCh <- findings
		}
		if err == nil {
			filesScanned.Add(1)
			continue
		}
		if errors.Is(err, errBinaryFile) {
			continue
		}
		errorsSkipped.Add(1)
		failures <- FileError{File: path, Message: err.Error()}
	}
}

func (s *Scanner) scanFile(path string) ([]rules.Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	maxSize := s.cfg.Scanner.MaxFileSize
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file exceeds %d byte limit", maxSize)
	}

	bufp := bufferPool.Get().(*[]byte)
	content, err := readInto(file, (*bufp)[:0], info.Size(), maxSize)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cap(content) <= pooledBufferLimit {
			*bufp = content
			bufferPool.Put(bufp)
		}
	}()

	return s.scanContent(path, content)
}

// ScanContent scans a buffer that is already in memory.
func (s *Scanner) ScanContent(name string, content []byte) *Result {
	start := time.Now()
	result := &Result{Root: s.wd}

	switch {
	case int64(len(content)) > s.cfg.Scanner.MaxFileSize:
		result.FileErrors = []FileError{{File: name, Message: fmt.Sprintf("file exceeds %d byte limit", s.cfg.Scanner.MaxFileSize)}}
	case s.cfg.Scanner.SkipBinary && bytes.IndexByte(content, 0) >= 0:
		return result
	default:
		result.Findings, _ = s.scanContent(name, content)
		result.FilesScanned = 1
	}

	SortFindings(result.Findings)
	if s.cfg.Baseline.Enabled {
		result.Findings, result.Suppressed = s.applyBaseline(result.Findings, result.Root)
	}
	result.Duration = time.Since(start)

	return result
}

func (s *Scanner) scanContent(path string, content []byte) ([]rules.Finding, error) {
	if s.cfg.Scanner.SkipBinary && bytes.IndexByte(content, 0) >= 0 {
		return nil, errBinaryFile
	}

	active := s.activeRules(path)
	if len(active) == 0 {
		return nil, nil
	}

	folded, foldBuf := foldFor(active, content)
	if foldBuf != nil {
		defer func() {
			if cap(folded) <= pooledBufferLimit {
				*foldBuf = folded
				foldPool.Put(foldBuf)
			}
		}()
	}

	candidates := buildCandidates(active, content, folded)

	var findings []rules.Finding
	seen := make(map[string]bool, 2)
	lineNum := 1

	for start := 0; start < len(content); {
		end := bytes.IndexByte(content[start:], '\n')
		var line []byte
		if end < 0 {
			line = content[start:]
			start = len(content)
		} else {
			line = content[start : start+end]
			start += end + 1
		}

		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}

		if len(line) > 0 {
			for i := range candidates {
				c := &candidates[i]
				if seen[c.rule.ID] || !c.hit(lineNum) {
					continue
				}
				if f := rules.MatchLineBytes(c.rule, line, lineNum, path, s.cfg.Rules.MaxLineLength); f != nil {
					findings = append(findings, *f)
					if c.rule.OncePerFile {
						seen[c.rule.ID] = true
					}
				}
			}
		}

		lineNum++
	}

	findings = syntax.Filter(path, content, findings)
	findings = append(findings, s.runAnalyzers(path, content)...)
	attachSource(findings, content)

	return findings, nil
}

// attachSource stores full source so fingerprints ignore snippet truncation.
func attachSource(findings []rules.Finding, content []byte) {
	if len(findings) == 0 {
		return
	}

	lines := strings.Split(string(content), "\n")
	for i := range findings {
		f := &findings[i]
		start := f.Line - 1
		end := f.EndLine
		if end < f.Line {
			end = f.Line
		}
		if start < 0 || start >= len(lines) || end > len(lines) {
			continue
		}
		f.Source = strings.Join(lines[start:end], "\n")
	}
}

func (s *Scanner) runAnalyzers(path string, content []byte) []rules.Finding {
	lang := rules.LanguageForExt(filepath.Ext(path))
	if s.analyzers == nil || lang == rules.LanguageAny {
		return nil
	}

	return s.analyzers.Analyze(&analyzer.FileContext{Path: path, Content: content, Language: lang})
}

func (s *Scanner) activeRules(path string) []*rules.Rule {
	lang := rules.LanguageForExt(filepath.Ext(path))

	cached, ok := s.langRules.Load(lang)
	if !ok {
		cached, _ = s.langRules.LoadOrStore(lang, rules.LanguageRules(s.rules, lang))
	}

	base := cached.([]*rules.Rule)
	extra := rules.PathRules(s.rules, lang, path)
	if len(extra) == 0 {
		return base
	}

	merged := make([]*rules.Rule, 0, len(base)+len(extra))
	merged = append(merged, base...)
	return append(merged, extra...)
}

func (s *Scanner) checkDependencies(rootPath string) ([]rules.Finding, *DependencyInfo) {
	info := &DependencyInfo{}

	if graph, err := analyzer.BuildImportGraph(rootPath); err == nil {
		info.Graph = graph
		info.Cycles = graph.FindCycles()
		info.Orphans = graph.GetOrphanPackages()
		info.Stats = graph.GetStats()
	}

	if s.cfg.Dependencies.Offline {
		info.Note = "offline mode: advisories not checked"
		return nil, info
	}

	ctx := context.Background()
	if timeout := s.cfg.Dependencies.Timeout; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	findings, deps, err := supply.Check(ctx, rootPath, supply.NewClient())
	info.Packages = deps
	info.Vulnerable = len(findings)
	if err != nil {
		info.Note = "advisory lookup incomplete: " + err.Error()
	}

	return findings, info
}
