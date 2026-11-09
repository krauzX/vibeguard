package rules

import (
	"regexp"
	"sort"
	"strings"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) Emoji() string {
	switch s {
	case SeverityInfo:
		return "💡"
	case SeverityWarning:
		return "⚠️"
	case SeverityCritical:
		return "🔴"
	default:
		return "❓"
	}
}

type Language string

const (
	LanguageAny       Language = ""
	LanguageGo        Language = "go"
	LanguagePython    Language = "python"
	LanguageJS        Language = "javascript"
	LanguageTS        Language = "typescript"
	LanguageJava      Language = "java"
	LanguageRuby      Language = "ruby"
	LanguagePHP       Language = "php"
	LanguageShell     Language = "shell"
	LanguageSQL       Language = "sql"
	LanguageYAML      Language = "yaml"
	LanguageTerraform Language = "terraform"
)

type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    Severity
	Languages   []Language
	Pattern     *regexp.Regexp
	PathPattern *regexp.Regexp
	OncePerFile bool
	CWE         string
	Fix         string
	Tags        []string
	ReportOnly  bool

	Anchors     []string
	anchorBytes [][]byte
	foldAnchors bool
}

type Finding struct {
	RuleID    string
	Severity  Severity
	File      string
	Line      int
	Column    int
	EndLine   int
	EndColumn int
	Message   string
	Code      string
	CWE       string
	Fix       string
	Source    string
}

var extToLang = map[string]Language{
	".go":   LanguageGo,
	".py":   LanguagePython,
	".js":   LanguageJS,
	".jsx":  LanguageJS,
	".ts":   LanguageTS,
	".tsx":  LanguageTS,
	".java": LanguageJava,
	".rb":   LanguageRuby,
	".php":  LanguagePHP,
	".sh":   LanguageShell,
	".bash": LanguageShell,
	".sql":  LanguageSQL,
	".yaml": LanguageYAML,
	".yml":  LanguageYAML,
	".tf":   LanguageTerraform,
	".hcl":  LanguageTerraform,
}

func LanguageForExt(ext string) Language {
	if lang, ok := extToLang[strings.ToLower(ext)]; ok {
		return lang
	}
	return LanguageAny
}

var allRules []*Rule

func init() {
	allRules = buildRules()
	for _, r := range allRules {
		applyAnchors(r)
	}
	sort.Slice(allRules, func(i, j int) bool {
		if allRules[i].Severity != allRules[j].Severity {
			return allRules[i].Severity > allRules[j].Severity
		}
		return allRules[i].ID < allRules[j].ID
	})
}

func GetRules() []*Rule {
	return allRules
}

func langMatches(rule *Rule, lang Language) bool {
	if len(rule.Languages) == 0 {
		return true
	}
	for _, rl := range rule.Languages {
		if rl == lang || rl == LanguageAny {
			return true
		}
	}
	return false
}

// LanguageRules returns the rules for a language that do not depend on the path.
func LanguageRules(all []*Rule, lang Language) []*Rule {
	matched := make([]*Rule, 0, len(all))
	for _, rule := range all {
		if rule.PathPattern != nil || rule.ReportOnly || !langMatches(rule, lang) {
			continue
		}
		matched = append(matched, rule)
	}
	return matched
}

// PathRules returns the rules whose path pattern accepts filename.
func PathRules(all []*Rule, lang Language, filename string) []*Rule {
	var matched []*Rule
	path := strings.ReplaceAll(filename, "\\", "/")

	for _, rule := range all {
		if rule.PathPattern == nil || !langMatches(rule, lang) {
			continue
		}
		if rule.PathPattern.MatchString(path) {
			matched = append(matched, rule)
		}
	}

	return matched
}

func buildRules() []*Rule {
	groups := [][]*Rule{
		secretRules(),
		injectionRules(),
		webRules(),
		configRules(),
		qualityRules(),
		languageRules(),
		supplyRules(),
	}

	var all []*Rule
	for _, group := range groups {
		all = append(all, group...)
	}
	return all
}

func GetRuleByID(id string) *Rule {
	for _, r := range allRules {
		if r.ID == id {
			return r
		}
	}
	return nil
}
