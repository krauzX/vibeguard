package analyzer

import "github.com/KrauzX/vibeguard/pkg/rules"

type Language = rules.Language
type Severity = rules.Severity
type Finding = rules.Finding

type FileContext struct {
	Path     string
	Content  []byte
	Language Language
	AST      interface{}
}

type Analyzer interface {
	Name() string
	Analyze(ctx *FileContext) ([]Finding, error)
	SupportedLanguages() []Language
}
