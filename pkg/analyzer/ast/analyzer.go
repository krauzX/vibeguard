package ast

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/KrauzX/vibeguard/pkg/analyzer"
	"github.com/KrauzX/vibeguard/pkg/rules"
)

type Analyzer struct{}

func New() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Name() string {
	return "ast-go"
}

func (a *Analyzer) SupportedLanguages() []analyzer.Language {
	return []analyzer.Language{rules.LanguageGo}
}

func (a *Analyzer) Analyze(ctx *analyzer.FileContext) ([]analyzer.Finding, error) {
	if ctx.Language != rules.LanguageGo {
		return nil, nil
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, ctx.Path, ctx.Content, parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	var findings []analyzer.Finding
	findings = append(findings, ignoredErrors(fset, ctx.Path, file)...)
	findings = append(findings, unsynchronizedGoroutines(fset, ctx.Path, file)...)
	return findings, nil
}

func newFinding(rule *ruleInfo, fset *token.FileSet, path string, node ast.Node, code string) analyzer.Finding {
	pos := fset.Position(node.Pos())
	end := fset.Position(node.End())

	return analyzer.Finding{
		RuleID:    string(rule.ID),
		Severity:  rule.Severity,
		File:      path,
		Line:      pos.Line,
		Column:    pos.Column,
		EndLine:   end.Line,
		EndColumn: end.Column,
		Message:   rule.Description,
		Code:      code,
		CWE:       rule.CWE,
	}
}

func callLabel(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name + "(...)"
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok {
			return x.Name + "." + fn.Sel.Name + "(...)"
		}
		return fn.Sel.Name + "(...)"
	}
	return "(...)"
}
