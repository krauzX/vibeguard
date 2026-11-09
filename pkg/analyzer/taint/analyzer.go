package taint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/KrauzX/vibeguard/pkg/analyzer"
	"github.com/KrauzX/vibeguard/pkg/rules"
)

const (
	RuleSQLInjection     = "TAINT-001"
	RuleCommandInjection = "TAINT-002"
	RulePathTraversal    = "TAINT-003"
	RuleSSRF             = "TAINT-004"
)

// Analyzer follows values from request input to the calls that consume them.
type Analyzer struct{}

func New() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Name() string {
	return "taint"
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
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		findings = append(findings, functionFindings(fset, ctx.Path, fn)...)
	}

	return findings, nil
}

// functionFindings taints a function to a fixpoint, then reports reached sinks.
func functionFindings(fset *token.FileSet, filePath string, fn *ast.FuncDecl) []analyzer.Finding {
	tainted := make(map[string]bool)
	for pass := 0; pass < 4; pass++ {
		changed := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			names, values := assignment(n)
			if len(names) == 0 || !anyTainted(values, tainted) {
				return true
			}
			for _, name := range names {
				if !tainted[name] {
					tainted[name] = true
					changed = true
				}
			}
			return true
		})
		if !changed {
			break
		}
	}

	if len(tainted) == 0 {
		return nil
	}

	var findings []analyzer.Finding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sink, ok := sinkFor(call)
		if !ok {
			return true
		}

		variable := reachedBy(call.Args, tainted)
		if variable == "" {
			return true
		}

		pos := fset.Position(call.Pos())
		end := fset.Position(call.End())
		findings = append(findings, analyzer.Finding{
			RuleID:    sink.ruleID,
			Severity:  rules.SeverityCritical,
			File:      filePath,
			Line:      pos.Line,
			Column:    pos.Column,
			EndLine:   end.Line,
			EndColumn: end.Column,
			Message:   fmt.Sprintf("%s: request input reaches %s via %s", sink.label, sink.target, variable),
			Code:      exprText(call),
			CWE:       sink.cwe,
		})
		return true
	})

	return findings
}

func assignment(n ast.Node) ([]string, []ast.Expr) {
	switch node := n.(type) {
	case *ast.AssignStmt:
		var names []string
		for _, lhs := range node.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
				names = append(names, ident.Name)
			}
		}
		return names, node.Rhs
	case *ast.ValueSpec:
		var names []string
		for _, ident := range node.Names {
			names = append(names, ident.Name)
		}
		return names, node.Values
	}
	return nil, nil
}

func anyTainted(exprs []ast.Expr, tainted map[string]bool) bool {
	for _, expr := range exprs {
		if isTainted(expr, tainted) {
			return true
		}
	}
	return false
}

func isTainted(expr ast.Expr, tainted map[string]bool) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return tainted[e.Name]
	case *ast.ParenExpr:
		return isTainted(e.X, tainted)
	case *ast.IndexExpr:
		if base := exprText(e.X); base == "os.Args" || strings.HasPrefix(base, "flag.Args") {
			return true
		}
		return isTainted(e.X, tainted)
	case *ast.SliceExpr:
		return isTainted(e.X, tainted)
	case *ast.SelectorExpr:
		return isTainted(e.X, tainted)
	case *ast.StarExpr:
		return isTainted(e.X, tainted)
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (isTainted(e.X, tainted) || isTainted(e.Y, tainted))
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if isTainted(elt, tainted) {
				return true
			}
		}
		return false
	case *ast.CallExpr:
		return isTaintedCall(e, tainted)
	}
	return false
}

// isTaintedCall treats a call as pass-through unless it sanitises the value.
func isTaintedCall(call *ast.CallExpr, tainted map[string]bool) bool {
	chain := exprText(call.Fun)
	if sanitizer(chain) {
		return false
	}
	if isSource(call) {
		return true
	}
	return anyTainted(call.Args, tainted)
}

func sanitizer(chain string) bool {
	switch chain {
	case "strconv.Atoi", "strconv.ParseInt", "strconv.ParseUint", "strconv.ParseFloat", "strconv.ParseBool":
		return true
	}
	return false
}

type sink struct {
	ruleID string
	cwe    string
	label  string
	target string
}

var sqlSinks = map[string]bool{
	"Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true,
	"Exec": true, "ExecContext": true, "Raw": true,
}

func sinkFor(call *ast.CallExpr) (sink, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return sink{}, false
	}

	chain := exprText(sel.X)
	name := sel.Sel.Name

	if sqlSinks[name] {
		return sink{RuleSQLInjection, "CWE-89", "SQL injection", chain + "." + name}, true
	}

	if chain == "exec" && name == "Command" {
		return sink{RuleCommandInjection, "CWE-78", "command injection", "exec.Command"}, true
	}

	if chain == "os" {
		switch name {
		case "Open", "OpenFile", "ReadFile", "ReadDir", "Create", "Remove", "RemoveAll", "Stat":
			return sink{RulePathTraversal, "CWE-22", "path traversal", "os." + name}, true
		}
	}

	if chain == "http" {
		switch name {
		case "Get", "Post", "Head", "NewRequest", "NewRequestWithContext":
			return sink{RuleSSRF, "CWE-918", "server-side request forgery", "http." + name}, true
		}
	}

	return sink{}, false
}

func reachedBy(args []ast.Expr, tainted map[string]bool) string {
	var found string
	for _, arg := range args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if found != "" {
				return false
			}
			if ident, ok := n.(*ast.Ident); ok && tainted[ident.Name] {
				found = ident.Name
				return false
			}
			return true
		})
		if found != "" {
			break
		}
	}
	return found
}

// isSource reports request, argument or stdin input.
func isSource(call *ast.CallExpr) bool {
	chain := exprText(call.Fun)

	switch {
	case strings.HasSuffix(chain, ".FormValue"), strings.HasSuffix(chain, ".PostFormValue"):
		return true
	case strings.HasSuffix(chain, ".Get") && strings.Contains(chain, "URL.Query"):
		return true
	case strings.HasSuffix(chain, ".Get") && strings.Contains(chain, "Header"):
		return true
	case strings.HasSuffix(chain, "URL.Query"), strings.HasSuffix(chain, ".Form"):
		return true
	case chain == "io.ReadAll", chain == "ioutil.ReadAll":
		return anyContains(call.Args, "Body")
	case strings.HasSuffix(chain, ".ReadString"), strings.HasSuffix(chain, ".ReadBytes"):
		return anyContains(call.Args, "Stdin")
	case chain == "bufio.NewReader":
		return anyContains(call.Args, "Stdin")
	case chain == "flag.Arg", chain == "flag.Args":
		return true
	}

	return false
}

func anyContains(exprs []ast.Expr, needle string) bool {
	for _, expr := range exprs {
		if strings.Contains(exprText(expr), needle) {
			return true
		}
	}
	return false
}

// exprText rebuilds a readable form of an expression.
func exprText(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.BasicLit:
		return e.Value
	case *ast.SelectorExpr:
		return exprText(e.X) + "." + e.Sel.Name
	case *ast.CallExpr:
		return exprText(e.Fun) + "(" + argText(e.Args) + ")"
	case *ast.IndexExpr:
		return exprText(e.X) + "[" + exprText(e.Index) + "]"
	case *ast.ParenExpr:
		return "(" + exprText(e.X) + ")"
	case *ast.BinaryExpr:
		return exprText(e.X) + " " + e.Op.String() + " " + exprText(e.Y)
	case *ast.StarExpr:
		return "*" + exprText(e.X)
	case *ast.UnaryExpr:
		return e.Op.String() + exprText(e.X)
	}
	return ""
}

func argText(args []ast.Expr) string {
	if len(args) == 0 {
		return ""
	}

	parts := make([]string, 0, len(args))
	for _, arg := range args {
		text := exprText(arg)
		if len(text) > 40 {
			text = text[:40] + "..."
		}
		parts = append(parts, text)
	}

	return strings.Join(parts, ", ")
}
