package ast

import (
	"go/ast"
	"go/token"

	"github.com/KrauzX/vibeguard/pkg/analyzer"
)

type callIndex struct {
	funcs   map[string]bool
	methods map[string]bool
	vars    map[string]string
}

func indexCalls(file *ast.File) *callIndex {
	idx := &callIndex{
		funcs:   make(map[string]bool),
		methods: make(map[string]bool),
		vars:    make(map[string]string),
	}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if !returnsError(d.Type) {
				continue
			}
			if d.Recv == nil {
				idx.funcs[d.Name.Name] = true
				continue
			}
			if recv := d.Recv.List; len(recv) > 0 {
				if name := typeName(recv[0].Type); name != "" {
					idx.methods[name+"."+d.Name.Name] = true
				}
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || value.Type == nil {
					continue
				}
				for _, name := range value.Names {
					idx.vars[name.Name] = typeName(value.Type)
				}
			}
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Field:
			for _, name := range node.Names {
				if typ := typeName(node.Type); typ != "" {
					idx.vars[name.Name] = typ
				}
			}
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				name, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				if typ := valueType(node.Rhs[i]); typ != "" {
					idx.vars[name.Name] = typ
				}
			}
		}
		return true
	})

	return idx
}

func (idx *callIndex) returnsError(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return idx.funcs[fn.Name]
	case *ast.SelectorExpr:
		receiver, ok := fn.X.(*ast.Ident)
		if !ok {
			return false
		}
		typ, known := idx.vars[receiver.Name]
		return known && idx.methods[typ+"."+fn.Sel.Name]
	}
	return false
}

func ignoredErrors(fset *token.FileSet, path string, file *ast.File) []analyzer.Finding {
	rule := ruleByID(RuleIgnoredError)
	idx := indexCalls(file)

	var findings []analyzer.Finding
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ExprStmt:
			call, ok := node.X.(*ast.CallExpr)
			if ok && idx.returnsError(call) {
				findings = append(findings, newFinding(rule, fset, path, call, callLabel(call)))
			}
		case *ast.AssignStmt:
			if !discardsEverything(node) {
				return true
			}
			call, ok := node.Rhs[0].(*ast.CallExpr)
			if ok && idx.returnsError(call) {
				findings = append(findings, newFinding(rule, fset, path, call, callLabel(call)))
			}
		}
		return true
	})

	return findings
}

func discardsEverything(assign *ast.AssignStmt) bool {
	if len(assign.Rhs) != 1 {
		return false
	}
	if _, ok := assign.Rhs[0].(*ast.CallExpr); !ok {
		return false
	}
	for _, lhs := range assign.Lhs {
		name, ok := lhs.(*ast.Ident)
		if !ok || name.Name != "_" {
			return false
		}
	}
	return true
}

func returnsError(fn *ast.FuncType) bool {
	if fn.Results == nil || len(fn.Results.List) == 0 {
		return false
	}
	last := fn.Results.List[len(fn.Results.List)-1]
	return typeName(last.Type) == "error"
}

func typeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeName(t.X)
	case *ast.SelectorExpr:
		if pkg, ok := t.X.(*ast.Ident); ok {
			return pkg.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	}
	return ""
}

func valueType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.UnaryExpr:
		return valueType(t.X)
	case *ast.CompositeLit:
		return typeName(t.Type)
	case *ast.CallExpr:
		return typeName(t.Fun)
	case *ast.ParenExpr:
		return valueType(t.X)
	}
	return ""
}
