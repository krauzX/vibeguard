package ast

import (
	"go/ast"
	"go/token"

	"github.com/KrauzX/vibeguard/pkg/analyzer"
)

var syncTypes = map[string]bool{
	"sync.WaitGroup": true,
	"errgroup.Group": true,
}

func unsynchronizedGoroutines(fset *token.FileSet, path string, file *ast.File) []analyzer.Finding {
	rule := ruleByID(RuleUnsynchronizedGo)
	fields := structSyncFields(file)

	var findings []analyzer.Finding
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || coordinates(fn, fields) {
			continue
		}
		for _, launch := range goroutines(fn.Body) {
			findings = append(findings, newFinding(rule, fset, path, launch, launchLabel(launch)))
		}
	}

	return findings
}

func coordinates(fn *ast.FuncDecl, fields map[string]bool) bool {
	groups := syncValues(fn)
	found := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.SendStmt, *ast.SelectStmt:
			found = true
		case *ast.UnaryExpr:
			found = node.Op == token.ARROW
		case *ast.CallExpr:
			if callee, ok := node.Fun.(*ast.Ident); ok && callee.Name == "close" {
				found = true
			}
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && isSyncValue(sel.X, groups, fields) {
				found = true
			}
		}
		return true
	})

	return found
}

func syncValues(fn *ast.FuncDecl) map[string]bool {
	names := make(map[string]bool)

	add := func(list *ast.FieldList) {
		if list == nil {
			return
		}
		for _, field := range list.List {
			if !syncTypes[typeName(field.Type)] {
				continue
			}
			for _, name := range field.Names {
				names[name.Name] = true
			}
		}
	}

	add(fn.Type.Params)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			if syncTypes[typeName(node.Type)] {
				for _, name := range node.Names {
					names[name.Name] = true
				}
			}
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				name, ok := lhs.(*ast.Ident)
				if ok && syncTypes[valueType(node.Rhs[i])] {
					names[name.Name] = true
				}
			}
		}
		return true
	})

	return names
}

func structSyncFields(file *ast.File) map[string]bool {
	fields := make(map[string]bool)

	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range structType.Fields.List {
			if !syncTypes[typeName(field.Type)] {
				continue
			}
			for _, name := range field.Names {
				fields[name.Name] = true
			}
		}
		return true
	})

	return fields
}

func isSyncValue(expr ast.Expr, groups, fields map[string]bool) bool {
	switch value := expr.(type) {
	case *ast.Ident:
		return groups[value.Name]
	case *ast.SelectorExpr:
		return fields[value.Sel.Name]
	}
	return false
}

func goroutines(body *ast.BlockStmt) []*ast.GoStmt {
	var launches []*ast.GoStmt

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.GoStmt:
			launches = append(launches, node)
			return false
		}
		return true
	})

	return launches
}

func launchLabel(launch *ast.GoStmt) string {
	if _, ok := launch.Call.Fun.(*ast.FuncLit); ok {
		return "go func(){...}()"
	}
	return "go " + callLabel(launch.Call)
}
