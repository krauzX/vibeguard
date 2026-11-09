package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ImportGraph maps packages to the packages they import.
type ImportGraph struct {
	Nodes  map[string]*PackageNode
	Edges  []Edge
	Module string
}

// PackageNode holds the files, imports and inbound references of one package.
type PackageNode struct {
	Path       string
	Name       string
	Main       bool
	Files      []string
	Imports    []string
	ImportedBy []string
	LineCount  int
}

type Edge struct {
	From string
	To   string
}

type GraphStats struct {
	TotalPackages     int
	TotalEdges        int
	TotalFiles        int
	TotalLines        int
	AvgImportsPerPkg  float64
	MaxImports        int
	CircularDepsCount int
}

// BuildImportGraph keys local packages by directory so module imports resolve.
func BuildImportGraph(rootPath string) (*ImportGraph, error) {
	graph := &ImportGraph{
		Nodes:  make(map[string]*PackageNode),
		Edges:  []Edge{},
		Module: readModulePath(rootPath),
	}

	fset := token.NewFileSet()
	root := filepath.Clean(rootPath)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if path == root {
				return nil
			}
			if skipTree[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil || isGeneratedFile(file) {
			return nil
		}

		dir, err := packageDir(root, path)
		if err != nil {
			return nil
		}

		node := graph.node(dir)
		if node.Name == "" {
			node.Name = file.Name.Name
		}
		node.Main = node.Main || file.Name.Name == "main"
		node.Files = append(node.Files, path)
		node.LineCount += countLines(path)

		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			target, ok := graph.resolve(importPath)
			if !ok || contains(node.Imports, target) {
				continue
			}

			node.Imports = append(node.Imports, target)
			graph.Edges = append(graph.Edges, Edge{From: dir, To: target})

			imported := graph.node(target)
			if !contains(imported.ImportedBy, dir) {
				imported.ImportedBy = append(imported.ImportedBy, dir)
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to build import graph: %w", err)
	}

	return graph, nil
}

var skipTree = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true,
	"venv": true, "__pycache__": true, "testdata": true,
}

func (g *ImportGraph) node(key string) *PackageNode {
	node, ok := g.Nodes[key]
	if !ok {
		node = &PackageNode{Path: key, Files: []string{}, Imports: []string{}, ImportedBy: []string{}}
		g.Nodes[key] = node
	}
	return node
}

func (g *ImportGraph) resolve(importPath string) (string, bool) {
	if g.Module != "" {
		if importPath == g.Module {
			return ".", true
		}
		if strings.HasPrefix(importPath, g.Module+"/") {
			return strings.TrimPrefix(importPath, g.Module+"/"), true
		}
	}

	first, _, _ := strings.Cut(importPath, "/")
	if !strings.Contains(first, ".") {
		return "", false
	}

	return importPath, true
}

func packageDir(root, path string) (string, error) {
	rel, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil {
		return "", err
	}

	rel = filepath.ToSlash(rel)
	if rel == "" || rel == "." {
		return ".", nil
	}
	return rel, nil
}

func readModulePath(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1]
		}
	}

	return ""
}

// FindCycles reports import cycles as chains of package paths.
func (g *ImportGraph) FindCycles() [][]string {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)
	cycles := [][]string{}

	var dfs func(node string, path []string)
	dfs = func(node string, path []string) {
		visited[node] = true
		recStack[node] = true
		path = append(path, node)

		if pkg, exists := g.Nodes[node]; exists {
			for _, imp := range pkg.Imports {
				if !visited[imp] {
					dfs(imp, path)
				} else if recStack[imp] {
					idx := 0
					for i, p := range path {
						if p == imp {
							idx = i
							break
						}
					}
					cycle := make([]string, len(path[idx:]))
					copy(cycle, path[idx:])
					cycles = append(cycles, cycle)
				}
			}
		}

		recStack[node] = false
	}

	for node := range g.Nodes {
		if !visited[node] {
			dfs(node, []string{})
		}
	}

	return cycles
}

// GetOrphanPackages lists local packages nothing imports; commands are entries.
func (g *ImportGraph) GetOrphanPackages() []string {
	orphans := []string{}
	for pkg, node := range g.Nodes {
		if len(node.Files) > 0 && len(node.ImportedBy) == 0 && !node.Main {
			orphans = append(orphans, pkg)
		}
	}
	sort.Strings(orphans)
	return orphans
}

func (g *ImportGraph) GetStats() GraphStats {
	stats := GraphStats{TotalEdges: len(g.Edges)}
	totalImports := 0

	for _, node := range g.Nodes {
		if len(node.Files) > 0 {
			stats.TotalPackages++
			stats.TotalFiles += len(node.Files)
			stats.TotalLines += node.LineCount
			importCount := len(node.Imports)
			totalImports += importCount
			if importCount > stats.MaxImports {
				stats.MaxImports = importCount
			}
		}
	}

	if stats.TotalPackages > 0 {
		stats.AvgImportsPerPkg = float64(totalImports) / float64(stats.TotalPackages)
	}

	stats.CircularDepsCount = len(g.FindCycles())

	return stats
}

func isGeneratedFile(file *ast.File) bool {
	for _, comment := range file.Comments {
		text := comment.Text()
		if strings.Contains(text, "Code generated") ||
			strings.Contains(text, "DO NOT EDIT") ||
			strings.Contains(text, "autogenerated") {
			return true
		}
	}
	return false
}

func countLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(data), "\n") + 1
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
