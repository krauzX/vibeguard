package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestBuildImportGraph(t *testing.T) {
	tmpDir := t.TempDir()

	mainGo := `package main

import (
	"fmt"
	"testpkg/utils"
)

func main() {
	fmt.Println("Hello")
	utils.Helper()
}
`

	utilsGo := `package utils

import "fmt"

func Helper() {
	fmt.Println("Helper function")
}
`

	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	utilsDir := filepath.Join(tmpDir, "utils")
	if err := os.MkdirAll(utilsDir, 0755); err != nil {
		t.Fatalf("Failed to create utils dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(utilsDir, "helper.go"), []byte(utilsGo), 0644); err != nil {
		t.Fatalf("Failed to write helper.go: %v", err)
	}

	graph, err := BuildImportGraph(tmpDir)
	if err != nil {
		t.Fatalf("BuildImportGraph failed: %v", err)
	}

	if graph == nil {
		t.Fatal("Expected non-nil graph")
	}

	if len(graph.Nodes) == 0 {
		t.Error("Expected at least one package node")
	}

	mainPkg := graph.Nodes["."]
	if mainPkg == nil {
		t.Fatalf("Expected the root package in the graph, got keys %v", keysOf(graph))
	}
	if len(mainPkg.Files) == 0 || !mainPkg.Main {
		t.Errorf("Expected root package to hold main.go, got %+v", mainPkg)
	}
}

func TestFindCycles(t *testing.T) {
	graph := &ImportGraph{
		Nodes: map[string]*PackageNode{
			"pkgA": {
				Path:    "pkgA",
				Imports: []string{"pkgB"},
			},
			"pkgB": {
				Path:    "pkgB",
				Imports: []string{"pkgC"},
			},
			"pkgC": {
				Path:    "pkgC",
				Imports: []string{"pkgA"}, // Creates cycle
			},
		},
		Edges: []Edge{
			{From: "pkgA", To: "pkgB"},
			{From: "pkgB", To: "pkgC"},
			{From: "pkgC", To: "pkgA"},
		},
	}

	cycles := graph.FindCycles()

	if len(cycles) == 0 {
		t.Error("Expected to find at least one cycle")
	}

	if len(cycles) > 0 {
		cycle := cycles[0]
		if len(cycle) != 3 {
			t.Errorf("Expected cycle length 3, got %d", len(cycle))
		}
	}
}

func TestGetOrphanPackages(t *testing.T) {
	graph := &ImportGraph{
		Nodes: map[string]*PackageNode{
			"main": {
				Path:       "main",
				Main:       true,
				Files:      []string{"main.go"},
				Imports:    []string{"pkgA"},
				ImportedBy: []string{},
			},
			"pkgA": {
				Path:       "pkgA",
				Files:      []string{"a.go"},
				Imports:    []string{},
				ImportedBy: []string{"main"},
			},
			"orphan": {
				Path:       "orphan",
				Files:      []string{"orphan.go"},
				Imports:    []string{},
				ImportedBy: []string{}, // Not imported by anyone
			},
		},
	}

	orphans := graph.GetOrphanPackages()

	if len(orphans) != 1 {
		t.Errorf("Expected 1 orphan package, got %d", len(orphans))
	}

	if len(orphans) > 0 && orphans[0] != "orphan" {
		t.Errorf("Expected orphan package 'orphan', got '%s'", orphans[0])
	}
}

func TestLocalImportsResolveToPackages(t *testing.T) {
	root := t.TempDir()
	writeGo(t, root, "go.mod", "module example.com/app\n\ngo 1.22\n")
	writeGo(t, root, "main.go", "package main\n\nimport \"example.com/app/internal/store\"\n\nfunc main() { store.Open() }\n")
	writeGo(t, root, "internal/store/store.go", "package store\n\nfunc Open() {}\n")

	graph, err := BuildImportGraph(root)
	if err != nil {
		t.Fatal(err)
	}

	store := graph.Nodes["internal/store"]
	if store == nil {
		t.Fatalf("expected the local package keyed by directory, got %v", keysOf(graph))
	}
	if len(store.ImportedBy) != 1 || store.ImportedBy[0] != "." {
		t.Errorf("expected internal/store imported by the root package, got %v", store.ImportedBy)
	}

	if orphans := graph.GetOrphanPackages(); len(orphans) != 0 {
		t.Errorf("expected no orphans, got %v", orphans)
	}
}

func TestLocalCycleIsFound(t *testing.T) {
	root := t.TempDir()
	writeGo(t, root, "go.mod", "module example.com/app\n\ngo 1.22\n")
	writeGo(t, root, "a/a.go", "package a\n\nimport \"example.com/app/b\"\n\nfunc Use() { b.Use() }\n")
	writeGo(t, root, "b/b.go", "package b\n\nimport \"example.com/app/a\"\n\nfunc Use() { a.Use() }\n")

	graph, err := BuildImportGraph(root)
	if err != nil {
		t.Fatal(err)
	}

	if cycles := graph.FindCycles(); len(cycles) == 0 {
		t.Errorf("expected a cycle between a and b, nodes %v", keysOf(graph))
	}
}

func keysOf(graph *ImportGraph) []string {
	keys := make([]string, 0, len(graph.Nodes))
	for key := range graph.Nodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeGo(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGetStats(t *testing.T) {
	graph := &ImportGraph{
		Nodes: map[string]*PackageNode{
			"pkgA": {
				Path:      "pkgA",
				Files:     []string{"a.go"},
				Imports:   []string{"pkgB", "pkgC"},
				LineCount: 100,
			},
			"pkgB": {
				Path:      "pkgB",
				Files:     []string{"b.go"},
				Imports:   []string{"pkgC"},
				LineCount: 50,
			},
			"pkgC": {
				Path:      "pkgC",
				Files:     []string{"c.go"},
				Imports:   []string{},
				LineCount: 75,
			},
		},
		Edges: []Edge{
			{From: "pkgA", To: "pkgB"},
			{From: "pkgA", To: "pkgC"},
			{From: "pkgB", To: "pkgC"},
		},
	}

	stats := graph.GetStats()

	if stats.TotalPackages != 3 {
		t.Errorf("Expected 3 packages, got %d", stats.TotalPackages)
	}

	if stats.TotalFiles != 3 {
		t.Errorf("Expected 3 files, got %d", stats.TotalFiles)
	}

	if stats.TotalLines != 225 {
		t.Errorf("Expected 225 lines, got %d", stats.TotalLines)
	}

	if stats.TotalEdges != 3 {
		t.Errorf("Expected 3 edges, got %d", stats.TotalEdges)
	}

	if stats.MaxImports != 2 {
		t.Errorf("Expected max imports 2, got %d", stats.MaxImports)
	}

	expectedAvg := float64(3) / float64(3) // (2+1+0) / 3
	if stats.AvgImportsPerPkg != expectedAvg {
		t.Errorf("Expected avg imports %.2f, got %.2f", expectedAvg, stats.AvgImportsPerPkg)
	}
}

func BenchmarkBuildImportGraph(b *testing.B) {
	tmpDir := b.TempDir()

	for i := 0; i < 10; i++ {
		content := `package testpkg

import "fmt"

func Test() {
	fmt.Println("test")
}
`
		filename := filepath.Join(tmpDir, fmt.Sprintf("file%d.go", i))
		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			b.Fatalf("Failed to write test file: %v", err)
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := BuildImportGraph(tmpDir)
		if err != nil {
			b.Fatalf("BuildImportGraph failed: %v", err)
		}
	}
}
