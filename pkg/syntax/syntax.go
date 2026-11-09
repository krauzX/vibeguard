package syntax

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	ts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars/java"
	"github.com/odvcencio/gotreesitter/grammars/javascript"
	"github.com/odvcencio/gotreesitter/grammars/php"
	"github.com/odvcencio/gotreesitter/grammars/python"
	"github.com/odvcencio/gotreesitter/grammars/ruby"
	"github.com/odvcencio/gotreesitter/grammars/tsx"
	"github.com/odvcencio/gotreesitter/grammars/typescript"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

type span struct{ start, end int }

type index struct {
	comments []span
	strings  []span
}

var (
	commentNodes = map[string]bool{"comment": true, "line_comment": true, "block_comment": true}
	stringNodes  = map[string]bool{
		"string": true, "string_literal": true, "template_string": true,
		"raw_string_literal": true, "char_literal": true, "heredoc_body": true,
		"encapsed_string": true,
	}
	interpolatedNodes = map[string]bool{"interpolation": true, "template_substitution": true}

	ruleOnce   sync.Once
	stringKeep map[string]bool
)

// Filter drops matches that sit inside a comment, or inside a plain string
// literal when the rule does not detect secrets.
func Filter(path string, src []byte, findings []rules.Finding) []rules.Finding {
	if len(findings) == 0 {
		return findings
	}
	idx := parse(path, src)
	if idx == nil {
		return findings
	}
	starts := lineStarts(src)
	kept := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		if !idx.suppresses(src, starts, f) {
			kept = append(kept, f)
		}
	}
	return kept
}

func (i *index) suppresses(src []byte, starts []int, f rules.Finding) bool {
	if f.Line < 1 || f.Line > len(starts) || f.Line != f.EndLine {
		return false
	}
	line := lineAt(src, starts, f.Line)
	base := starts[f.Line-1]
	start := base + columnOffset(line, f.Column)
	end := base + columnOffset(line, f.EndColumn)
	if end <= start {
		end = start + 1
	}
	if contains(i.comments, start, end) {
		return true
	}
	if keepsStringMatches(f.RuleID) {
		return false
	}
	return contains(i.strings, start, end)
}

func parse(path string, src []byte) *index {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return parseGo(path, src)
	case ".js", ".jsx", ".mjs", ".cjs":
		return parseTree(javascript.Language(), src)
	case ".ts":
		return parseTree(typescript.Language(), src)
	case ".tsx":
		return parseTree(tsx.Language(), src)
	case ".py":
		return parseTree(python.Language(), src)
	case ".java":
		return parseTree(java.Language(), src)
	case ".rb":
		return parseTree(ruby.Language(), src)
	case ".php":
		return parseTree(php.Language(), src)
	}
	return nil
}

func parseGo(path string, src []byte) *index {
	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, path, src, parser.ParseComments)
	if file == nil {
		return nil
	}

	idx := &index{}
	for _, group := range file.Comments {
		for _, c := range group.List {
			idx.comments = append(idx.comments, span{fset.Position(c.Pos()).Offset, fset.Position(c.End()).Offset})
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && (lit.Kind == token.STRING || lit.Kind == token.CHAR) {
			idx.strings = append(idx.strings, span{fset.Position(lit.Pos()).Offset, fset.Position(lit.End()).Offset})
		}
		return true
	})
	return idx
}

func parseTree(lang *ts.Language, src []byte) *index {
	if lang == nil {
		return nil
	}
	tree, err := ts.NewParser(lang).Parse(src)
	if err != nil {
		return nil
	}
	defer tree.Release()

	idx := &index{}
	collect(tree.RootNode(), lang, idx, 0)
	return idx
}

func collect(n *ts.Node, lang *ts.Language, idx *index, depth int) {
	if n == nil || depth > 512 {
		return
	}

	typ := n.Type(lang)
	switch {
	case commentNodes[typ]:
		idx.comments = append(idx.comments, span{int(n.StartByte()), int(n.EndByte())})
		return
	case stringNodes[typ] && !hasInterpolation(n, lang):
		idx.strings = append(idx.strings, span{int(n.StartByte()), int(n.EndByte())})
		return
	}

	for i := 0; i < n.ChildCount(); i++ {
		collect(n.Child(i), lang, idx, depth+1)
	}
}

func hasInterpolation(n *ts.Node, lang *ts.Language) bool {
	for i := 0; i < n.ChildCount(); i++ {
		if interpolatedNodes[n.Child(i).Type(lang)] {
			return true
		}
	}
	return false
}

func contains(spans []span, start, end int) bool {
	for _, s := range spans {
		if s.start <= start && end <= s.end {
			return true
		}
	}
	return false
}

// keepsStringMatches leaves secrets and custom rules untouched.
func keepsStringMatches(id string) bool {
	ruleOnce.Do(func() {
		stringKeep = make(map[string]bool)
		for _, r := range rules.GetRules() {
			keep := false
			for _, tag := range r.Tags {
				if tag == "secret" || tag == "custom" {
					keep = true
				}
			}
			stringKeep[r.ID] = keep
		}
	})
	if keep, ok := stringKeep[id]; ok {
		return keep
	}
	return true
}

func lineStarts(src []byte) []int {
	starts := make([]int, 1, 64)
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func lineAt(src []byte, starts []int, line int) []byte {
	rest := src[starts[line-1]:]
	if n := bytes.IndexByte(rest, '\n'); n >= 0 {
		return rest[:n]
	}
	return rest
}

func columnOffset(line []byte, column int) int {
	if column <= 1 {
		return 0
	}
	offset, n := 0, 1
	for offset < len(line) && n < column {
		_, size := utf8.DecodeRune(line[offset:])
		offset += size
		n++
	}
	return offset
}
