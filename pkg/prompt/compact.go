package prompt

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

type TokenOptimizer struct {
	format     PromptFormat
	compact    bool
	maxContext int
}

func NewTokenOptimizer(format PromptFormat, compact bool) *TokenOptimizer {
	return &TokenOptimizer{
		format:     format,
		compact:    compact,
		maxContext: 3,
	}
}

func (t *TokenOptimizer) OptimizePrompt(ctx *PromptContext) string {
	if t.compact {
		return t.compactFormat(ctx)
	}
	return t.fullFormat(ctx)
}

func (t *TokenOptimizer) compactFormat(ctx *PromptContext) string {
	lines := strings.Split(ctx.FileContent, "\n")
	start := ctx.Finding.Line - t.maxContext
	if start < 0 {
		start = 0
	}
	end := ctx.Finding.Line + t.maxContext
	if end > len(lines) {
		end = len(lines)
	}

	var code strings.Builder
	for i := start; i < end; i++ {
		marker := " "
		if i+1 == ctx.Finding.Line {
			marker = ">"
		}
		code.WriteString(fmt.Sprintf("%s%d: %s\n", marker, i+1, strings.TrimSpace(lines[i])))
	}

	fix := ctx.Finding.FixText()

	return fmt.Sprintf("[%s] %s:%d\n```\n%s```\nFix: %s",
		ctx.Finding.RuleID,
		filepath.Base(ctx.FilePath),
		ctx.Finding.Line,
		code.String(),
		fix)
}

func (t *TokenOptimizer) fullFormat(ctx *PromptContext) string {
	return NewGenerator(t.format).FormatPrompt(
		NewGenerator(t.format).Generate(ctx))
}

func CompactBatchFormat(findings []rules.Finding, filePath string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("#%s %d issues\n\n", filepath.Base(filePath), len(findings)))

	for _, f := range findings {
		b.WriteString(fmt.Sprintf("[%s] L%d: %s\n", f.RuleID, f.Line, f.Message))
	}

	return b.String()
}
