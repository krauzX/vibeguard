package prompt

import (
	"fmt"
	"strings"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

type BatchPrompt struct {
	FilePath     string
	Findings     []rules.Finding
	Prompts      []*FixPrompt
	PromptFormat PromptFormat
}

type BatchGenerator struct {
	generator *PromptGenerator
}

func NewBatchGenerator(format PromptFormat) *BatchGenerator {
	return &BatchGenerator{
		generator: NewGenerator(format),
	}
}

func (bg *BatchGenerator) GenerateBatch(filePath string, findings []rules.Finding) (*BatchPrompt, error) {
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings to generate prompts for")
	}

	ctx, err := CollectContext(filePath, findings[0])
	if err != nil {
		return nil, err
	}

	batch := &BatchPrompt{
		FilePath:     filePath,
		Findings:     findings,
		PromptFormat: bg.generator.format,
	}

	for _, f := range findings {
		ctx.Finding = f
		prompt := bg.generator.Generate(ctx)
		batch.Prompts = append(batch.Prompts, prompt)
	}

	return batch, nil
}

func (bg *BatchGenerator) FormatBatch(batch *BatchPrompt) string {
	switch bg.generator.format {
	case Claude:
		return bg.formatClaudeBatch(batch)
	case GPT:
		return bg.formatGPTBatch(batch)
	case Copilot:
		return bg.formatCopilotBatch(batch)
	default:
		return bg.formatGenericBatch(batch)
	}
}

func (bg *BatchGenerator) formatGenericBatch(batch *BatchPrompt) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# Security Fixes for %s\n\n", batch.FilePath))
	b.WriteString(fmt.Sprintf("Found %d security issues to fix:\n\n", len(batch.Findings)))

	for i, prompt := range batch.Prompts {
		b.WriteString(fmt.Sprintf("## Fix %d: %s\n\n", i+1, prompt.Title))
		b.WriteString(prompt.Context)
		b.WriteString("\n")
		b.WriteString(prompt.CodeBlock)
		b.WriteString("\n")
		b.WriteString(prompt.Instructions)
		b.WriteString("\n\n---\n\n")
	}

	b.WriteString("## Verification\n\n")
	b.WriteString(fmt.Sprintf("After applying all fixes, run:\n"))
	b.WriteString(fmt.Sprintf("```bash\nvibeguard verify %s\n```\n", shortPath(batch.FilePath)))

	return b.String()
}

func (bg *BatchGenerator) formatClaudeBatch(batch *BatchPrompt) string {
	var b strings.Builder

	b.WriteString("<security-fix-batch>\n")
	b.WriteString(fmt.Sprintf("<file>%s</file>\n", batch.FilePath))
	b.WriteString(fmt.Sprintf("<issue-count>%d</issue-count>\n\n", len(batch.Findings)))

	for i, prompt := range batch.Prompts {
		b.WriteString(fmt.Sprintf("<fix id=\"%d\">\n", i+1))
		b.WriteString(fmt.Sprintf("<title>%s</title>\n", prompt.Title))
		b.WriteString(fmt.Sprintf("<context>%s</context>\n", prompt.Context))
		b.WriteString(fmt.Sprintf("<code>%s</code>\n", prompt.CodeBlock))
		b.WriteString(fmt.Sprintf("<instructions>%s</instructions>\n", prompt.Instructions))
		b.WriteString("</fix>\n\n")
	}

	b.WriteString("<verification>\n")
	b.WriteString(fmt.Sprintf("Run: vibeguard verify %s\n", shortPath(batch.FilePath)))
	b.WriteString("</verification>\n")
	b.WriteString("</security-fix-batch>")

	return b.String()
}

func (bg *BatchGenerator) formatGPTBatch(batch *BatchPrompt) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("## Security Fixes for %s\n\n", batch.FilePath))
	b.WriteString(fmt.Sprintf("**%d issues found**\n\n", len(batch.Findings)))
	b.WriteString("Fix each issue in order:\n\n")

	for i, prompt := range batch.Prompts {
		b.WriteString(fmt.Sprintf("### Issue %d: %s\n", i+1, prompt.Title))
		b.WriteString(prompt.Context)
		b.WriteString("\n")
		b.WriteString(prompt.CodeBlock)
		b.WriteString("\n")
		b.WriteString(prompt.Instructions)
		b.WriteString("\n\n")
	}

	b.WriteString("---\n\n")
	b.WriteString("**After fixing all issues:**\n")
	b.WriteString(fmt.Sprintf("```bash\nvibeguard verify %s\n```\n", shortPath(batch.FilePath)))

	return b.String()
}

func (bg *BatchGenerator) formatCopilotBatch(batch *BatchPrompt) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("// Security fixes for %s (%d issues)\n\n", batch.FilePath, len(batch.Findings)))

	for i, prompt := range batch.Prompts {
		b.WriteString(fmt.Sprintf("// Fix %d: %s\n", i+1, prompt.Title))
		b.WriteString(fmt.Sprintf("// Line %d: %s\n", prompt.Finding.Line, prompt.Finding.Message))
		b.WriteString("// \n")
	}

	b.WriteString("// Apply each fix above, then verify:\n")
	b.WriteString(fmt.Sprintf("// vibeguard verify %s\n", shortPath(batch.FilePath)))

	return b.String()
}
