package prompt

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

type PromptFormat string

const (
	Claude  PromptFormat = "claude"
	GPT     PromptFormat = "gpt"
	Copilot PromptFormat = "copilot"
	Generic PromptFormat = "generic"
)

type PromptContext struct {
	Finding     rules.Finding
	FilePath    string
	FileName    string
	FileContent string
	LineRange   [2]int
	Imports     []string
	ProjectRoot string
	Language    string
	Rule        *rules.Rule
}

type FixPrompt struct {
	Title        string
	Context      string
	CodeBlock    string
	Instructions string
	Verification string
	PromptFormat PromptFormat
	Finding      rules.Finding
	FilePath     string
}

type PromptGenerator struct {
	format PromptFormat
}

func NewGenerator(format PromptFormat) *PromptGenerator {
	return &PromptGenerator{format: format}
}

func (g *PromptGenerator) Generate(ctx *PromptContext) *FixPrompt {
	prompt := &FixPrompt{
		Title:        g.generateTitle(ctx),
		Context:      g.generateContext(ctx),
		CodeBlock:    g.generateCodeBlock(ctx),
		Instructions: g.generateInstructions(ctx),
		Verification: g.generateVerification(ctx),
		PromptFormat: g.format,
		Finding:      ctx.Finding,
		FilePath:     ctx.FilePath,
	}
	return prompt
}

func (g *PromptGenerator) generateTitle(ctx *PromptContext) string {
	severity := ctx.Finding.Severity.Emoji()
	return fmt.Sprintf("%s Security Fix: %s", severity, ctx.Finding.Message)
}

func (g *PromptGenerator) generateContext(ctx *PromptContext) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("File: %s | Line: %d | CWE: %s\n", ctx.FilePath, ctx.Finding.Line, ctx.Finding.CWE))
	b.WriteString(fmt.Sprintf("Rule: %s\n", ctx.Finding.RuleID))

	if ctx.Rule != nil {
		b.WriteString(fmt.Sprintf("Description: %s\n", ctx.Rule.Description))
		if len(ctx.Rule.Tags) > 0 {
			b.WriteString(fmt.Sprintf("Tags: %s\n", strings.Join(ctx.Rule.Tags, ", ")))
		}
	}

	return b.String()
}

func (g *PromptGenerator) generateCodeBlock(ctx *PromptContext) string {
	lines := strings.Split(ctx.FileContent, "\n")

	start := ctx.Finding.Line - 5
	if start < 0 {
		start = 0
	}

	end := ctx.Finding.Line + 5
	if end > len(lines) {
		end = len(lines)
	}

	var b strings.Builder
	b.WriteString("```")
	b.WriteString(ctx.Language)
	b.WriteString("\n")

	for i := start; i < end; i++ {
		lineNum := i + 1
		marker := "  "
		if lineNum == ctx.Finding.Line {
			marker = ">>"
		}
		b.WriteString(fmt.Sprintf("%s %d: %s\n", marker, lineNum, lines[i]))
	}

	b.WriteString("```\n")
	return b.String()
}

func (g *PromptGenerator) generateInstructions(ctx *PromptContext) string {
	ruleID := ctx.Finding.RuleID

	if ctx.Rule != nil && ctx.Rule.Fix != "" {
		return "### Recommended Fix\n" + ctx.Rule.Fix
	}

	switch {
	case strings.HasPrefix(ruleID, "SEC-001"):
		return g.genSecretFix(ctx)
	case strings.HasPrefix(ruleID, "SEC-002"):
		return g.genAWSKeyFix(ctx)
	case strings.HasPrefix(ruleID, "SEC-009"):
		return g.genPrivateKeyFix(ctx)
	case strings.HasPrefix(ruleID, "VULN-001"):
		return g.genEvalFix(ctx)
	case strings.HasPrefix(ruleID, "VULN-005"), strings.HasPrefix(ruleID, "TAINT-001"):
		return g.genSQLInjectionFix(ctx)
	case strings.HasPrefix(ruleID, "VULN-002"), strings.HasPrefix(ruleID, "TAINT-002"):
		return g.genCommandInjectionFix(ctx)
	case strings.HasPrefix(ruleID, "SEC-021"):
		return g.genSSLFix(ctx)
	case strings.HasPrefix(ruleID, "SEC-022"):
		return g.genWeakCryptoFix(ctx)
	case strings.HasPrefix(ruleID, "AST-001"):
		return g.genUncheckedErrorFix(ctx)
	case strings.HasPrefix(ruleID, "PLH-001"):
		return g.genPlaceholderFix(ctx)
	default:
		return g.genGenericFix(ctx)
	}
}

func (g *PromptGenerator) genSecretFix(ctx *PromptContext) string {
	return `### Vulnerability Analysis
The code contains a hardcoded secret that could be exposed if the repository is compromised or made public.

### Recommended Fix
1. Move the secret to an environment variable
2. Use os.Getenv() or equivalent to access it
3. Add the variable name to .env.example
4. Ensure .env is in .gitignore

### Fixed Code Pattern
Use environment variables instead of hardcoded values:
- Go: os.Getenv("SECRET_NAME")
- Python: os.environ["SECRET_NAME"]
- JavaScript: process.env.SECRET_NAME

### Security Checklist
- [ ] Secret removed from source code
- [ ] Environment variable documented in .env.example
- [ ] .env added to .gitignore
- [ ] Secret rotated (if previously exposed)`
}

func (g *PromptGenerator) genAWSKeyFix(ctx *PromptContext) string {
	return `### Vulnerability Analysis
AWS access key or secret key detected in source code.

### Recommended Fix
1. Remove the hardcoded AWS credentials
2. Use IAM roles, environment variables, or AWS SDK credential chains
3. Rotate the exposed credentials immediately
4. Check AWS CloudTrail for unauthorized access

### Fixed Code Pattern
// Go - use AWS SDK default credential chain
sess := session.Must(session.NewSession())

// Or use environment variables
awsAccessKey := os.Getenv("AWS_ACCESS_KEY_ID")
awsSecretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")`
}

func (g *PromptGenerator) genPrivateKeyFix(ctx *PromptContext) string {
	return `### Vulnerability Analysis
Private key (RSA/EC/DSA) detected in source code.

### Critical Action Required
1. REVOKE the exposed key immediately
2. Generate a new key pair
3. Remove the private key from source code
4. Add *.pem, *.key to .gitignore
5. Use a secrets manager for key storage

### Security Impact
Private keys can be used to:
- Decrypt sensitive data
- Impersonate services
- Sign malicious code`
}

func (g *PromptGenerator) genEvalFix(ctx *PromptContext) string {
	return `### Vulnerability Analysis
Dynamic code execution via eval() detected - high risk of code injection.

### Recommended Fix
1. Remove eval() usage entirely
2. Use safe alternatives (JSON.parse, type-safe parsing)
3. Validate and sanitize all inputs before processing

### Fixed Code Pattern
// Instead of eval(userInput)
// Use JSON.parse with validation
const data = JSON.parse(userInput);

// Or use a schema validator
const schema = { /* define expected structure */ };
const validated = validate(schema, userInput);`
}

func (g *PromptGenerator) genSQLInjectionFix(ctx *PromptContext) string {
	return `### Vulnerability Analysis
SQL query built with string formatting - vulnerable to SQL injection.

### Recommended Fix
1. Use parameterized queries (prepared statements)
2. Never concatenate user input into SQL
3. Use ORM query builders when possible

### Fixed Code Pattern
// Instead of:
db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userId))

// Use parameterized query:
db.Query("SELECT * FROM users WHERE id = ?", userId)

// Python:
cursor.execute("SELECT * FROM users WHERE id = %s", (userId,))`
}

func (g *PromptGenerator) genCommandInjectionFix(ctx *PromptContext) string {
	return `### Vulnerability Analysis
Command execution with user-controlled input - vulnerable to command injection.

### Recommended Fix
1. Avoid shell execution when possible
2. Use exec.Command with explicit arguments (no shell)
3. Validate and sanitize all inputs
4. Use allowlists for permitted commands

### Fixed Code Pattern
// Instead of:
os.system("ping " + userInput)

// Use:
exec.Command("ping", "-c", "1", validatedInput)`
}

func (g *PromptGenerator) genSSLFix(ctx *PromptContext) string {
	return `### Vulnerability Analysis
SSL/TLS certificate verification is disabled - MITM risk.

### Recommended Fix
1. Enable certificate verification
2. Use proper TLS configuration
3. Never disable verification in production

### Fixed Code Pattern
// Instead of:
http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

// Use:
http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}`
}

func (g *PromptGenerator) genWeakCryptoFix(ctx *PromptContext) string {
	return `### Vulnerability Analysis
Weak cryptographic algorithm (MD5/SHA1) detected.

### Recommended Fix
1. Replace MD5/SHA1 with SHA-256 or stronger
2. Use purpose-built algorithms (bcrypt for passwords)
3. Never use MD5/SHA1 for security purposes

### Fixed Code Pattern
// Instead of:
hash := md5.Sum(data)

// Use:
hash := sha256.Sum256(data)

// For passwords:
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)`
}

func (g *PromptGenerator) genUncheckedErrorFix(ctx *PromptContext) string {
	return `### Vulnerability Analysis
Error return value not checked - silent failures possible.

### Recommended Fix
1. Always check error return values
2. Handle errors appropriately (log, return, panic)
3. Use error wrapping for context

### Fixed Code Pattern
// Instead of:
file, _ := os.Open("path.txt")

// Use:
file, err := os.Open("path.txt")
if err != nil {
    return fmt.Errorf("failed to open file: %w", err)
}
defer file.Close()`
}

func (g *PromptGenerator) genPlaceholderFix(ctx *PromptContext) string {
	return `### Issue Analysis
TODO/placeholder comment indicates incomplete implementation.

### Recommended Fix
1. Implement the functionality or remove the code
2. If deferring, create a tracked issue
3. Never commit placeholder code to production

### Action Required
Complete the implementation or remove the placeholder.`
}

func (g *PromptGenerator) genGenericFix(ctx *PromptContext) string {
	return fmt.Sprintf(`### Vulnerability Analysis
Security issue detected by rule %s.

### Recommended Fix
Review the flagged code and apply security best practices:
1. Validate all inputs
2. Use parameterized queries for database access
3. Avoid dynamic code execution
4. Follow principle of least privilege

### Additional Resources
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE-%s: https://cwe.mitre.org/data/definitions/%s.html`, ctx.Finding.RuleID, ctx.Finding.CWE, ctx.Finding.CWE)
}

func (g *PromptGenerator) generateVerification(ctx *PromptContext) string {
	return fmt.Sprintf("After applying the fix, run:\nvibeguard verify %s", shortPath(ctx.FilePath))
}

// ShortPath trims an absolute path to the working directory so generated
// commands can be pasted into a shell.
func shortPath(path string) string {
	wd, err := os.Getwd()
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(wd, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return path
	}

	return filepath.ToSlash(rel)
}

func CollectContext(filePath string, finding rules.Finding) (*PromptContext, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}

	content, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	ext := filepath.Ext(absPath)
	language := strings.TrimPrefix(ext, ".")

	rule := rules.GetRuleByID(finding.RuleID)

	return &PromptContext{
		Finding:     finding,
		FilePath:    absPath,
		FileName:    filepath.Base(absPath),
		FileContent: string(content),
		Language:    language,
		Rule:        rule,
	}, nil
}

func (g *PromptGenerator) FormatPrompt(prompt *FixPrompt) string {
	switch g.format {
	case Claude:
		return g.formatClaude(prompt)
	case GPT:
		return g.formatGPT(prompt)
	case Copilot:
		return g.formatCopilot(prompt)
	default:
		return g.formatGeneric(prompt)
	}
}

func (g *PromptGenerator) formatClaude(prompt *FixPrompt) string {
	return fmt.Sprintf(`<fix-request>
<task>Security Vulnerability Remediation</task>

<context>
%s
</context>

<current-code>
%s
</current-code>

<instructions>
%s
</instructions>

<verification>
%s
</verification>
</fix-request>`, prompt.Context, prompt.CodeBlock, prompt.Instructions, prompt.Verification)
}

func (g *PromptGenerator) formatGPT(prompt *FixPrompt) string {
	return fmt.Sprintf(`## Security Fix Request

**Context:**
%s

**Current Code:**
%s

**Instructions:**
%s

**Verification:**
%s`, prompt.Context, prompt.CodeBlock, prompt.Instructions, prompt.Verification)
}

func (g *PromptGenerator) formatCopilot(prompt *FixPrompt) string {
	return fmt.Sprintf(`// Security Fix: %s
// File: %s Line: %d
// 
// Issue: %s
// 
// Please fix this security vulnerability by:
%s
//
// After fix, verify with: %s`,
		prompt.Title, prompt.FilePath, prompt.Finding.Line,
		prompt.Finding.Message, prompt.Instructions, prompt.Verification)
}

func (g *PromptGenerator) formatGeneric(prompt *FixPrompt) string {
	return fmt.Sprintf(`# %s

## Context
%s

## Current Code
%s

## Instructions
%s

## Verification
%s`, prompt.Title, prompt.Context, prompt.CodeBlock, prompt.Instructions, prompt.Verification)
}
