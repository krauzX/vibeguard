# VibeGuard

VibeGuard scans a source repository for exposed secrets, injection sinks and
risky configuration. Every finding comes with a CWE, a severity and fix text for
the line that matched, so the report can go straight into a patch or a review
comment.

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Version-1.0.0-green.svg)](https://github.com/KrauzX/vibeguard/releases)

## What it does

A scanner tells you a file and a line. The rest of the job is deciding whether
the finding is real, working out the fix, and getting the change reviewed.
VibeGuard is built for that part.

- Every rule carries remediation text, so `fix` and `prompt` work without a
  model or a network connection.
- `--diff` reports only findings on lines a change touches, so old debt does not
  block a pull request.
- Reports are stable: content-derived ids, a versioned schema, SARIF
  fingerprints, and exit codes that tell a breach apart from a failed scan.
- One static binary. No account, no server, no outbound request unless advisory
  checks are enabled.

## Scope

Detection is pattern based. Rules are regular expressions, and a parser-backed
check drops matches that sit in comments or in plain string literals. Go files
also get AST and taint passes, because those two checks need more than a line of
text. Go, JavaScript/TypeScript, Python, Java, Ruby and PHP are parsed; other
formats are matched as plain text.

For cross-file data flow, use Semgrep or CodeQL. VibeGuard does not try to
replace them. It aims to be fast, quiet about the cases that look suspicious but
are not, and specific when it fires.

## Install and first run

```bash
go install github.com/KrauzX/vibeguard@latest

# Scan the current directory
vibeguard scan .

# Scan a buffer without touching disk
git show HEAD:main.go | vibeguard scan - --stdin-name main.go

# Report only what a branch changed
vibeguard scan . --diff main --format sarif --output -

# Write fix prompts for one file
vibeguard prompt main.go

# Write one fix guide for every finding
vibeguard fix . --output fixes.md

# Re-check a file after fixing it
vibeguard verify main.go
```

Exit codes are fixed, so a script can tell the three outcomes apart:

| Exit | Meaning |
|------|---------|
| `0` | Scan completed and no configured policy was breached |
| `1` | Scan completed and findings breached the policy |
| `2` | Usage error, unreadable input, or a partial scan |

A partial scan is always `2`, even with `--fail-on none`, because a report with
missing files must not look like a pass. Unreadable files appear in `errors[]`
of the report and in the terminal summary.

## Example

`scan` prints findings to the terminal:

```
  main.go
    [CRITICAL] line 7: Hardcoded Slack Token
      CWE-798
```

`vibeguard prompt` turns the same finding into a task:

```markdown
## Fix: Hardcoded Slack Token (CWE-798)

### Current Code
apiKey := "xoxb-123456789012-abcdefghijklm"

### Recommended Fix
apiKey := os.Getenv("SLACK_TOKEN")
if apiKey == "" {
    log.Fatal("SLACK_TOKEN required")
}

### Checklist
- [ ] Secret removed from source
- [ ] Added to .env.example
- [ ] .env in .gitignore
```

## Commands

| Command | Description |
|---------|-------------|
| `vibeguard scan <path>` | Scan a file, a directory or `-` for standard input |
| `vibeguard prompt <path>` | Write fix prompts for each finding |
| `vibeguard fix <path>` | Write one fix guide covering all findings |
| `vibeguard verify <file>` | Re-check a file; `--json` prints what remains |
| `vibeguard sbom <path>` | Write a CycloneDX 1.5 bill of materials |
| `vibeguard rules [lang]` | List every rule, optionally filtered by language |
| `vibeguard baseline add` | Accept a finding by id with a reason |
| `vibeguard baseline remove` | Drop a suppression again |
| `vibeguard baseline show` | Print the current suppressions |
| `vibeguard plugin init` | Create the project rule directory |
| `vibeguard plugin create` | Add a custom regex rule with optional fix text |
| `vibeguard plugin delete` | Delete a custom rule |
| `vibeguard plugin list` | List installed custom rules |

### Choosing what fails the build

`--fail-on` takes a comma separated list of `none`, `any`, `warning`, `critical`
and `secret`. Without the flag the policy comes from
`security.fail_on_critical` and `security.fail_on_secrets`, which both default to
on.

```bash
vibeguard scan . --fail-on critical,secret   # default policy, stated explicitly
vibeguard scan . --fail-on any               # informational findings fail too
vibeguard scan . --fail-on none              # report only, exit 0 on a clean run
```

## What gets scanned

A scan follows the repository rather than the folder. `.gitignore` files are
honoured at every level, so vendored dependencies, build output and local
scratch files stay out of the report without extra configuration. Minified
bundles, source maps and dependency lockfiles are skipped by default, and `.env`
files are kept in scope even when no extension matches.

```yaml
scanner:
  respect_gitignore: true   # honour .gitignore and .git/info/exclude
  skip_minified: true       # *.min.js, *.bundle.js, *.map
  skip_lockfiles: true      # package-lock.json, yarn.lock, go.sum, ...
  skip_binary: true         # extensions and NUL-byte sniffing
```

Set `security.include_extensions` to an empty list to scan every text file. Add
names to `security.exclude_paths` to drop directories by name, regardless of the
ignore files.

### Standard input

`scan -` reads the file from standard input. `--stdin-name` gives it the name
used for language detection and in the report, so the same extension logic
applies as on disk.

```bash
vibeguard scan - --stdin-name handler.go --format json < handler.go
```

### Changed lines only

`--diff` keeps findings that touch a line changed since the given revision and
drops the rest. The base defaults to `HEAD`, and untracked files count as fully
changed. Outside a git work tree the flag falls back to a full scan and says so
on stderr.

```bash
vibeguard scan . --diff            # working tree against HEAD
vibeguard scan . --diff origin/main
```

Changed ranges come from `git diff -U0`, and a finding is kept only when its own
span overlaps a hunk.

## Output formats

`scan` prints a terminal report by default. Pass a format flag, or set an
extension on `--output` and the format is inferred from it.

```bash
vibeguard scan .                                    # terminal
vibeguard scan . --sarif --output results.sarif     # SARIF 2.1.0
vibeguard scan . --json  --output results.json      # JSON
vibeguard scan . --html  --output report.html       # HTML
vibeguard scan . --junit --output results.xml       # JUnit XML
vibeguard scan . --csv   --output results.csv       # CSV
vibeguard scan . --markdown --output report.md      # Markdown
vibeguard scan . --github                           # Actions annotations
```

`--format` accepts `terminal`, `json`, `sarif`, `html`, `junit`, `csv`,
`markdown` and `github`. The shorthand flags map to the same names.

`--output -` streams any format to standard output. A scan read from stdin also
writes to standard output, so no report file is left behind. The terminal report
is skipped when the report owns stdout, which keeps the stream parseable. When a
format flag is given without `--output` for a directory scan, the report goes to
`vibeguard-report.<ext>`.

`--no-timestamp` omits the timestamp and duration fields, which makes two runs
over the same tree byte-identical and diffable in CI.

## Report contracts

JSON reports carry `"schema_version": "2"`, and that number changes whenever the
shape does. There are no compatibility shims and no legacy fields: a consumer
pins the version it understands and upgrades deliberately.

Each finding has a content-derived `id` that survives moved lines, a 1-based
character `column`, an exclusive `end_line`/`end_column` span when the rule or
analyzer knows it, the matched `code`, its `cwe`, and the `fix` text a prompt is
built from. `root` is the scanned path, and `errors[]` lists files that could not
be read.

```json
{
  "schema_version": "2",
  "root": "/repo",
  "findings": [
    {
      "id": "2315798ae90c3027",
      "rule_id": "SEC-001",
      "severity": "CRITICAL",
      "file": "config.go",
      "line": 12,
      "column": 14,
      "end_line": 12,
      "end_column": 33,
      "message": "Hardcoded AWS Access Key",
      "code": "key := \"AKIA...\"",
      "cwe": "CWE-798",
      "fix": "Read the key from the environment ..."
    }
  ],
  "errors": []
}
```

SARIF uses the same spans and `partialFingerprints` under the `vibeguard/v2`
key. It sets `executionSuccessful: false` and adds `toolExecutionNotifications`
when files were skipped, and writes `helpUri` only for rules with a valid CWE.

`verify --json` prints the remaining findings with the same finding shape, plus
`"ok"`, so a check can be re-run after an edit without parsing prose.

## Prompt formats

The wording changes per reader; the findings do not.

```bash
vibeguard prompt main.go --format generic   # plain markdown
vibeguard prompt main.go --format claude    # XML blocks
vibeguard prompt main.go --format gpt       # markdown sections
vibeguard prompt main.go --format copilot   # inline comments
vibeguard prompt main.go --compact          # one line per finding
vibeguard prompt . --batch                  # one prompt per file
```

## Rules

63 rules across seven groups:

| Group | Count | Examples |
|-------|-------|----------|
| **Secrets** | 24 | Slack and AWS keys, private keys, MD5, SHA1, DES |
| **Injection** | 7 | SQL from formatting, `eval`, `exec`, `pickle`, YAML |
| **Web** | 10 | innerHTML, prototype pollution, XXE, SSRF, open redirect |
| **Config** | 7 | Debug mode, permissive CORS, world-writable files |
| **Quality** | 9 | TODO stubs, console prints, magic numbers, deep nesting |
| **Language** | 5 | Go goroutine leaks, Python tempfiles, asserts |
| **Supply** | 1 | Known CVEs in pinned dependency versions |

Run `vibeguard rules` for the full list with CWE ids. Every rule ships with fix
text, so `fix` and `prompt` never return an empty recommendation.

Language-tagged rules cover Go, Python, JavaScript/TypeScript, Java, Ruby and
PHP. Untagged rules run on every scanned text file, which is what covers shell,
SQL, YAML and Terraform. Those formats are matched as text and are not parsed
for context.

### Custom rules

```bash
vibeguard plugin create CUS-001 "Internal token" "INT_[A-Z]{8}" --fix "Read it from the environment"
vibeguard plugin list
```

Custom rules live in `.vibeguard/rules/` as JSON and are loaded on every scan.
They keep their own `fix` text, so `rules`, `fix` and `prompt` treat them like
built-in rules. Commit the directory so the rules travel with the project.

### Go analysis

Go files get an `AST-001`/`AST-002` pass over the parsed syntax tree. It reports
errors discarded from calls declared in the same file, and goroutines started
where the function never waits on a `WaitGroup`, sends or closes a channel, or
selects.

Injection rules for Go are backed by a taint pass rather than a pattern. Values
read from a request (`FormValue`, `URL.Query().Get`, `Header.Get`), from
`os.Args` or from stdin are followed through assignments and string building
until they reach a query, `exec.Command`, a file path or an outbound HTTP call.
A sink is reported only when a tainted value gets there, and converting to a
number clears the taint.

## Dependency and advisory checks

With `dependencies.check_vulnerabilities` on, pinned versions from `go.mod`,
`package.json`, `package-lock.json` and `requirements.txt` are checked against
the [OSV database](https://osv.dev). Matches are reported as `SC-001` with the
advisory id, its summary and the first fixed version. Ranges such as `^1.2.3`
are skipped, because a registry cannot answer for a version that was never
pinned. Answers are cached for a day under the user cache directory.

Network use is bounded and optional:

```bash
vibeguard scan . --offline          # no advisory requests at all
vibeguard scan . --timeout 10s      # budget for the whole OSV phase
vibeguard scan . --skip-deps        # skip manifest parsing as well
```

`--offline` is not a silent skip. The report records that advisories were not
checked in `dependencies.note`. If the budget runs out after some advisories
were fetched, those findings are still reported and the note says what is
missing.

```bash
vibeguard sbom . --output sbom.json
```

`sbom` writes a CycloneDX 1.5 document for the same manifests: one component per
pinned dependency, each with a package URL, plus the tool version that produced
it. Pass `--no-timestamp` to derive the serial number from the components, which
makes two runs over the same tree byte-identical.

## GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - run: go install github.com/KrauzX/vibeguard@latest
      - run: vibeguard scan . --sarif --output results.sarif --no-color
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

One process writes one report, so a job that needs both SARIF and JSON runs the
scan twice with a different output path.

## Configuration

Settings come from `vibeguard.yaml` in the working directory, or from `--config`.

```yaml
security:
  fail_on_critical: true    # any critical finding fails the run
  fail_on_secrets: true     # any secret-tagged finding fails the run
  exclude_paths:
    - node_modules
    - vendor
    - .git
  include_extensions:
    - .go
    - .py
    - .js

baseline:
  enabled: true
  path: .vibeguard-baseline.json

reporting:
  format: sarif           # format used when no flag is passed
  output: results.sarif   # output file used when --output is omitted

dependencies:
  check_vulnerabilities: true   # query OSV for pinned dependency versions
  offline: false                # skip every network lookup
  timeout: 30s                  # budget for the advisory phase

scanner:
  workers: 0            # 0 = one worker per CPU
  max_file_size: 10485760
  skip_binary: true
  skip_minified: true
  skip_lockfiles: true
  respect_gitignore: true

rules:
  enable_go: true
  enable_python: true
  max_line_length: 200    # bytes kept for the reported snippet
```

Whole lines are always scanned. `max_line_length` only trims the snippet written
into reports, so long generated lines are still checked end to end.

## How a scan runs

Files are read once into a pooled buffer and split by byte offset instead of
through a scanner object. Each rule carries the literals its pattern must
contain. A rule is dropped for a file when none of its literals is present, and
the regex then runs only on lines that contain one, which keeps the cost tied to
candidate lines rather than file size.

This repository (81 files) scans in about 0.1 s with `--skip-deps` and about
0.8 s with advisory lookups. Parsing adds roughly 0.2 ms per file and runs only
for files that already produced a match. A synthetic 8.6 MB file of 1.5 million
lines takes about 5 s. Very large generated files are the slow path, since anchor
scanning is linear in rules times bytes.

### Match context

Before a match is reported, the file is parsed and the span is checked against
the syntax tree. A match inside a comment is dropped. A match inside a plain
string literal is dropped unless the rule looks for secrets or comes from a
plugin, because a token in a string is the finding while `eval(...)` in a
docstring is not. Interpolated strings stay in scope, so the code inside
`f"{...}"` is still checked.

Go uses the standard library parser. JavaScript, TypeScript, TSX, Python, Java,
Ruby and PHP go through a pure-Go tree-sitter runtime. A file that fails to parse
keeps its raw matches, so the filter can remove noise but never hide code it
could not read.

## Baseline

Accepted findings are recorded in a JSON file and skipped on later runs. The file
is consulted only when `baseline.enabled` is true.

```bash
vibeguard baseline add --id 2315798ae90c3027 --reason "test token, not a real one"
vibeguard baseline show
vibeguard baseline remove --id 2315798ae90c3027
```

Suppressions are keyed by the finding id, which is derived from the rule, the
file and the flagged source text, so moving an accepted line does not resurrect
it. `--reason` is stored with the entry and printed by `baseline show`. An entry
that no longer matches anything is harmless; `baseline show` lists it so it can
be removed.

## Architecture

```
vibeguard/
├── pkg/
│   ├── prompt/       # fix prompts, batching and compaction
│   ├── analyzer/     # import graph, AST and taint analysis
│   │   ├── ast/      # Go AST checks
│   │   ├── taint/    # source to sink tracking for Go
│   │   └── supply/   # manifest parsing and OSV lookup
│   ├── baseline/     # suppression file
│   ├── config/       # configuration loading
│   ├── diff/         # git hunk ranges for --diff
│   ├── output/       # formatters (terminal, JSON, SARIF, HTML, JUnit, CSV)
│   ├── ignore/       # .gitignore matcher
│   ├── rules/        # rule registry, catalogs, matcher, fixes and plugins
│   ├── scanner/      # worker pool and candidate index
│   └── syntax/       # parser-backed context filter
├── .github/workflows/
│   ├── scan.yml
│   ├── pr-comment.yml
│   └── test.yml
└── main.go
```

## Development

```bash
go build ./...
go test ./...
go test -bench=. ./pkg/scanner    # scanner benchmarks
```

`internal/contract` holds the repository invariants: every rule has a CWE and fix
text, every config key is read, and no exported helper is left without a caller.

## License

MIT. See [LICENSE](LICENSE).
