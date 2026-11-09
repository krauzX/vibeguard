package diff

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/KrauzX/vibeguard/pkg/rules"
	"github.com/KrauzX/vibeguard/pkg/scanner"
)

// Span is an inclusive line range.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type Ranges map[string][]Span

var ErrNotRepository = errors.New("not a git work tree")

// ChangedLines lists lines that differ from base, including untracked files.
func ChangedLines(root, base string) (Ranges, error) {
	if base == "" {
		base = "HEAD"
	}

	inside, err := gitOutput(root, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotRepository, err)
	}
	if strings.TrimSpace(inside) != "true" {
		return nil, ErrNotRepository
	}

	ranges := make(Ranges)

	if base == "HEAD" && !hasCommit(root) {
		tracked, err := gitOutput(root, "ls-files", "-z")
		if err != nil {
			return nil, fmt.Errorf("git ls-files: %w", err)
		}
		markWholeFiles(tracked, ranges)
	} else {
		patch, err := gitOutput(root, "-c", "core.quotePath=false", "diff", "-U0", "--no-color", "--relative", "--no-ext-diff", "--diff-filter=ACMRT", base, "--")
		if err != nil {
			return nil, fmt.Errorf("git diff %s: %w", base, err)
		}
		parsePatch(patch, ranges)
	}

	untracked, err := gitOutput(root, "-c", "core.quotePath=false", "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	markWholeFiles(untracked, ranges)

	for path, spans := range ranges {
		ranges[path] = merge(spans)
	}

	return ranges, nil
}

func (r Ranges) Contains(path string, line int) bool {
	return r.intersects(path, line, line)
}

// Filter keeps the findings whose span touches a changed line.
func (r Ranges) Filter(result *scanner.Result) []rules.Finding {
	kept := make([]rules.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		path := result.RelPath(f.File)
		start := f.Line
		end := f.EndLine
		if end < start {
			end = start
		}
		if r.intersects(path, start, end) {
			kept = append(kept, f)
		}
	}

	return kept
}

func (r Ranges) intersects(path string, start, end int) bool {
	spans, ok := r[normalize(path)]
	if !ok {
		return false
	}

	for _, span := range spans {
		if start <= span.End && end >= span.Start {
			return true
		}
	}

	return false
}

func normalize(path string) string {
	path = strings.ReplaceAll(filepath.ToSlash(path), "\\", "/")
	path = strings.TrimPrefix(path, "./")

	return strings.TrimPrefix(path, "/")
}

func parsePatch(patch string, ranges Ranges) {
	var current string
	sc := bufio.NewScanner(strings.NewReader(patch))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for sc.Scan() {
		line := sc.Text()

		switch {
		case strings.HasPrefix(line, "+++ "):
			current = parseHeaderPath(strings.TrimPrefix(line, "+++ "))
		case strings.HasPrefix(line, "@@ "):
			if current == "" {
				continue
			}
			if span, ok := parseHunk(line); ok {
				ranges[current] = append(ranges[current], span)
			}
		case strings.HasPrefix(line, "Binary files ") && current != "":
			ranges[current] = append(ranges[current], Span{Start: 1, End: maxInt})
		}
	}
}

func parseHeaderPath(header string) string {
	header = strings.TrimSpace(header)
	if header == "/dev/null" {
		return ""
	}

	if strings.HasPrefix(header, "\"") {
		if unquoted, err := strconv.Unquote(header); err == nil {
			header = unquoted
		}
	}

	if tab := strings.IndexByte(header, '\t'); tab >= 0 {
		header = header[:tab]
	}

	return normalize(strings.TrimPrefix(header, "b/"))
}

// parseHunk reads the new-file range out of an "@@ -a,b +c,d @@" header.
func parseHunk(header string) (Span, bool) {
	plus := strings.Index(header, "+")
	if plus < 0 {
		return Span{}, false
	}

	rest := header[plus+1:]
	if space := strings.IndexByte(rest, ' '); space >= 0 {
		rest = rest[:space]
	}

	parts := strings.SplitN(rest, ",", 2)
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return Span{}, false
	}

	count := 1
	if len(parts) == 2 {
		count, err = strconv.Atoi(parts[1])
		if err != nil {
			return Span{}, false
		}
	}
	if count == 0 {
		return Span{}, false
	}

	return Span{Start: start, End: start + count - 1}, true
}

func markWholeFiles(list string, ranges Ranges) {
	for _, raw := range strings.Split(list, "\x00") {
		path := normalize(strings.TrimSpace(raw))
		if path == "" {
			continue
		}
		ranges[path] = append(ranges[path], Span{Start: 1, End: maxInt})
	}
}

// merge sorts spans and joins adjacent ones.
func merge(spans []Span) []Span {
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })

	out := make([]Span, 0, len(spans))
	for _, span := range spans {
		last := len(out) - 1
		if last >= 0 && span.Start <= out[last].End+1 {
			if span.End > out[last].End {
				out[last].End = span.End
			}
			continue
		}
		out = append(out, span)
	}

	return out
}

func hasCommit(root string) bool {
	_, err := gitOutput(root, "rev-parse", "--verify", "--quiet", "HEAD")
	return err == nil
}

func gitOutput(root string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	if resolved, err := filepath.Abs(root); err == nil {
		cmd.Dir = resolved
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", errors.New(message)
	}

	return stdout.String(), nil
}

const maxInt = int(^uint(0) >> 1)
