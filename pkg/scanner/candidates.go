package scanner

import (
	"bytes"
	"sort"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

type candidate struct {
	rule   *rules.Rule
	lines  []int
	cursor int
	always bool
}

func buildCandidates(active []*rules.Rule, content, folded []byte) []candidate {
	starts := make([]int, 0, len(content)/40+2)
	starts = append(starts, 0)
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			starts = append(starts, i+1)
		}
	}

	out := make([]candidate, 0, len(active))
	for _, r := range active {
		haystack := content
		if r.FoldAnchors() && folded != nil {
			haystack = folded
		}

		lines := anchorLines(r, haystack, starts)
		out = append(out, candidate{rule: r, lines: lines, always: len(lines) == 0 && len(r.Anchors) == 0})
	}

	return out
}

func anchorLines(r *rules.Rule, content []byte, starts []int) []int {
	if len(r.Anchors) == 0 {
		return nil
	}

	var lines []int
	for _, anchor := range r.Anchors {
		needle := []byte(anchor)
		for offset := 0; ; {
			idx := bytes.Index(content[offset:], needle)
			if idx < 0 {
				break
			}
			lines = append(lines, sort.SearchInts(starts, offset+idx+1))
			offset += idx + len(needle)
		}
	}

	if len(lines) == 0 {
		return nil
	}

	sort.Ints(lines)
	unique := lines[:1]
	for _, n := range lines[1:] {
		if n != unique[len(unique)-1] {
			unique = append(unique, n)
		}
	}

	return unique
}

// hit reports whether the rule can still match on this line.
func (c *candidate) hit(line int) bool {
	if c.always {
		return true
	}
	for c.cursor < len(c.lines) && c.lines[c.cursor] < line {
		c.cursor++
	}
	return c.cursor < len(c.lines) && c.lines[c.cursor] == line
}

func foldInto(dst, src []byte) []byte {
	dst = dst[:0]
	for _, c := range src {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}
