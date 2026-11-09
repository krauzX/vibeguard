package scanner

import (
	"regexp"
	"strings"
	"testing"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

func candidateLines(content, anchor string) []int {
	rule := &rules.Rule{ID: "TEST-001", Pattern: regexp.MustCompile(regexp.QuoteMeta(anchor)), Anchors: []string{anchor}}
	cands := buildCandidates([]*rules.Rule{rule}, []byte(content), nil)
	return cands[0].lines
}

func TestAnchorLinesMapToPhysicalLines(t *testing.T) {
	cases := []struct {
		name    string
		content string
		anchor  string
		want    []int
	}{
		{"first line", "hit\nb\nc\n", "hit", []int{1}},
		{"middle line", "a\nhit\nc\n", "hit", []int{2}},
		{"column zero third line", "a\nb\nhit\n", "hit", []int{3}},
		{"no trailing newline", "a\nhit", "hit", []int{2}},
		{"tenth line", strings.Repeat("x\n", 9) + "hit\n", "hit", []int{10}},
		{"twice on one line", "hit hit\nb\n", "hit", []int{1}},
		{"windows newlines", "a\r\nhit\r\n", "hit", []int{2}},
		{"indented", "a\n    hit\n", "hit", []int{2}},
	}

	for _, c := range cases {
		got := candidateLines(c.content, c.anchor)
		if len(got) != len(c.want) {
			t.Fatalf("%s: lines %v, want %v", c.name, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: lines %v, want %v", c.name, got, c.want)
			}
		}
	}
}

func TestEveryOccurrenceGetsItsOwnLine(t *testing.T) {
	content := strings.Repeat("hit\n", 50)
	lines := candidateLines(content, "hit")

	if len(lines) != 50 {
		t.Fatalf("expected 50 candidates, got %d", len(lines))
	}
	for i, line := range lines {
		if line != i+1 {
			t.Fatalf("candidate %d mapped to line %d", i, line)
		}
	}
}
