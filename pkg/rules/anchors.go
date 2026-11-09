package rules

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

const (
	minAnchorLen  = 3
	minPrefixLen  = 2
	maxPrefixLen  = 12
	maxPrefixSets = 16
	maxAnchors    = 8
)

// deriveAnchors returns literals where at least one has to appear for the pattern to match.
// The second result reports whether the anchors are lowercase and need a folded haystack.
func deriveAnchors(pattern *regexp.Regexp) ([]string, bool) {
	if pattern == nil {
		return nil, false
	}

	parsed, err := syntax.Parse(pattern.String(), syntax.Perl)
	if err != nil {
		return nil, false
	}

	list := prefixSet(parsed)
	if len(list) == 0 {
		list = anchorSet(parsed)
	}
	if len(list) == 0 {
		return nil, false
	}

	if !hasFold(parsed) {
		return list, false
	}

	folded := make([]string, len(list))
	for i, a := range list {
		folded[i] = strings.ToLower(a)
	}

	return dedupe(folded), true
}

func hasFold(re *syntax.Regexp) bool {
	if re.Op == syntax.OpLiteral && re.Flags&syntax.FoldCase != 0 {
		return true
	}
	for _, sub := range re.Sub {
		if hasFold(sub) {
			return true
		}
	}
	return false
}

// prefixSet lists the literals a match can start with; every one has to appear in the line.
func prefixSet(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{head(string(re.Rune))}
	case syntax.OpCapture, syntax.OpPlus:
		return prefixSet(re.Sub[0])
	case syntax.OpAlternate:
		var union []string
		for _, sub := range re.Sub {
			set := prefixSet(sub)
			if len(set) == 0 {
				return nil
			}
			union = append(union, set...)
		}
		return normalizeAnchors(union)
	case syntax.OpConcat:
		acc, ok := literalOf(re.Sub[0])
		if !ok {
			return prefixSet(re.Sub[0])
		}

		for i := 1; i < len(re.Sub); i++ {
			if next, ok := literalOf(re.Sub[i]); ok {
				acc += next
				continue
			}
			set := prefixSet(re.Sub[i])
			if len(set) == 0 {
				break
			}
			for j := range set {
				set[j] = head(acc + set[j])
			}
			return normalizeAnchors(set)
		}

		return []string{head(acc)}
	}

	return nil
}

func literalOf(re *syntax.Regexp) (string, bool) {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpLiteral {
		return "", false
	}
	return string(re.Rune), true
}

func head(s string) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return ""
	}
	if len(runes) > maxPrefixLen {
		runes = runes[:maxPrefixLen]
	}
	return string(runes)
}

func normalizeAnchors(in []string) []string {
	out := dedupe(in)

	kept := out[:0]
	for _, a := range out {
		if len(a) >= minPrefixLen {
			kept = append(kept, a)
		}
	}

	if len(kept) == 0 || len(kept) > maxPrefixSets {
		return nil
	}

	if len(kept) > maxAnchors {
		sortByLength(kept)
		kept = kept[:maxAnchors]
	}

	return kept
}

func sortByLength(in []string) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && len(in[j]) > len(in[j-1]); j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

func anchorSet(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) < minAnchorLen {
			return nil
		}
		return []string{string(re.Rune)}
	case syntax.OpCapture, syntax.OpPlus:
		return anchorSet(re.Sub[0])
	case syntax.OpConcat:
		var best []string
		for _, sub := range re.Sub {
			set := anchorSet(sub)
			if len(set) > 0 && (len(best) == 0 || len(set[0]) > len(best[0])) {
				best = set
			}
		}
		return best
	case syntax.OpAlternate:
		var union []string
		for _, sub := range re.Sub {
			set := anchorSet(sub)
			if len(set) == 0 {
				return nil
			}
			union = append(union, set...)
		}
		return dedupe(union)
	}

	return nil
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func applyAnchors(r *Rule) {
	r.Anchors, r.foldAnchors = deriveAnchors(r.Pattern)
	r.anchorBytes = r.anchorBytes[:0]
	for _, a := range r.Anchors {
		r.anchorBytes = append(r.anchorBytes, []byte(a))
	}
}
