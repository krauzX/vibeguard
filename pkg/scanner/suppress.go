package scanner

import (
	"github.com/KrauzX/vibeguard/pkg/baseline"
	"github.com/KrauzX/vibeguard/pkg/rules"
)

func (s *Scanner) applyBaseline(findings []rules.Finding, root string) ([]rules.Finding, int64) {
	path := s.cfg.Baseline.Path
	if path == "" {
		path = ".vibeguard-baseline.json"
	}

	b := baseline.New(path)
	if err := b.Load(); err != nil || b.Count() == 0 {
		return findings, 0
	}

	kept := findings[:0]
	for _, f := range findings {
		if b.IsSuppressed(f.Fingerprint(relativePath(root, f.File))) {
			continue
		}
		kept = append(kept, f)
	}

	return kept, int64(len(findings) - len(kept))
}
