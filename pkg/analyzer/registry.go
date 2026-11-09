package analyzer

import (
	"sync"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

type Registry struct {
	mu        sync.RWMutex
	analyzers map[string]Analyzer
}

func NewRegistry() *Registry {
	return &Registry{
		analyzers: make(map[string]Analyzer),
	}
}

func (r *Registry) Register(name string, a Analyzer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.analyzers[name] = a
}

func (r *Registry) Get(name string) (Analyzer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.analyzers[name]
	return a, ok
}

func (r *Registry) List() []Analyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]Analyzer, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		list = append(list, a)
	}
	return list
}

func (r *Registry) Analyze(ctx *FileContext) []Finding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var all []Finding
	for _, a := range r.analyzers {
		for _, l := range a.SupportedLanguages() {
			if l == ctx.Language || l == rules.LanguageAny {
				findings, err := a.Analyze(ctx)
				if err == nil {
					all = append(all, findings...)
				}
				break
			}
		}
	}

	for i := range all {
		normalizeSpan(ctx.Content, &all[i])
	}

	return all
}
