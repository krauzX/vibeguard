package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type PluginConfig struct {
	RulesDir string   `json:"rules_dir" yaml:"rules_dir"`
	Enabled  bool     `json:"enabled" yaml:"enabled"`
	Exclude  []string `json:"exclude" yaml:"exclude"`
}

type CustomRuleFile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Pattern     string   `json:"pattern"`
	Severity    string   `json:"severity"`
	Languages   []string `json:"languages,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Fix         string   `json:"fix,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Enabled     bool     `json:"enabled"`
}

type PluginLoader struct {
	configDir string
	rulesDir  string
}

func NewPluginLoader(configDir string) *PluginLoader {
	return &PluginLoader{
		configDir: configDir,
		rulesDir:  filepath.Join(configDir, "rules"),
	}
}

func (p *PluginLoader) LoadAll() ([]*Rule, error) {
	if _, err := os.Stat(p.rulesDir); os.IsNotExist(err) {
		return nil, nil
	}

	var allRules []*Rule

	err := filepath.Walk(p.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		rules, err := p.LoadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load %s: %v\n", path, err)
			return nil
		}

		allRules = append(allRules, rules...)
		return nil
	})

	return allRules, err
}

func (p *PluginLoader) LoadFile(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var fileRules []CustomRuleFile
	if err := json.Unmarshal(data, &fileRules); err != nil {
		var single CustomRuleFile
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, fmt.Errorf("invalid JSON in %s: %w", path, err)
		}
		fileRules = []CustomRuleFile{single}
	}

	var rules []*Rule
	for _, fr := range fileRules {
		if !fr.Enabled {
			continue
		}

		rule, err := p.convertRule(fr)
		if err != nil {
			return nil, fmt.Errorf("invalid rule %s: %w", fr.ID, err)
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func (p *PluginLoader) convertRule(fr CustomRuleFile) (*Rule, error) {
	sev := SeverityWarning
	switch strings.ToUpper(fr.Severity) {
	case "CRITICAL":
		sev = SeverityCritical
	case "INFO":
		sev = SeverityInfo
	}

	var pattern *regexp.Regexp
	if fr.Pattern != "" {
		var err error
		pattern, err = regexp.Compile(fr.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern: %w", err)
		}
	}

	var langs []Language
	for _, l := range fr.Languages {
		langs = append(langs, Language(l))
	}

	rule := &Rule{
		ID:          fr.ID,
		Name:        fr.Name,
		Description: fr.Description,
		Severity:    sev,
		Languages:   langs,
		Pattern:     pattern,
		CWE:         fr.CWE,
		Fix:         fr.Fix,
		Tags:        append(fr.Tags, "custom"),
	}
	applyAnchors(rule)

	return rule, nil
}

func (p *PluginLoader) SaveRule(rule *Rule) error {
	if err := os.MkdirAll(p.rulesDir, 0755); err != nil {
		return err
	}

	fr := CustomRuleFile{
		ID:          rule.ID,
		Name:        rule.Name,
		Description: rule.Description,
		Severity:    rule.Severity.String(),
		Languages:   make([]string, len(rule.Languages)),
		CWE:         rule.CWE,
		Fix:         rule.Fix,
		Tags:        rule.Tags,
		Enabled:     true,
	}

	if rule.Pattern != nil {
		fr.Pattern = rule.Pattern.String()
	}

	for i, l := range rule.Languages {
		fr.Languages[i] = string(l)
	}

	data, err := json.MarshalIndent([]CustomRuleFile{fr}, "", "  ")
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.json", strings.ToLower(rule.ID))
	return os.WriteFile(filepath.Join(p.rulesDir, filename), data, 0644)
}

func (p *PluginLoader) ListRules() ([]string, error) {
	if _, err := os.Stat(p.rulesDir); os.IsNotExist(err) {
		return nil, nil
	}

	var files []string
	err := filepath.Walk(p.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".json") {
			files = append(files, filepath.Base(path))
		}
		return nil
	})

	return files, err
}

func (p *PluginLoader) DeleteRule(id string) error {
	filename := fmt.Sprintf("%s.json", strings.ToLower(id))
	path := filepath.Join(p.rulesDir, filename)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("rule %s not found", id)
	}

	return os.Remove(path)
}

func (p *PluginLoader) InitDir() error {
	return os.MkdirAll(p.rulesDir, 0755)
}

func GetProjectPluginDir() string {
	return ".vibeguard"
}
