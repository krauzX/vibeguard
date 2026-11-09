package config

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Security     SecurityConfig     `mapstructure:"security"`
	Dependencies DependenciesConfig `mapstructure:"dependencies"`
	Baseline     BaselineConfig     `mapstructure:"baseline"`
	Reporting    ReportingConfig    `mapstructure:"reporting"`
	Scanner      ScannerConfig      `mapstructure:"scanner"`
	Rules        RulesConfig        `mapstructure:"rules"`
}

type BaselineConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

type SecurityConfig struct {
	FailOnSecrets     bool     `mapstructure:"fail_on_secrets"`
	FailOnCritical    bool     `mapstructure:"fail_on_critical"`
	ExcludePaths      []string `mapstructure:"exclude_paths"`
	IncludeExtensions []string `mapstructure:"include_extensions"`
}

type DependenciesConfig struct {
	CheckVulnerabilities bool          `mapstructure:"check_vulnerabilities"`
	Offline              bool          `mapstructure:"offline"`
	Timeout              time.Duration `mapstructure:"timeout"`
}

type ReportingConfig struct {
	Format  string `mapstructure:"format"`
	Output  string `mapstructure:"output"`
	NoColor bool   `mapstructure:"no_color"`
	Quiet   bool   `mapstructure:"quiet"`
	Verbose bool   `mapstructure:"verbose"`
}

type ScannerConfig struct {
	Workers          int   `mapstructure:"workers"`
	MaxFileSize      int64 `mapstructure:"max_file_size"`
	SkipBinary       bool  `mapstructure:"skip_binary"`
	SkipMinified     bool  `mapstructure:"skip_minified"`
	SkipLockfiles    bool  `mapstructure:"skip_lockfiles"`
	RespectGitignore bool  `mapstructure:"respect_gitignore"`
}

type RulesConfig struct {
	EnableGo      bool `mapstructure:"enable_go"`
	EnablePython  bool `mapstructure:"enable_python"`
	EnableJS      bool `mapstructure:"enable_js"`
	EnableJava    bool `mapstructure:"enable_java"`
	EnableShell   bool `mapstructure:"enable_shell"`
	EnableRuby    bool `mapstructure:"enable_ruby"`
	EnablePHP     bool `mapstructure:"enable_php"`
	MaxLineLength int  `mapstructure:"max_line_length"`
}

func DefaultConfig() *Config {
	return &Config{
		Security: SecurityConfig{
			FailOnSecrets:  true,
			FailOnCritical: true,
			ExcludePaths: []string{
				".git", "node_modules", "vendor", ".venv", "venv",
				"__pycache__", ".idea", ".vscode", "dist", "build",
				".next", ".nuxt", "target", "bin", "obj",
				"docs", "examples",
			},
			IncludeExtensions: []string{
				".go", ".py", ".js", ".ts", ".jsx", ".tsx",
				".java", ".rb", ".php", ".sh", ".bash",
				".yaml", ".yml", ".json", ".toml", ".env",
				".sql", ".xml", ".html", ".css", ".conf",
				".cfg", ".ini", ".properties", ".tf", ".hcl",
			},
		},
		Dependencies: DependenciesConfig{
			CheckVulnerabilities: true,
			Timeout:              30 * time.Second,
		},
		Reporting: ReportingConfig{
			NoColor: false,
			Quiet:   false,
			Verbose: false,
		},
		Scanner: ScannerConfig{
			Workers:          runtime.NumCPU(),
			MaxFileSize:      10 * 1024 * 1024,
			SkipBinary:       true,
			SkipMinified:     true,
			SkipLockfiles:    true,
			RespectGitignore: true,
		},
		Rules: RulesConfig{
			EnableGo:      true,
			EnablePython:  true,
			EnableJS:      true,
			EnableJava:    true,
			EnableShell:   true,
			EnableRuby:    true,
			EnablePHP:     true,
			MaxLineLength: 200,
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		path = findConfigFile()
	}

	if path == "" {
		cfg.normalize()
		return cfg, nil
	}

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config %s: %w", path, err)
		}
		return cfg, nil
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config %s: %w", path, err)
	}

	cfg.normalize()
	return cfg, nil
}

func (c *Config) normalize() {
	defaults := DefaultConfig()

	if c.Scanner.MaxFileSize <= 0 {
		c.Scanner.MaxFileSize = defaults.Scanner.MaxFileSize
		fmt.Fprintf(os.Stderr, "warning: scanner.max_file_size must be positive, using %d\n", c.Scanner.MaxFileSize)
	}
	if c.Rules.MaxLineLength <= 0 {
		c.Rules.MaxLineLength = defaults.Rules.MaxLineLength
		fmt.Fprintf(os.Stderr, "warning: rules.max_line_length must be positive, using %d\n", c.Rules.MaxLineLength)
	}
	if c.Scanner.Workers < 0 {
		c.Scanner.Workers = 0
	}
	if c.Dependencies.Timeout < 0 {
		c.Dependencies.Timeout = 0
	}
}

func findConfigFile() string {
	candidates := []string{
		"vibeguard.yaml",
		"vibeguard.yml",
		".vibeguard.yaml",
		".vibeguard.yml",
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	return ""
}

func (c *Config) GetExcludePaths() map[string]bool {
	excludes := make(map[string]bool)
	for _, p := range c.Security.ExcludePaths {
		excludes[p] = true
	}
	return excludes
}

func (c *Config) GetIncludeExtensions() map[string]bool {
	exts := make(map[string]bool)
	for _, e := range c.Security.IncludeExtensions {
		exts[e] = true
	}
	return exts
}

func (c *Config) WorkerCount() int {
	max := 4 * runtime.NumCPU()
	if max < 4 {
		max = 4
	}

	if c.Scanner.Workers <= 0 {
		return runtime.NumCPU()
	}
	if c.Scanner.Workers > max {
		return max
	}

	return c.Scanner.Workers
}
