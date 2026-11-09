package supply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Dependency is one pinned requirement found in a manifest.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
	File      string
	Line      int
}

var exactVersion = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$`)

// ParseManifests collects every requirement below root that carries an exact
// version. Ranges are skipped: asking a vulnerability database about "^1.2"
// would answer a question nobody asked.
func ParseManifests(root string) []Dependency {
	var deps []Dependency

	filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if skipDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		switch entry.Name() {
		case "go.mod":
			deps = append(deps, parseGoMod(path)...)
		case "package.json":
			deps = append(deps, parsePackageJSON(path)...)
		case "requirements.txt":
			deps = append(deps, parseRequirements(path)...)
		}
		return nil
	})

	return dedupe(deps)
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target":
		return true
	}
	return false
}

func dedupe(deps []Dependency) []Dependency {
	seen := make(map[string]bool, len(deps))
	out := deps[:0]
	for _, dep := range deps {
		key := dep.Ecosystem + "|" + dep.Name + "|" + dep.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, dep)
	}
	return out
}

func parseGoMod(path string) []Dependency {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var deps []Dependency
	inBlock := false

	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "require (":
			inBlock = true
			continue
		case inBlock && trimmed == ")":
			inBlock = false
			continue
		}

		fields := strings.Fields(trimmed)
		if inBlock {
			if len(fields) < 2 || strings.HasPrefix(trimmed, "//") {
				continue
			}
		} else if len(fields) != 3 || fields[0] != "require" {
			continue
		}

		name := fields[0]
		version := fields[1]
		if !inBlock {
			name, version = fields[1], fields[2]
		}

		deps = append(deps, Dependency{
			Name:      name,
			Version:   goVersion(version),
			Ecosystem: "Go",
			File:      path,
			Line:      i + 1,
		})
	}

	return deps
}

func goVersion(version string) string {
	version = strings.TrimPrefix(version, "v")
	return strings.TrimSuffix(version, "+incompatible")
}

func parsePackageJSON(path string) []Dependency {
	dir := filepath.Dir(path)
	for _, lock := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		if deps := parseLockfile(filepath.Join(dir, lock)); len(deps) > 0 {
			return deps
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	var deps []Dependency
	for _, group := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name, version := range group {
			if !exactVersion.MatchString(version) {
				continue
			}
			deps = append(deps, Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: "npm",
				File:      path,
				Line:      findLine(lines, `"`+name+`"`),
			})
		}
	}

	return deps
}

func parseLockfile(path string) []Dependency {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var lock struct {
		Packages     map[string]struct{ Version string }
		Dependencies map[string]struct{ Version string }
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	var deps []Dependency

	for key, entry := range lock.Packages {
		if key == "" || entry.Version == "" {
			continue
		}
		name := key
		if idx := strings.LastIndex(name, "node_modules/"); idx >= 0 {
			name = name[idx+len("node_modules/"):]
		}
		if strings.Contains(name, "/node_modules/") || name == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   entry.Version,
			Ecosystem: "npm",
			File:      path,
			Line:      findLine(lines, `"node_modules/`+name+`"`),
		})
	}

	for name, entry := range lock.Dependencies {
		if entry.Version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   entry.Version,
			Ecosystem: "npm",
			File:      path,
			Line:      findLine(lines, `"`+name+`": {`),
		})
	}

	return dedupe(deps)
}

func parseRequirements(path string) []Dependency {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var deps []Dependency
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}

		name, version, ok := strings.Cut(trimmed, "==")
		if !ok {
			continue
		}

		name = strings.TrimSpace(name)
		version = strings.TrimSpace(strings.SplitN(version, ";", 2)[0])
		if name == "" || !exactVersion.MatchString(version) {
			continue
		}

		deps = append(deps, Dependency{
			Name:      strings.ToLower(name),
			Version:   version,
			Ecosystem: "PyPI",
			File:      path,
			Line:      i + 1,
		})
	}

	return deps
}

func findLine(lines []string, needle string) int {
	for i, line := range lines {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	return 0
}
