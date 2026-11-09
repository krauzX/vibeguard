package ignore

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

type pattern struct {
	re       *regexp.Regexp
	base     string
	negate   bool
	dirOnly  bool
	basename bool
}

func (p *pattern) match(rel string, isDir bool) bool {
	if p.dirOnly && !isDir {
		return false
	}
	if p.base != "" {
		if !strings.HasPrefix(rel, p.base+"/") {
			return false
		}
		rel = rel[len(p.base)+1:]
	}
	if p.basename {
		return p.re.MatchString(path.Base(rel))
	}
	return p.re.MatchString(rel)
}

type Matcher struct {
	root     string
	patterns []pattern
}

// New loads the repository level ignore files; nested files are added as the walk descends.
func New(root string) *Matcher {
	m := &Matcher{root: root}
	m.load(filepath.Join(root, ".gitignore"), "")
	m.load(filepath.Join(root, ".git", "info", "exclude"), "")
	return m
}

// Load reads the .gitignore inside dir, which is relative to the scan root.
func (m *Matcher) Load(dir string) {
	m.load(filepath.Join(m.root, filepath.FromSlash(dir), ".gitignore"), dir)
}

func (m *Matcher) load(file, base string) {
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 1<<16)
	for scanner.Scan() {
		if p, ok := parse(scanner.Text(), base); ok {
			m.patterns = append(m.patterns, p)
		}
	}
}

// Match reports whether rel is excluded; later patterns override earlier ones.
func (m *Matcher) Match(rel string, isDir bool) bool {
	if len(m.patterns) == 0 {
		return false
	}

	rel = path.Clean(filepath.ToSlash(rel))
	ignored := false
	for i := range m.patterns {
		if m.patterns[i].match(rel, isDir) {
			ignored = !m.patterns[i].negate
		}
	}

	return ignored
}

func parse(line, base string) (pattern, bool) {
	line = strings.TrimSuffix(line, "\r")
	if line == "" || strings.HasPrefix(line, "#") {
		return pattern{}, false
	}

	p := pattern{base: base}

	switch {
	case strings.HasPrefix(line, "!"):
		p.negate = true
		line = line[1:]
	case strings.HasPrefix(line, `\!`), strings.HasPrefix(line, `\#`):
		line = line[1:]
	}

	line = strings.TrimRight(line, " ")
	if line == "" {
		return pattern{}, false
	}

	if strings.HasSuffix(line, "/") {
		p.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}

	anchored := strings.HasPrefix(line, "/")
	line = strings.TrimPrefix(line, "/")
	if line == "" {
		return pattern{}, false
	}

	p.basename = !anchored && !strings.Contains(line, "/")

	re, err := regexp.Compile("^" + translate(line) + "$")
	if err != nil {
		return pattern{}, false
	}

	p.re = re
	return p, true
}

func translate(glob string) string {
	var b strings.Builder

	for i := 0; i < len(glob); i++ {
		switch glob[i] {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				i++
				if i+1 < len(glob) && glob[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
					continue
				}
				b.WriteString(".*")
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '[':
			end := i + 1
			if end < len(glob) && (glob[end] == '!' || glob[end] == '^') {
				end++
			}
			if end < len(glob) && glob[end] == ']' {
				end++
			}
			for end < len(glob) && glob[end] != ']' {
				end++
			}
			if end >= len(glob) {
				b.WriteString(`\[`)
				continue
			}
			class := glob[i : end+1]
			if strings.HasPrefix(class, "[!") {
				class = "[^" + class[2:]
			}
			b.WriteString(class)
			i = end
		case '\\':
			if i+1 < len(glob) {
				i++
				b.WriteString(regexp.QuoteMeta(string(glob[i])))
				continue
			}
			b.WriteString(`\\`)
		default:
			b.WriteString(regexp.QuoteMeta(string(glob[i])))
		}
	}

	return b.String()
}
