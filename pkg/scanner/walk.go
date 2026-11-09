package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/KrauzX/vibeguard/pkg/ignore"
)

func (s *Scanner) walkFiles(root string, matcher *ignore.Matcher, fileCh chan<- string, filesSkipped *atomic.Int64) {
	info, err := os.Stat(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking path: %v\n", err)
		return
	}
	if !info.IsDir() {
		fileCh <- root
		return
	}

	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		if entry.IsDir() {
			if path == root {
				return nil
			}
			name := entry.Name()
			if name == ".git" || s.excludePaths[name] {
				return filepath.SkipDir
			}
			if matcher != nil {
				if matcher.Match(rel, true) {
					filesSkipped.Add(1)
					return filepath.SkipDir
				}
				matcher.Load(rel)
			}
			return nil
		}

		if !entry.Type().IsRegular() {
			return nil
		}

		name := entry.Name()
		if s.isNoise(name) {
			filesSkipped.Add(1)
			return nil
		}
		if matcher != nil && matcher.Match(rel, false) {
			filesSkipped.Add(1)
			return nil
		}
		if !s.accepts(name) {
			filesSkipped.Add(1)
			return nil
		}

		fileCh <- path
		return nil
	})

	if walkErr != nil {
		fmt.Fprintf(os.Stderr, "Error walking path: %v\n", walkErr)
	}
}

func (s *Scanner) accepts(name string) bool {
	if isEnvFile(name) {
		return true
	}

	ext := strings.ToLower(filepath.Ext(name))
	if len(s.includeExts) == 0 || s.includeExts[ext] {
		return true
	}

	return ext == "" && isLikelySourceFile(name)
}

func (s *Scanner) isNoise(name string) bool {
	lower := strings.ToLower(name)

	if s.cfg.Scanner.SkipBinary && binaryExts[strings.ToLower(filepath.Ext(lower))] {
		return true
	}
	if !s.cfg.Scanner.SkipMinified {
		return false
	}

	switch {
	case strings.HasSuffix(lower, ".min.js"),
		strings.HasSuffix(lower, ".min.css"),
		strings.HasSuffix(lower, ".min.mjs"),
		strings.HasSuffix(lower, ".bundle.js"),
		strings.HasSuffix(lower, ".map"):
		return true
	}

	return s.cfg.Scanner.SkipLockfiles && lockFiles[lower]
}

func isEnvFile(name string) bool {
	lower := strings.ToLower(name)
	if lower != ".env" && !strings.HasPrefix(lower, ".env.") {
		return false
	}

	for _, suffix := range []string{".example", ".sample", ".template", ".dist"} {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}

	return true
}

var binaryExts = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".bin": true, ".o": true, ".a": true, ".lib": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".bmp": true, ".ico": true, ".svg": true, ".webp": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	".wav": true, ".flac": true, ".ogg": true,
	".zip": true, ".tar": true, ".gz": true, ".bz2": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true,
	".xlsx": true, ".ppt": true, ".pptx": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".pyc": true, ".pyo": true, ".class": true,
}

var lockFiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"npm-shrinkwrap.json": true, "go.sum": true, "cargo.lock": true,
	"composer.lock": true, "poetry.lock": true, "gemfile.lock": true,
	"mix.lock": true, "podfile.lock": true, "packages.lock.json": true,
}

func isLikelySourceFile(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "makefile", "dockerfile", "vagrantfile", "gemfile", "rakefile",
		"procfile", "cmakelists.txt", "meson.build", "jenkinsfile":
		return true
	}
	return false
}
