package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// Fingerprint derives an id from rule, CWE, path and flagged source; the line is
// excluded so an accepted finding survives code moving.
func Fingerprint(ruleID, cwe, file, code string) string {
	sum := sha256.New()
	for _, part := range []string{ruleID, cwe, normalizeFingerprintPath(file), squashSpaces(code)} {
		sum.Write([]byte(part))
		sum.Write([]byte{0})
	}

	return hex.EncodeToString(sum.Sum(nil))[:16]
}

// Fingerprint hashes the full flagged source, never the truncated snippet.
func (f Finding) Fingerprint(relPath string) string {
	return Fingerprint(f.RuleID, f.CWE, relPath, f.FingerprintSource())
}

// FingerprintSource is the text the identity is derived from.
func (f Finding) FingerprintSource() string {
	if f.Source != "" {
		return f.Source
	}

	return f.Code
}

func normalizeFingerprintPath(path string) string {
	path = strings.ReplaceAll(filepath.ToSlash(path), "\\", "/")

	return strings.TrimPrefix(path, "./")
}

func squashSpaces(text string) string {
	return strings.Join(strings.Fields(text), " ")
}
