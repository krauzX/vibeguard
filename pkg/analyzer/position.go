package analyzer

import (
	"bytes"
	"unicode/utf8"
)

// normalizeSpan rewrites byte-based columns from go/token into the 1-based
// character columns that reports, SARIF and editors use.
func normalizeSpan(content []byte, finding *Finding) {
	finding.Column = charColumn(content, finding.Line, finding.Column)
	if finding.EndColumn > 0 {
		finding.EndColumn = charColumn(content, finding.EndLine, finding.EndColumn)
	}
	if finding.EndLine == 0 {
		finding.EndLine = finding.Line
	}
}

func charColumn(content []byte, line, column int) int {
	if column <= 1 {
		return max(column, 0)
	}

	start := lineOffset(content, line)
	if start < 0 {
		return column
	}

	end := min(start+column-1, len(content))

	return utf8.RuneCount(content[start:end]) + 1
}

func lineOffset(content []byte, line int) int {
	if line <= 1 {
		return 0
	}

	offset := 0
	for n := 1; n < line; n++ {
		next := bytes.IndexByte(content[offset:], '\n')
		if next < 0 {
			return -1
		}
		offset += next + 1
	}

	return offset
}
