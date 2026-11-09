package rules

import (
	"strings"
	"testing"
)

func lit(parts ...string) string { return strings.Join(parts, "") }

func TestColumnZeroIsDetected(t *testing.T) {
	cases := []struct {
		rule string
		line string
	}{
		{"VULN-001", lit("ev", "al(q);")},
		{"VULN-002", lit("os.sys", "tem(cmd)")},
		{"PY-001", lit("ex", `ec("x")`)},
		{"PY-002", lit("ev", `al("1")`)},
		{"QLT-001", lit("pr", "int(x)")},
		{"SEC-022", lit("m", "d5(data)")},
		{"SEC-023", lit("sh", "a1(data)")},
		{"SEC-024", lit("DE", "S.new(key)")},
	}

	for _, c := range cases {
		rule := ruleByID(t, c.rule)
		if MatchLineBytes(rule, []byte(c.line), 1, "sample", 200) == nil {
			t.Errorf("%s missed %q at column zero", c.rule, c.line)
		}
		if MatchLineBytes(rule, []byte("    "+c.line), 1, "sample", 200) == nil {
			t.Errorf("%s missed indented %q", c.rule, c.line)
		}
	}
}

func TestIdentifiersDoNotMatch(t *testing.T) {
	cases := []struct {
		rule string
		line string
	}{
		{"VULN-001", lit("myev", "al(x)")},
		{"VULN-002", lit("os.sys", "temx(z)")},
		{"PY-001", lit("xex", "ec(y)")},
		{"PY-002", lit("n_ev", "al(z)")},
		{"QLT-001", lit("spr", "int(x)")},
		{"SEC-022", lit("zzm", "d5(data)")},
		{"SEC-023", lit("nsh", "a1(data)")},
		{"SEC-024", lit("fooDE", "S.new(k)")},
	}

	for _, c := range cases {
		rule := ruleByID(t, c.rule)
		if MatchLineBytes(rule, []byte(c.line), 1, "sample", 200) != nil {
			t.Errorf("%s matched the identifier %q", c.rule, c.line)
		}
	}
}

func TestQualityRuleCoversPrintVariants(t *testing.T) {
	rule := ruleByID(t, "QLT-001")

	for _, line := range []string{
		lit("pri", "nt(x)"),
		lit("console.", "log(x)"),
		lit("pu", "ts(y)"),
		lit("System.out.", "println(z)"),
		lit("Logger.", "info(msg)"),
		lit("p", " ", `"debug value"`),
	} {
		if MatchLineBytes(rule, []byte(line), 1, "sample", 200) == nil {
			t.Errorf("QLT-001 missed %q", line)
		}
	}

	for _, line := range []string{lit("spr", "int(x)"), lit("mypr", "int(x)"), lit("prin", "ter(x)"), lit("repr", "int(x)")} {
		if MatchLineBytes(rule, []byte(line), 1, "sample", 200) != nil {
			t.Errorf("QLT-001 matched %q", line)
		}
	}
}
