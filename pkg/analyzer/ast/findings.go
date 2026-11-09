package ast

import (
	"github.com/KrauzX/vibeguard/pkg/analyzer"
	"github.com/KrauzX/vibeguard/pkg/rules"
)

type RuleID string

const (
	RuleIgnoredError     RuleID = "AST-001"
	RuleUnsynchronizedGo RuleID = "AST-002"
)

type ruleInfo struct {
	ID          RuleID
	Name        string
	Description string
	Severity    analyzer.Severity
	CWE         string
}

var astRules = []ruleInfo{
	{
		ID:          RuleIgnoredError,
		Name:        "Ignored Error Result",
		Description: "Error returned by a call is discarded",
		Severity:    rules.SeverityWarning,
		CWE:         "CWE-252",
	},
	{
		ID:          RuleUnsynchronizedGo,
		Name:        "Unsynchronized Goroutine",
		Description: "Goroutine started where nothing waits, closes a channel or selects",
		Severity:    rules.SeverityWarning,
		CWE:         "CWE-672",
	},
}

func ruleByID(id RuleID) *ruleInfo {
	for i := range astRules {
		if astRules[i].ID == id {
			return &astRules[i]
		}
	}
	return nil
}
