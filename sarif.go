package sight

import (
	"strings"

	"github.com/GrayCodeAI/hawk/sarif"
)

// SARIF 2.1.0 output support — emitted via the shared github.com/GrayCodeAI/hawk/sarif
// package so sight and inspect produce structurally identical output and the
// SARIF type tree only lives in one place.

// ToSARIF converts a slice of Finding values into a SARIF 2.1.0 JSON string
// compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other
// SARIF-consuming tools.
func ToSARIF(findings []Finding) string {
	b := sarif.New(sarif.Tool{
		Name:           "sight",
		Version:        Version,
		InformationURI: "https://github.com/GrayCodeAI/sight",
	})

	for _, f := range findings {
		ruleID := extractRuleID(f.Message)
		if ruleID == "" {
			ruleID = f.Concern
		}

		// Register the rule (deduped by ID inside the builder).
		rule := sarif.Rule{
			ID:               ruleID,
			ShortDescription: extractRuleName(f.Message),
			FullDescription:  f.Message,
			Severity:         severityToSARIF(f.Severity),
		}
		if f.CWE != "" {
			rule.Tags = []string{"security", f.CWE}
			rule.HelpURI = "https://cwe.mitre.org/data/definitions/" +
				strings.TrimPrefix(f.CWE, "CWE-") + ".html"
		}
		b.AddRule(rule)

		// Add the result.
		result := sarif.Result{
			RuleID:   ruleID,
			Severity: severityToSARIF(f.Severity),
			Message:  f.Message,
		}
		if f.File != "" {
			result.URI = f.File
			if f.Line > 0 {
				result.Region = &sarif.Region{
					StartLine: f.Line,
					EndLine:   f.EndLine, // 0 → builder defaults to StartLine
				}
			}
		}
		if f.Fix != "" {
			result.Fix = f.Fix
		}
		b.AddResult(result)
	}

	return b.String()
}

// severityToSARIF maps sight Severity to sarif.Severity.
func severityToSARIF(s Severity) sarif.Severity {
	switch s {
	case SeverityCritical, SeverityHigh:
		return sarif.SeverityError
	case SeverityMedium:
		return sarif.SeverityWarning
	case SeverityLow:
		return sarif.SeverityNote
	default:
		return sarif.SeverityNone
	}
}

// extractRuleID pulls the rule ID from a message formatted as "[ID] Name: Description".
func extractRuleID(msg string) string {
	if !strings.HasPrefix(msg, "[") {
		return ""
	}
	end := strings.Index(msg, "]")
	if end < 0 {
		return ""
	}
	return msg[1:end]
}

// extractRuleName pulls the rule name from a message formatted as "[ID] Name: Description".
func extractRuleName(msg string) string {
	end := strings.Index(msg, "]")
	if end < 0 {
		return msg
	}
	rest := strings.TrimSpace(msg[end+1:])
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return rest
	}
	return strings.TrimSpace(rest[:colon])
}
