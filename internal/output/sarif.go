// SARIF 2.1.0 output for sight, emitted via the shared
// github.com/GrayCodeAI/hawk/sarif package.

package output

import (
	"strings"

	"github.com/GrayCodeAI/hawk/sarif"
)

// ToolVersion is the sight tool version reported in SARIF output. It is set
// at startup by the parent sight package from the canonical VERSION file.
// Default falls back to "dev" so direct internal use (e.g. tests) still works.
var ToolVersion = "dev"

// SetToolVersion lets the parent sight package wire its canonical Version
// into this internal package without creating an import cycle.
func SetToolVersion(v string) { ToolVersion = v }

// FormatSARIF produces SARIF 2.1.0 JSON from review findings.
//
// Output is delegated to the shared sarif.Builder so sight and inspect
// produce structurally identical SARIF.
func FormatSARIF(findings []Finding) (string, error) {
	b := sarif.New(sarif.Tool{
		Name:           "sight",
		Version:        ToolVersion,
		InformationURI: "https://github.com/GrayCodeAI/sight",
	})

	for _, f := range findings {
		ruleID := "sight/" + f.Concern

		// Register the rule (deduped by ID inside the builder).
		rule := sarif.Rule{
			ID:               ruleID,
			Name:             f.Concern,
			ShortDescription: f.Concern + " analysis",
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
					EndLine:   f.EndLine,
				}
			}
		}
		if f.Fix != "" {
			result.Fix = f.Fix
		}
		if f.CWE != "" {
			result.Taxa = []sarif.TaxaRef{
				{ID: f.CWE, Component: "CWE"},
			}
		}
		b.AddResult(result)
	}

	return b.String(), nil
}

// severityToSARIF maps the int severity used internally by sight to the
// sarif.Severity enum.
//
// sight Finding.Severity convention (int):
//
//	>= 3 (high, critical) → SARIF "error"
//	   2 (medium)         → SARIF "warning"
//	other (0, 1, info)    → SARIF "note"
func severityToSARIF(severity int) sarif.Severity {
	switch {
	case severity >= 3:
		return sarif.SeverityError
	case severity == 2:
		return sarif.SeverityWarning
	default:
		return sarif.SeverityNote
	}
}
