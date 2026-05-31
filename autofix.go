package sight

import (
	"context"
	"fmt"
	"strings"
)

// AutoFix generates fix suggestions for findings.
// Instead of just reporting problems, suggests concrete code changes.
type AutoFix struct {
	provider Provider
}

// FixSuggestion is a proposed code change to resolve a finding.
type FixSuggestion struct {
	Finding     *Finding
	FixedCode   string  // the corrected code
	Explanation string  // why this fix works
	Confidence  float64 // 0-1 how confident the fix is correct

	// Additional fields used by the pattern-based fix pipeline (fix_pipeline.go).

	// FindingID links this suggestion back to the originating Finding.
	FindingID string `json:"finding_id"`
	// Title is a short, human-readable summary of the fix.
	Title string `json:"title"`
	// Description explains why the fix is needed and what it does.
	Description string `json:"description"`
	// FixCode contains the suggested code or configuration change.
	FixCode string `json:"fix_code"`
	// Category classifies the fix area, e.g. "input-validation", "auth",
	// "crypto", "injection", "xss", "ssrf".
	Category string `json:"category"`
	// Severity mirrors the severity of the original finding.
	Severity string `json:"severity"`
	// EstimatedEffort indicates how much work the fix requires:
	// "trivial", "easy", "moderate", or "complex".
	EstimatedEffort string `json:"estimated_effort"`
	// Priority ranks this suggestion (1 = highest, 5 = lowest).
	Priority int `json:"priority"`
}

// NewAutoFix creates an auto-fixer using the given LLM provider.
func NewAutoFix(provider Provider) *AutoFix {
	return &AutoFix{provider: provider}
}

// SuggestFixes generates fix suggestions for a set of findings.
func (af *AutoFix) SuggestFixes(ctx context.Context, findings []Finding, diff string) ([]FixSuggestion, error) {
	if af.provider == nil || len(findings) == 0 {
		return nil, nil
	}

	var suggestions []FixSuggestion
	for _, f := range findings {
		if f.Severity == SeverityInfo {
			continue // skip informational
		}
		suggestion := af.generateFix(ctx, f, diff)
		if suggestion != nil {
			suggestions = append(suggestions, *suggestion)
		}
	}
	return suggestions, nil
}

func (af *AutoFix) generateFix(ctx context.Context, f Finding, diff string) *FixSuggestion {
	prompt := fmt.Sprintf(`You found this issue in a code review:

File: %s (line %d)
Severity: %s
Issue: %s

Here's the relevant diff:
%s

Suggest a concrete fix. Reply with ONLY:
1. The corrected code (just the fixed lines)
2. A one-sentence explanation

Format:
FIXED:
<code>
EXPLANATION: <why>`, f.File, f.Line, f.Severity, f.Message, extractRelevantDiff(diff, f.File, f.Line))

	result, err := af.provider.Chat(ctx, []Message{{Role: "user", Content: prompt}}, ChatOpts{})
	if err != nil || result == nil || result.Content == "" {
		return nil
	}
	resp := result.Content

	return parseFixResponse(resp, &f)
}

func parseFixResponse(resp string, f *Finding) *FixSuggestion {
	fixedIdx := strings.Index(resp, "FIXED:")
	explIdx := strings.Index(resp, "EXPLANATION:")

	if fixedIdx < 0 {
		return nil
	}

	var fixedCode, explanation string
	if explIdx > fixedIdx {
		fixedCode = strings.TrimSpace(resp[fixedIdx+6 : explIdx])
		explanation = strings.TrimSpace(resp[explIdx+12:])
	} else {
		fixedCode = strings.TrimSpace(resp[fixedIdx+6:])
	}

	if fixedCode == "" {
		return nil
	}

	return &FixSuggestion{
		Finding:     f,
		FixedCode:   fixedCode,
		Explanation: explanation,
		Confidence:  0.7,
	}
}

func extractRelevantDiff(diff, file string, line int) string {
	lines := strings.Split(diff, "\n")
	var relevant []string
	inFile := false
	lineCount := 0

	for _, l := range lines {
		if strings.HasPrefix(l, "diff --git") || strings.HasPrefix(l, "--- ") || strings.HasPrefix(l, "+++ ") {
			if strings.Contains(l, file) {
				inFile = true
			} else if inFile {
				break
			}
			continue
		}
		if inFile {
			lineCount++
			if lineCount >= line-5 && lineCount <= line+5 {
				relevant = append(relevant, l)
			}
		}
	}

	result := strings.Join(relevant, "\n")
	if len(result) > 500 {
		result = result[:500]
	}
	return result
}
