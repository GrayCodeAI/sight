package sight

import "testing"

func TestToContractResult(t *testing.T) {
	t.Parallel()

	result := &Result{
		Findings: []Finding{
			{
				Concern:    "security",
				Severity:   SeverityHigh,
				File:       "main.go",
				Line:       12,
				Message:    "issue",
				Fix:        "fix",
				Confidence: 0.9,
			},
		},
		Comments: []InlineComment{{Path: "main.go", StartLine: 12, Body: "comment"}},
		Stats: Stats{
			FilesReviewed: 1,
			FindingsTotal: 1,
			BySeverity:    map[Severity]int{SeverityHigh: 1},
			ByConcern:     map[string]int{"security": 1},
			TokensUsed:    42,
		},
		Report: "report",
		FailOn: SeverityMedium,
		ConfidenceBreakdown: &ConfidenceBreakdown{
			High: []Finding{{Concern: "security", Severity: SeverityHigh, File: "main.go", Line: 12, Message: "issue", Confidence: 0.9}},
		},
	}

	got := ToContractResult(result)
	if got == nil {
		t.Fatal("expected non-nil contract result")
	}
	if got.Report != "report" {
		t.Fatalf("Report = %q, want report", got.Report)
	}
	if len(got.Findings) != 1 || got.Findings[0].Severity != SeverityHigh {
		t.Fatalf("unexpected findings conversion: %+v", got.Findings)
	}
	if got.Stats.TokensUsed != 42 {
		t.Fatalf("TokensUsed = %d, want 42", got.Stats.TokensUsed)
	}
	if got.ConfidenceBreakdown == nil || len(got.ConfidenceBreakdown.High) != 1 {
		t.Fatal("expected confidence breakdown to convert")
	}
}
