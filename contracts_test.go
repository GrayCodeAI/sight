package sight

import (
	"context"
	"testing"
)

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

func TestToContractResult_FailOnThresholdTakesEffect(t *testing.T) {
	t.Parallel()

	// A below-critical threshold configured on the sight Result must
	// survive conversion: the contract's Failed() honors it only when
	// FailOnSet is true, which ToContractResult must arrange via SetFailOn.
	result := &Result{
		FailOn: SeverityHigh,
		Findings: []Finding{
			{Severity: SeverityInfo, Message: "note", Confidence: 0.5},
		},
	}

	contract := ToContractResult(result)
	if !contract.FailOnSet {
		t.Fatal("FailOnSet = false, want true after conversion")
	}
	if contract.FailOn != SeverityHigh {
		t.Fatalf("FailOn = %v, want high", contract.FailOn)
	}
	if contract.Failed() {
		t.Error("info finding must not fail a review with a high threshold")
	}

	result.Findings = append(result.Findings, Finding{
		Severity: SeverityHigh, Message: "real problem", Confidence: 0.5,
	})
	contract = ToContractResult(result)
	if !contract.Failed() {
		t.Error("high finding must fail a review with a high threshold")
	}
}

func TestToContractResult_FailOnConfiguredViaOptions(t *testing.T) {
	t.Parallel()

	reviewWith := func(response string) *Result {
		t.Helper()
		r := NewReviewer(
			WithProvider(&fixMockProvider{response: response}),
			WithFailOn(SeverityHigh),
			WithConcerns("security"),
			WithParallel(false),
		)
		result, err := r.Review(context.Background(), sampleDiff)
		if err != nil {
			t.Fatalf("Review failed: %v", err)
		}
		return result
	}

	infoOnly := reviewWith(`[{"file": "handler.go", "line": 13, "severity": "info", "message": "style nit", "fix": "n/a"}]`)
	if got := ToContractResult(infoOnly).Failed(); got {
		t.Error("Failed() = true for info-only findings with failOn=high, want false")
	}

	highFinding := reviewWith(`[{"file": "handler.go", "line": 13, "severity": "high", "message": "SQL injection", "fix": "use params"}]`)
	if got := ToContractResult(highFinding).Failed(); !got {
		t.Error("Failed() = false for a high finding with failOn=high, want true")
	}
}
