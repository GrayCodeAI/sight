package output

import (
	"strings"
	"testing"
	"time"
)

func TestFormatTerminal_NoFindings(t *testing.T) {
	out := FormatTerminal(nil, Stats{FilesReviewed: 5, HunksAnalyzed: 10})
	if !strings.Contains(out, "No issues found") {
		t.Error("expected 'No issues found' for empty findings")
	}
	if !strings.Contains(out, "5 files") {
		t.Error("expected file count in header")
	}
}

func TestFormatTerminal_WithFindings(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: 4, File: "main.go", Line: 10, Message: "SQL injection", Fix: "use params"},
		{Concern: "bugs", Severity: 3, File: "handler.go", Line: 20, Message: "nil deref", Reasoning: "pointer not checked"},
		{Concern: "style", Severity: 1, File: "util.go", Line: 5, Message: "long function"},
	}
	stats := Stats{
		FilesReviewed: 3,
		HunksAnalyzed: 5,
		FindingsTotal: 3,
		TokensUsed:    1500,
		BySeverity:    map[int]int{4: 1, 3: 1, 1: 1},
		ByConcern:     map[string]int{"security": 1, "bugs": 1, "style": 1},
		DurationPerConcern: map[string]time.Duration{
			"security": 200 * time.Millisecond,
			"bugs":     150 * time.Millisecond,
		},
	}

	out := FormatTerminal(findings, stats)
	if !strings.Contains(out, "CRITICAL") {
		t.Error("expected CRITICAL section")
	}
	if !strings.Contains(out, "SQL injection") {
		t.Error("expected finding message")
	}
	if !strings.Contains(out, "main.go:10") {
		t.Error("expected file:line location")
	}
	if !strings.Contains(out, "SUMMARY: 3 findings") {
		t.Error("expected summary line")
	}
	if !strings.Contains(out, "1500 tokens") {
		t.Error("expected token count")
	}
}

func TestFormatJSON(t *testing.T) {
	findings := []Finding{
		{Concern: "bugs", Severity: 3, File: "x.go", Line: 1, Message: "test"},
	}
	out, err := FormatJSON(findings)
	if err != nil {
		t.Fatalf("FormatJSON error: %v", err)
	}
	if !strings.Contains(out, "test") {
		t.Error("expected finding in JSON output")
	}
}

func TestFormatGitHubReview_Empty(t *testing.T) {
	out := FormatGitHubReview(nil)
	if !strings.Contains(out, "No issues found") {
		t.Error("expected no-issues message")
	}
}

func TestFormatGitHubReview_WithFindings(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: 4, File: "api.go", Line: 42, Message: "XSS", Fix: "escape output"},
	}
	out := FormatGitHubReview(findings)
	if !strings.Contains(out, "CRITICAL") {
		t.Error("expected severity label")
	}
	if !strings.Contains(out, "api.go:42") {
		t.Error("expected location")
	}
}
