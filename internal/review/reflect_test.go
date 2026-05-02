package review

import (
	"strings"
	"testing"
)

func TestBuildReflectPrompt_Basic(t *testing.T) {
	findings := []Finding{
		{
			Concern:  "security",
			Severity: SeverityCritical,
			File:     "handler.go",
			Line:     13,
			Message:  "SQL injection via string concatenation",
			Fix:      "Use parameterized queries",
		},
		{
			Concern:  "bugs",
			Severity: SeverityHigh,
			File:     "handler.go",
			Line:     15,
			Message:  "Unchecked error return",
		},
	}

	prompt := BuildReflectPrompt(findings, "diff content here")
	if !strings.Contains(prompt, "SQL injection") {
		t.Error("expected finding message in prompt")
	}
	if !strings.Contains(prompt, "handler.go:13") {
		t.Error("expected file:line in prompt")
	}
	if !strings.Contains(prompt, "security") {
		t.Error("expected concern name in prompt")
	}
	if !strings.Contains(prompt, "Use parameterized queries") {
		t.Error("expected fix in prompt")
	}
	if !strings.Contains(prompt, "diff content here") {
		t.Error("expected diff context in prompt")
	}
	if !strings.Contains(prompt, "Findings to validate") {
		t.Error("expected section header in prompt")
	}
}

func TestBuildReflectPrompt_LongDiff(t *testing.T) {
	longDiff := strings.Repeat("x", 10000)
	findings := []Finding{
		{Concern: "security", Severity: SeverityHigh, File: "a.go", Line: 1, Message: "issue"},
	}

	prompt := BuildReflectPrompt(findings, longDiff)
	if !strings.Contains(prompt, "truncated") {
		t.Error("expected truncation notice for long diff")
	}
	// Should not contain the full string
	if strings.Contains(prompt, longDiff) {
		t.Error("long diff should be truncated")
	}
}

func TestBuildReflectPrompt_ShortDiff(t *testing.T) {
	findings := []Finding{
		{Concern: "bugs", Severity: SeverityLow, File: "a.go", Line: 1, Message: "minor"},
	}

	prompt := BuildReflectPrompt(findings, "short diff")
	if strings.Contains(prompt, "truncated") {
		t.Error("short diff should not be truncated")
	}
	if !strings.Contains(prompt, "short diff") {
		t.Error("expected full diff content")
	}
}

func TestParseReflectResponse_Valid(t *testing.T) {
	response := `[
		{"index": 0, "action": "keep", "severity": "critical", "score": 8, "message": "Valid finding", "reason": "confirmed"},
		{"index": 1, "action": "drop", "severity": "", "score": 2, "message": "", "reason": "false positive"},
		{"index": 2, "action": "adjust", "severity": "medium", "score": 5, "message": "Adjusted", "reason": "not as severe"}
	]`

	results := ParseReflectResponse(response)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Action != "keep" {
		t.Errorf("expected 'keep', got %q", results[0].Action)
	}
	if results[0].Score != 8 {
		t.Errorf("expected score 8, got %d", results[0].Score)
	}
	if results[1].Action != "drop" {
		t.Errorf("expected 'drop', got %q", results[1].Action)
	}
	if results[2].Action != "adjust" {
		t.Errorf("expected 'adjust', got %q", results[2].Action)
	}
	if results[2].Severity != "medium" {
		t.Errorf("expected severity 'medium', got %q", results[2].Severity)
	}
}

func TestParseReflectResponse_MarkdownWrapped(t *testing.T) {
	response := "Here are the results:\n\n```json\n" +
		`[{"index": 0, "action": "keep", "severity": "high", "score": 7, "message": "ok", "reason": "valid"}]` +
		"\n```\n"

	results := ParseReflectResponse(response)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestParseReflectResponse_InvalidJSON(t *testing.T) {
	results := ParseReflectResponse("not json at all")
	if len(results) != 0 {
		t.Errorf("expected 0 results for invalid JSON, got %d", len(results))
	}
}

func TestParseReflectResponse_Empty(t *testing.T) {
	results := ParseReflectResponse("[]")
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty array, got %d", len(results))
	}
}

func TestApplyReflection_KeepAll(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: SeverityCritical, File: "a.go", Line: 1, Message: "issue 1"},
		{Concern: "bugs", Severity: SeverityHigh, File: "b.go", Line: 2, Message: "issue 2"},
	}
	reflections := []ReflectResult{
		{Index: 0, Action: "keep", Severity: "critical", Score: 9, Message: "issue 1"},
		{Index: 1, Action: "keep", Severity: "high", Score: 8, Message: "issue 2"},
	}

	result := ApplyReflection(findings, reflections)
	if len(result) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result))
	}
}

func TestApplyReflection_DropOne(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: SeverityCritical, File: "a.go", Line: 1, Message: "real issue"},
		{Concern: "bugs", Severity: SeverityHigh, File: "b.go", Line: 2, Message: "false positive"},
	}
	reflections := []ReflectResult{
		{Index: 0, Action: "keep", Severity: "critical", Score: 9, Message: "real issue"},
		{Index: 1, Action: "drop", Reason: "not actually a bug"},
	}

	result := ApplyReflection(findings, reflections)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding after drop, got %d", len(result))
	}
	if result[0].Message != "real issue" {
		t.Errorf("expected 'real issue', got %q", result[0].Message)
	}
}

func TestApplyReflection_AdjustSeverity(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: SeverityCritical, File: "a.go", Line: 1, Message: "issue"},
	}
	reflections := []ReflectResult{
		{Index: 0, Action: "adjust", Severity: "medium", Score: 5, Message: "Adjusted issue"},
	}

	result := ApplyReflection(findings, reflections)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Severity != SeverityMedium {
		t.Errorf("expected medium severity, got %v", result[0].Severity)
	}
	if result[0].Message != "Adjusted issue" {
		t.Errorf("expected 'Adjusted issue', got %q", result[0].Message)
	}
}

func TestApplyReflection_NoReflections(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: SeverityHigh, File: "a.go", Line: 1, Message: "issue"},
	}

	result := ApplyReflection(findings, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 finding when no reflections, got %d", len(result))
	}
}

func TestApplyReflection_UnmappedFinding(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: SeverityHigh, File: "a.go", Line: 1, Message: "issue 1"},
		{Concern: "bugs", Severity: SeverityMedium, File: "b.go", Line: 2, Message: "issue 2"},
	}
	// Only reflect on index 0; index 1 should be kept as-is
	reflections := []ReflectResult{
		{Index: 0, Action: "drop"},
	}

	result := ApplyReflection(findings, reflections)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Message != "issue 2" {
		t.Errorf("expected 'issue 2', got %q", result[0].Message)
	}
}

func TestApplyReflectionWithScore_FilterLowScore(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: SeverityHigh, File: "a.go", Line: 1, Message: "high confidence"},
		{Concern: "style", Severity: SeverityLow, File: "b.go", Line: 2, Message: "low confidence"},
	}
	reflections := []ReflectResult{
		{Index: 0, Action: "keep", Score: 8},
		{Index: 1, Action: "keep", Score: 2},
	}

	result := ApplyReflectionWithScore(findings, reflections, 5)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding after score filter, got %d", len(result))
	}
	if result[0].Message != "high confidence" {
		t.Errorf("expected 'high confidence', got %q", result[0].Message)
	}
}

func TestApplyReflectionWithScore_ZeroMinScore(t *testing.T) {
	findings := []Finding{
		{Concern: "bugs", Severity: SeverityLow, File: "a.go", Line: 1, Message: "issue"},
	}
	reflections := []ReflectResult{
		{Index: 0, Action: "keep", Score: 1},
	}

	// minScore=0 disables score filtering
	result := ApplyReflectionWithScore(findings, reflections, 0)
	if len(result) != 1 {
		t.Errorf("expected 1 finding with minScore=0, got %d", len(result))
	}
}

func TestApplyReflectionWithScore_AdjustWithLowScore(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: SeverityCritical, File: "a.go", Line: 1, Message: "issue"},
	}
	reflections := []ReflectResult{
		{Index: 0, Action: "adjust", Severity: "medium", Score: 2, Message: "adjusted"},
	}

	result := ApplyReflectionWithScore(findings, reflections, 5)
	if len(result) != 0 {
		t.Errorf("expected 0 findings (adjusted but low score), got %d", len(result))
	}
}

func TestApplyReflection_KeepWithNewMessage(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: SeverityHigh, File: "a.go", Line: 1, Message: "original"},
	}
	reflections := []ReflectResult{
		{Index: 0, Action: "keep", Message: "refined message"},
	}

	result := ApplyReflection(findings, reflections)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Message != "refined message" {
		t.Errorf("expected 'refined message', got %q", result[0].Message)
	}
}

func TestApplyReflection_KeepWithSameMessage(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: SeverityHigh, File: "a.go", Line: 1, Message: "original"},
	}
	reflections := []ReflectResult{
		{Index: 0, Action: "keep", Message: "original"},
	}

	result := ApplyReflection(findings, reflections)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Message != "original" {
		t.Errorf("expected 'original', got %q", result[0].Message)
	}
}

func TestSeverityStr(t *testing.T) {
	tests := []struct {
		sev      Severity
		expected string
	}{
		{SeverityInfo, "info"},
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	}

	for _, tc := range tests {
		result := severityStr(tc.sev)
		if result != tc.expected {
			t.Errorf("severityStr(%d): expected %q, got %q", tc.sev, tc.expected, result)
		}
	}
}

func TestExtractReflectJSON_PlainJSON(t *testing.T) {
	input := `[{"index": 0, "action": "keep"}]`
	result := extractReflectJSON(input)
	if result != input {
		t.Errorf("expected %q, got %q", input, result)
	}
}

func TestExtractReflectJSON_Wrapped(t *testing.T) {
	input := "Here are results:\n\n```json\n[{\"index\": 0}]\n```\n"
	result := extractReflectJSON(input)
	if result != `[{"index": 0}]` {
		t.Errorf("unexpected result: %q", result)
	}
}

func TestExtractReflectJSON_NoArray(t *testing.T) {
	result := extractReflectJSON("no array here")
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestReflectSystemPrompt_NotEmpty(t *testing.T) {
	if ReflectSystemPrompt == "" {
		t.Error("expected non-empty reflect system prompt")
	}
	if !strings.Contains(ReflectSystemPrompt, "KEEP") {
		t.Error("expected KEEP instruction in prompt")
	}
	if !strings.Contains(ReflectSystemPrompt, "DROP") {
		t.Error("expected DROP instruction in prompt")
	}
	if !strings.Contains(ReflectSystemPrompt, "ADJUST") {
		t.Error("expected ADJUST instruction in prompt")
	}
}
