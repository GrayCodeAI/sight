package review

import (
	"testing"
)

func TestParseResponse_ValidJSON(t *testing.T) {
	response := `[
		{
			"file": "main.go",
			"line": 42,
			"end_line": 45,
			"severity": "high",
			"message": "Unchecked error return",
			"fix": "Add error check: if err != nil { return err }",
			"reasoning": "Ignoring errors can lead to silent failures"
		},
		{
			"file": "handler.go",
			"line": 15,
			"severity": "critical",
			"message": "SQL injection via string concatenation",
			"fix": "Use parameterized query",
			"reasoning": "User input is directly concatenated into SQL"
		}
	]`

	findings := ParseResponse(response, "security")
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].File != "main.go" {
		t.Errorf("expected main.go, got %s", findings[0].File)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected high, got %v", findings[0].Severity)
	}
	if findings[0].Concern != "security" {
		t.Errorf("expected security concern, got %s", findings[0].Concern)
	}
	if findings[1].Severity != SeverityCritical {
		t.Errorf("expected critical, got %v", findings[1].Severity)
	}
}

func TestParseResponse_MarkdownWrapped(t *testing.T) {
	response := "Here are the findings:\n\n```json\n" + `[
		{
			"file": "auth.go",
			"line": 10,
			"severity": "high",
			"message": "Hardcoded secret",
			"fix": "Use environment variable",
			"reasoning": "Secrets in code can be leaked via VCS"
		}
	]` + "\n```\n\nLet me know if you have questions."

	findings := ParseResponse(response, "security")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].File != "auth.go" {
		t.Errorf("expected auth.go, got %s", findings[0].File)
	}
}

func TestParseResponse_EmptyArray(t *testing.T) {
	response := "[]"
	findings := ParseResponse(response, "bugs")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseResponse_InvalidJSON(t *testing.T) {
	response := "I found no issues with this code."
	findings := ParseResponse(response, "bugs")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings from non-JSON response, got %d", len(findings))
	}
}

func TestParseResponse_MissingRequiredFields(t *testing.T) {
	response := `[
		{"severity": "high", "message": "something"},
		{"file": "x.go", "line": 1, "severity": "low", "message": "valid finding", "fix": "do this"}
	]`
	findings := ParseResponse(response, "bugs")
	if len(findings) != 1 {
		t.Fatalf("expected 1 valid finding (skipping one without file), got %d", len(findings))
	}
	if findings[0].File != "x.go" {
		t.Errorf("expected x.go, got %s", findings[0].File)
	}
}

func TestParseResponse_LeadingText(t *testing.T) {
	response := `Based on my analysis, here are the issues I found:

[{"file": "server.go", "line": 88, "severity": "medium", "message": "Missing context timeout", "fix": "Add context.WithTimeout", "reasoning": "Long-running requests without timeout can exhaust resources"}]`

	findings := ParseResponse(response, "performance")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Concern != "performance" {
		t.Errorf("expected performance concern, got %s", findings[0].Concern)
	}
}

func TestParseResponse_AllSeverities(t *testing.T) {
	response := `[
		{"file": "a.go", "line": 1, "severity": "critical", "message": "a", "fix": "x"},
		{"file": "b.go", "line": 2, "severity": "high", "message": "b", "fix": "x"},
		{"file": "c.go", "line": 3, "severity": "medium", "message": "c", "fix": "x"},
		{"file": "d.go", "line": 4, "severity": "low", "message": "d", "fix": "x"},
		{"file": "e.go", "line": 5, "severity": "info", "message": "e", "fix": "x"}
	]`
	findings := ParseResponse(response, "style")
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}

	expected := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	for i, f := range findings {
		if f.Severity != expected[i] {
			t.Errorf("finding %d: expected %v, got %v", i, expected[i], f.Severity)
		}
	}
}
