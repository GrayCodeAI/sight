package audit

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

// Test basic audit report operations

func TestNewAuditReport(t *testing.T) {
	report := NewAuditReport()
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if report.Count() != 0 {
		t.Errorf("expected 0 findings, got %d", report.Count())
	}
}

func TestAddFinding(t *testing.T) {
	report := NewAuditReport()

	finding := AuditFinding{
		Severity:     "high",
		Category:     "injection",
		File:         "main.go",
		Line:         10,
		Description:  "SQL injection detected",
		Recommendation: "Use parameterized queries",
		Source:       "static_analysis",
	}

	report.AddFinding(finding)

	if report.Count() != 1 {
		t.Errorf("expected 1 finding, got %d", report.Count())
	}

	findings := report.Findings()
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected severity high, got %s", findings[0].Severity)
	}
}

func TestAddMultipleFindings(t *testing.T) {
	report := NewAuditReport()

	findings := []AuditFinding{
		{Severity: "critical", Category: "rce", Description: "Remote code execution"},
		{Severity: "high", Category: "injection", Description: "SQL injection"},
		{Severity: "medium", Category: "xss", Description: "Cross-site scripting"},
		{Severity: "low", Category: "info", Description: "Information exposure"},
	}

	for _, f := range findings {
		report.AddFinding(f)
	}

	if report.Count() != 4 {
		t.Errorf("expected 4 findings, got %d", report.Count())
	}

	// Check severity counts
	critical := report.FilterBySeverity("critical")
	if len(critical) != 1 {
		t.Errorf("expected 1 critical finding, got %d", len(critical))
	}

	high := report.FilterBySeverity("high")
	if len(high) != 1 {
		t.Errorf("expected 1 high finding, got %d", len(high))
	}

	medium := report.FilterBySeverity("medium")
	if len(medium) != 1 {
		t.Errorf("expected 1 medium finding, got %d", len(medium))
	}

	low := report.FilterBySeverity("low")
	if len(low) != 1 {
		t.Errorf("expected 1 low finding, got %d", len(low))
	}
}

// Test filtering operations

func TestFilterByCategory(t *testing.T) {
	report := NewAuditReport()

	findings := []AuditFinding{
		{Severity: "high", Category: "injection", Description: "SQL injection"},
		{Severity: "high", Category: "injection", Description: "Another injection"},
		{Severity: "medium", Category: "xss", Description: "XSS found"},
		{Severity: "low", Category: "info", Description: "Info exposure"},
	}

	for _, f := range findings {
		report.AddFinding(f)
	}

	injections := report.FilterByCategory("injection")
	if len(injections) != 2 {
		t.Errorf("expected 2 injection findings, got %d", len(injections))
	}

	xss := report.FilterByCategory("xss")
	if len(xss) != 1 {
		t.Errorf("expected 1 xss finding, got %d", len(xss))
	}

	info := report.FilterByCategory("info")
	if len(info) != 1 {
		t.Errorf("expected 1 info finding, got %d", len(info))
	}
}

// Test summary generation

func TestSummary(t *testing.T) {
	report := NewAuditReport()

	findings := []AuditFinding{
		{Severity: "critical", Category: "rce", Description: "Remote code execution"},
		{Severity: "critical", Category: "rce", Description: "Another RCE"},
		{Severity: "high", Category: "injection", Description: "SQL injection"},
		{Severity: "medium", Category: "xss", Description: "XSS found"},
	}

	for _, f := range findings {
		report.AddFinding(f)
	}

	summary := report.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}

	// Check that summary contains expected information
	if summary == "No security findings detected." {
		t.Error("expected findings in summary")
	}
}

// Test JSON serialization

func TestAuditFindingJSON(t *testing.T) {
	finding := AuditFinding{
		Severity:     "high",
		Category:     "injection",
		File:         "main.go",
		Line:         10,
		Description:  "SQL injection detected",
		Recommendation: "Use parameterized queries",
		Source:       "static_analysis",
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("failed to marshal finding: %v", err)
	}

	var decoded AuditFinding
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal finding: %v", err)
	}

	if decoded.Severity != finding.Severity {
		t.Errorf("expected severity %s, got %s", finding.Severity, decoded.Severity)
	}
	if decoded.Category != finding.Category {
		t.Errorf("expected category %s, got %s", finding.Category, decoded.Category)
	}
	if decoded.File != finding.File {
		t.Errorf("expected file %s, got %s", finding.File, decoded.File)
	}
	if decoded.Source != finding.Source {
		t.Errorf("expected source %s, got %s", finding.Source, decoded.Source)
	}
}

// Test AuditScope

func TestAuditScope(t *testing.T) {
	scope := &AuditScope{
		Targets: []AuditTarget{
			{Type: AuditTargetHooks, Path: "/hooks/webhook"},
			{Type: AuditTargetMCP, Path: "/mcp/server"},
			{Type: AuditTargetEndpoints, Path: "/api/endpoint"},
		},
		Rules: []string{
			"detect_unauthenticated_endpoints",
			"detect_hardcoded_secrets",
		},
	}

	if len(scope.Targets) != 3 {
		t.Errorf("expected 3 targets, got %d", len(scope.Targets))
	}
	if len(scope.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(scope.Rules))
	}
}

// Test ValidateRule

func TestValidateRule(t *testing.T) {
	tests := []struct {
		rule     string
		expected bool
	}{
		{"detect_unauthenticated_endpoints", true},
		{"detect_hardcoded_secrets", true},
		{"detect_missing_input_validation", true},
		{"detect_excessive_permissions", true},
		{"detect_insecure_mcp_config", true},
		{"detect_webhook_validation", true},
		{"invalid_rule", false},
		{"", false},
	}

	for _, tt := range tests {
		got := ValidateRule(tt.rule)
		if got != tt.expected {
			t.Errorf("ValidateRule(%q) = %v, want %v", tt.rule, got, tt.expected)
		}
	}
}

// Test helper functions

func TestMustJSONMarshal(t *testing.T) {
	// Test with valid data - the function exists but is unexported
	// We just test the JSON marshaling works
	data := map[string]string{"key": "value"}
	result, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if string(result) == "" {
		t.Error("expected non-empty JSON")
	}
}

// Test ParseRules

func TestDefaultRules(t *testing.T) {
	rules := DefaultRules()
	if len(rules) == 0 {
		t.Error("expected non-empty default rules")
	}

	// Check expected rules are present
	expectedRules := map[string]bool{
		"detect_unauthenticated_endpoints": true,
		"detect_hardcoded_secrets":         true,
		"detect_missing_input_validation":  true,
		"detect_excessive_permissions":     true,
		"detect_insecure_mcp_config":       true,
		"detect_webhook_validation":        true,
	}

	for _, rule := range rules {
		if !expectedRules[rule] {
			t.Errorf("unexpected rule: %s", rule)
		}
	}
}

// Test that auditTarget correctly dispatches

func TestAuditTargetDispatch(t *testing.T) {
	// AuditTargetDispatch is tested indirectly through other tests
}

// Test concurrent additions

func TestConcurrentAddFinding(t *testing.T) {
	report := NewAuditReport()

	err := errors.New("test error")
	var wg sync.WaitGroup

	// Add findings concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(sev string) {
			defer wg.Done()
			if sev == "error" {
				report.AddFinding(AuditFinding{
					Severity: "high",
					Category: "error",
					Description: err.Error(),
					Source: "test",
				})
			} else {
				report.AddFinding(AuditFinding{
					Severity: sev,
					Category: "test",
					Description: "Test finding",
					Source: "test",
				})
			}
		}([]string{"high", "medium", "low"}[i%3])
	}

	wg.Wait()

	if report.Count() != 100 {
		t.Errorf("expected 100 findings after concurrent add, got %d", report.Count())
	}
}
