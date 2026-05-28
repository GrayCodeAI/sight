package sight

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSARIFOutput_BasicFindings(t *testing.T) {
	findings := []Finding{
		{
			Concern:  "security",
			Severity: SeverityHigh,
			File:     "src/auth.go",
			Line:     42,
			EndLine:  45,
			Message:  "SQL injection vulnerability in user query",
			Fix:      "Use parameterized queries",
			CWE:      "CWE-89",
		},
		{
			Concern:  "performance",
			Severity: SeverityMedium,
			File:     "src/handler.go",
			Line:     10,
			Message:  "Unnecessary allocation in hot path",
		},
	}

	sarif := GenerateSARIF(findings, "1.2.0")

	// Must be valid JSON
	var log sarifLog
	if err := json.Unmarshal([]byte(sarif), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	// Check SARIF version
	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", log.Version)
	}

	// Check schema URL
	if !strings.Contains(log.Schema, "sarif-schema-2.1.0.json") {
		t.Error("expected SARIF 2.1.0 schema URL")
	}

	// Must have exactly one run
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}

	run := log.Runs[0]

	// Check tool driver
	if run.Tool.Driver.Name != "sight" {
		t.Errorf("expected tool name 'sight', got %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "1.2.0" {
		t.Errorf("expected tool version '1.2.0', got %q", run.Tool.Driver.Version)
	}
	if run.Tool.Driver.InformationURI == "" {
		t.Error("expected informationUri to be set")
	}

	// Check results
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}

	// Check first result
	r0 := run.Results[0]
	if r0.RuleID != "security" {
		t.Errorf("expected ruleId 'security', got %q", r0.RuleID)
	}
	if r0.Level != "error" {
		t.Errorf("expected level 'error' for HIGH severity, got %q", r0.Level)
	}
	if !strings.Contains(r0.Message.Text, "SQL injection vulnerability") {
		t.Errorf("expected message to contain finding message, got %q", r0.Message.Text)
	}
	if !strings.Contains(r0.Message.Text, "Fix: Use parameterized queries") {
		t.Error("expected message to contain fix suggestion")
	}
	if len(r0.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r0.Locations))
	}
	if r0.Locations[0].PhysicalLocation == nil {
		t.Fatal("expected physicalLocation")
	}
	if r0.Locations[0].PhysicalLocation.ArtifactLocation.URI != "src/auth.go" {
		t.Errorf("unexpected URI: %s", r0.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	region := r0.Locations[0].PhysicalLocation.Region
	if region == nil {
		t.Fatal("expected region for line range")
	}
	if region.StartLine != 42 {
		t.Errorf("expected startLine 42, got %d", region.StartLine)
	}
	if region.EndLine != 45 {
		t.Errorf("expected endLine 45, got %d", region.EndLine)
	}

	// Check second result
	r1 := run.Results[1]
	if r1.RuleID != "performance" {
		t.Errorf("expected ruleId 'performance', got %q", r1.RuleID)
	}
	if r1.Level != "warning" {
		t.Errorf("expected level 'warning' for MEDIUM severity, got %q", r1.Level)
	}

	// Check rules
	rules := run.Tool.Driver.Rules
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	ruleIDs := make(map[string]bool)
	for _, r := range rules {
		ruleIDs[r.ID] = true
	}
	if !ruleIDs["security"] {
		t.Error("expected 'security' rule")
	}
	if !ruleIDs["performance"] {
		t.Error("expected 'performance' rule")
	}
}

func TestSARIFOutput_EmptyFindings(t *testing.T) {
	sarif := GenerateSARIF(nil, "1.0.0")

	var log sarifLog
	if err := json.Unmarshal([]byte(sarif), &log); err != nil {
		t.Fatalf("invalid SARIF JSON for empty findings: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", log.Version)
	}

	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}

	run := log.Runs[0]
	if len(run.Results) != 0 {
		t.Errorf("expected 0 results for empty findings, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 0 {
		t.Errorf("expected 0 rules for empty findings, got %d", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Name != "sight" {
		t.Errorf("expected tool name 'sight', got %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "1.0.0" {
		t.Errorf("expected tool version '1.0.0', got %q", run.Tool.Driver.Version)
	}
}

func TestSARIFOutput_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityCritical, "error"},
		{SeverityHigh, "error"},
		{SeverityMedium, "warning"},
		{SeverityLow, "note"},
		{SeverityInfo, "none"},
	}

	for _, tt := range tests {
		findings := []Finding{
			{
				Concern:  "test",
				Severity: tt.severity,
				File:     "test.go",
				Line:     1,
				Message:  "test finding",
			},
		}
		sarif := GenerateSARIF(findings, "test")

		var log sarifLog
		if err := json.Unmarshal([]byte(sarif), &log); err != nil {
			t.Fatalf("invalid SARIF JSON for severity %v: %v", tt.severity, err)
		}

		result := log.Runs[0].Results[0]
		if result.Level != tt.want {
			t.Errorf("severity %v: expected level %q, got %q", tt.severity, tt.want, result.Level)
		}
	}

	// Also test severityToSARIFLevel directly
	for _, tt := range tests {
		got := severityToSARIFLevel(tt.severity)
		if got != tt.want {
			t.Errorf("severityToSARIFLevel(%d) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestSARIFOutput_UnknownConcern(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityMedium, File: "test.go", Line: 5, Message: "no concern set"},
	}

	sarif := GenerateSARIF(findings, "test")

	var log sarifLog
	if err := json.Unmarshal([]byte(sarif), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if log.Runs[0].Results[0].RuleID != "unknown" {
		t.Errorf("expected ruleId 'unknown', got %q", log.Runs[0].Results[0].RuleID)
	}
}

func TestSARIFOutput_LocationWithoutLine(t *testing.T) {
	findings := []Finding{
		{Concern: "test", Severity: SeverityLow, File: "README.md", Message: "general issue"},
	}

	sarif := GenerateSARIF(findings, "test")

	var log sarifLog
	if err := json.Unmarshal([]byte(sarif), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	result := log.Runs[0].Results[0]
	if len(result.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(result.Locations))
	}
	loc := result.Locations[0]
	if loc.PhysicalLocation == nil {
		t.Fatal("expected physicalLocation")
	}
	if loc.PhysicalLocation.ArtifactLocation.URI != "README.md" {
		t.Errorf("unexpected URI: %s", loc.PhysicalLocation.ArtifactLocation.URI)
	}
	// No line info => no region
	if loc.PhysicalLocation.Region != nil {
		t.Error("expected no region when no line info")
	}
}

func TestSARIFOutput_DefaultVersion(t *testing.T) {
	sarif := GenerateSARIF(nil, "")

	var log sarifLog
	if err := json.Unmarshal([]byte(sarif), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if log.Runs[0].Tool.Driver.Version != "dev" {
		t.Errorf("expected 'dev' version for empty string, got %q", log.Runs[0].Tool.Driver.Version)
	}
}
