// Tests for SARIF emission. SARIF output is delegated to the shared
// github.com/GrayCodeAI/sarif package, which has its own structural tests;
// the tests here verify sight-specific behaviour (severity mapping, rule
// IDs, CWE handling, location population).
//
// Tests parse the JSON output via local minimal types rather than
// re-exporting the wire format.

package output

import (
	"encoding/json"
	"strings"
	"testing"
)

// Minimal SARIF wire model — covers only the fields the tests assert on.
type testSarifLog struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name  string
				Rules []struct {
					ID   string
					Name string
				}
			}
		}
		Results []struct {
			RuleID    string `json:"ruleId"`
			Level     string
			Message   struct{ Text string }
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					Region           *struct {
						StartLine int `json:"startLine"`
						EndLine   int `json:"endLine"`
					}
				} `json:"physicalLocation"`
			}
			Fixes []struct {
				Description struct{ Text string }
			}
			Taxa []struct {
				ID            string
				ToolComponent struct{ Text string }
			}
		}
	}
	Version string
}

func parseSARIF(t *testing.T, raw string) testSarifLog {
	t.Helper()
	var log testSarifLog
	if err := json.Unmarshal([]byte(raw), &log); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}
	return log
}

func TestFormatSARIF_EmptyFindings(t *testing.T) {
	out, err := FormatSARIF(nil)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}

	log := parseSARIF(t, out)

	if log.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(log.Runs[0].Results))
	}
	if log.Runs[0].Tool.Driver.Name != "sight" {
		t.Errorf("expected tool name 'sight', got %q", log.Runs[0].Tool.Driver.Name)
	}
}

func TestFormatSARIF_WithFindings(t *testing.T) {
	findings := []Finding{
		{
			Concern: "security", Severity: 4,
			File: "handler.go", Line: 13, EndLine: 14,
			Message: "SQL injection via string concatenation",
			Fix:     "Use parameterized queries",
		},
		{
			Concern: "bugs", Severity: 3,
			File: "util.go", Line: 25,
			Message: "Nil pointer dereference",
		},
	}

	out, err := FormatSARIF(findings)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}
	log := parseSARIF(t, out)

	if len(log.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(log.Runs[0].Results))
	}

	r0 := log.Runs[0].Results[0]
	if r0.RuleID != "sight/security" {
		t.Errorf("expected ruleId 'sight/security', got %q", r0.RuleID)
	}
	if r0.Level != "error" {
		t.Errorf("expected level 'error' for critical, got %q", r0.Level)
	}
	if r0.Message.Text != "SQL injection via string concatenation" {
		t.Errorf("unexpected message: %q", r0.Message.Text)
	}
	if len(r0.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r0.Locations))
	}
	if r0.Locations[0].PhysicalLocation.ArtifactLocation.URI != "handler.go" {
		t.Errorf("unexpected URI: %q", r0.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if r0.Locations[0].PhysicalLocation.Region == nil {
		t.Fatal("expected non-nil region")
	}
	if r0.Locations[0].PhysicalLocation.Region.StartLine != 13 {
		t.Errorf("expected startLine 13, got %d", r0.Locations[0].PhysicalLocation.Region.StartLine)
	}
	if r0.Locations[0].PhysicalLocation.Region.EndLine != 14 {
		t.Errorf("expected endLine 14, got %d", r0.Locations[0].PhysicalLocation.Region.EndLine)
	}
	if len(r0.Fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(r0.Fixes))
	}
	if r0.Fixes[0].Description.Text != "Use parameterized queries" {
		t.Errorf("unexpected fix: %q", r0.Fixes[0].Description.Text)
	}

	r1 := log.Runs[0].Results[1]
	if r1.RuleID != "sight/bugs" {
		t.Errorf("expected ruleId 'sight/bugs', got %q", r1.RuleID)
	}
	if r1.Level != "error" {
		t.Errorf("expected level 'error' for high severity, got %q", r1.Level)
	}
	if len(r1.Fixes) != 0 {
		t.Errorf("expected 0 fixes for finding without fix, got %d", len(r1.Fixes))
	}
}

func TestFormatSARIF_WithCWE(t *testing.T) {
	findings := []Finding{
		{
			Concern: "security", Severity: 4,
			File: "handler.go", Line: 10,
			Message: "SQL injection",
			CWE:     "CWE-89",
		},
	}

	out, err := FormatSARIF(findings)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}
	log := parseSARIF(t, out)

	result := log.Runs[0].Results[0]
	if len(result.Taxa) != 1 {
		t.Fatalf("expected 1 taxa reference, got %d", len(result.Taxa))
	}
	if result.Taxa[0].ID != "CWE-89" {
		t.Errorf("expected CWE-89, got %q", result.Taxa[0].ID)
	}
	if result.Taxa[0].ToolComponent.Text != "CWE" {
		t.Errorf("expected toolComponent 'CWE', got %q", result.Taxa[0].ToolComponent.Text)
	}
}

func TestFormatSARIF_SeverityLevels(t *testing.T) {
	findings := []Finding{
		{Concern: "a", Severity: 4, File: "a.go", Line: 1, Message: "critical"},
		{Concern: "b", Severity: 3, File: "b.go", Line: 1, Message: "high"},
		{Concern: "c", Severity: 2, File: "c.go", Line: 1, Message: "medium"},
		{Concern: "d", Severity: 1, File: "d.go", Line: 1, Message: "low"},
		{Concern: "e", Severity: 0, File: "e.go", Line: 1, Message: "info"},
	}

	out, err := FormatSARIF(findings)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}
	log := parseSARIF(t, out)

	expected := []string{"error", "error", "warning", "note", "note"}
	for i, r := range log.Runs[0].Results {
		if r.Level != expected[i] {
			t.Errorf("result[%d]: expected level %q, got %q", i, expected[i], r.Level)
		}
	}
}

func TestFormatSARIF_NoFile(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: 2, Message: "General security concern"},
	}

	out, err := FormatSARIF(findings)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}
	log := parseSARIF(t, out)

	if len(log.Runs[0].Results[0].Locations) != 0 {
		t.Errorf("expected 0 locations for finding without file, got %d",
			len(log.Runs[0].Results[0].Locations))
	}
}

func TestFormatSARIF_NoLineNumber(t *testing.T) {
	findings := []Finding{
		{
			Concern: "security", Severity: 2, File: "handler.go", Line: 0,
			Message: "File-level concern",
		},
	}

	out, err := FormatSARIF(findings)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}
	log := parseSARIF(t, out)

	result := log.Runs[0].Results[0]
	if len(result.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(result.Locations))
	}
	if result.Locations[0].PhysicalLocation.Region != nil {
		t.Error("expected nil region for line=0")
	}
}

func TestFormatSARIF_EndLineFallback(t *testing.T) {
	findings := []Finding{
		{
			Concern: "bugs", Severity: 2, File: "main.go", Line: 42, EndLine: 0,
			Message: "Issue",
		},
	}

	out, err := FormatSARIF(findings)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}
	log := parseSARIF(t, out)

	region := log.Runs[0].Results[0].Locations[0].PhysicalLocation.Region
	if region == nil {
		t.Fatal("expected non-nil region")
	}
	if region.EndLine != 42 {
		t.Errorf("expected endLine to fallback to 42, got %d", region.EndLine)
	}
}

func TestFormatSARIF_RulesDedup(t *testing.T) {
	findings := []Finding{
		{Concern: "security", Severity: 4, File: "a.go", Line: 1, Message: "issue 1"},
		{Concern: "security", Severity: 3, File: "b.go", Line: 2, Message: "issue 2"},
		{Concern: "bugs", Severity: 2, File: "c.go", Line: 3, Message: "issue 3"},
	}

	out, err := FormatSARIF(findings)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}
	log := parseSARIF(t, out)

	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 2 {
		t.Errorf("expected 2 deduplicated rules, got %d", len(rules))
	}
}

func TestFormatSARIF_ValidJSON(t *testing.T) {
	findings := []Finding{
		{
			Concern: "security", Severity: 4, File: "a.go", Line: 1,
			Message: "test with \"quotes\" and special <chars>",
		},
	}

	out, err := FormatSARIF(findings)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}
	if !json.Valid([]byte(out)) {
		t.Error("output is not valid JSON")
	}
}

func TestFormatSARIF_SchemaURL(t *testing.T) {
	out, err := FormatSARIF(nil)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}
	if !strings.Contains(out, "sarif-schema-2.1.0") {
		t.Error("expected SARIF schema URL in output")
	}
}

func TestSeverityToSARIF(t *testing.T) {
	tests := []struct {
		severity int
		expected string
	}{
		{4, "error"},
		{3, "error"},
		{2, "warning"},
		{1, "note"},
		{0, "note"},
		{5, "error"}, // anything >= 3
	}

	for _, tc := range tests {
		got := severityToSARIF(tc.severity)
		// Compare against the SARIF wire-level string by emitting a
		// single-result builder and reading the level out.
		findings := []Finding{
			{Concern: "x", Severity: tc.severity, File: "f", Line: 1, Message: "m"},
		}
		out, _ := FormatSARIF(findings)
		log := parseSARIF(t, out)
		if log.Runs[0].Results[0].Level != tc.expected {
			t.Errorf("severityToSARIF(%d) → %v; expected level %q",
				tc.severity, got, tc.expected)
		}
	}
}
