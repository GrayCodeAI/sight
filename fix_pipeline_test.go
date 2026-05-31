package sight

import (
	"strings"
	"testing"
)

// =====================================================================
// 1. NewFixPipeline creates pipeline with built-in rules
// =====================================================================

func TestNewFixPipeline_HasBuiltinRules(t *testing.T) {
	p := NewFixPipeline()
	if p == nil {
		t.Fatal("expected non-nil FixPipeline")
	}
	if len(p.rules) != 7 {
		t.Fatalf("expected 7 built-in rules, got %d", len(p.rules))
	}
}

// =====================================================================
// 2. SQL injection finding generates parameterized query fix
// =====================================================================

func TestGenerateFixes_SQLInjection(t *testing.T) {
	p := NewFixPipeline()
	findings := []Finding{
		{
			Concern:  "sql injection in query builder",
			Severity: SeverityHigh,
			File:     "db/query.go",
			Line:     42,
			Message:  "string concatenation used to build SQL query",
			CWE:      "CWE-89",
		},
	}

	fixes := p.GenerateFixes(findings)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}

	fix := fixes[0]
	if fix.Category != "injection" {
		t.Errorf("expected category 'injection', got %q", fix.Category)
	}
	if fix.Priority != 1 {
		t.Errorf("expected priority 1, got %d", fix.Priority)
	}
	if fix.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %f", fix.Confidence)
	}
	if !strings.Contains(fix.Title, "parameterized") {
		t.Errorf("expected title to mention parameterized queries, got %q", fix.Title)
	}
	if !strings.Contains(fix.FixCode, "db.Query") {
		t.Errorf("expected fix code to contain 'db.Query', got %q", fix.FixCode)
	}
	if fix.FindingID == "" {
		t.Error("expected non-empty FindingID")
	}
}

// =====================================================================
// 3. XSS finding generates escaping fix
// =====================================================================

func TestGenerateFixes_XSS(t *testing.T) {
	p := NewFixPipeline()
	findings := []Finding{
		{
			Concern:  "xss vulnerability",
			Severity: SeverityHigh,
			File:     "handlers/render.go",
			Line:     15,
			Message:  "user input rendered without escaping",
			CWE:      "CWE-79",
		},
	}

	fixes := p.GenerateFixes(findings)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}

	fix := fixes[0]
	if fix.Category != "xss" {
		t.Errorf("expected category 'xss', got %q", fix.Category)
	}
	if fix.Priority != 1 {
		t.Errorf("expected priority 1, got %d", fix.Priority)
	}
	if !strings.Contains(fix.Title, "Escape") && !strings.Contains(fix.Title, "sanitize") {
		t.Errorf("expected title to mention escaping/sanitizing, got %q", fix.Title)
	}
	if !strings.Contains(fix.FixCode, "html.EscapeString") {
		t.Errorf("expected fix code to mention html.EscapeString, got %q", fix.FixCode)
	}
}

// =====================================================================
// 4. Hardcoded secret finding generates env var fix
// =====================================================================

func TestGenerateFixes_HardcodedSecret(t *testing.T) {
	p := NewFixPipeline()
	findings := []Finding{
		{
			Concern:  "hardcoded credential in source",
			Severity: SeverityCritical,
			File:     "config/secrets.go",
			Line:     8,
			Message:  "API key hardcoded in source code",
			CWE:      "CWE-798",
		},
	}

	fixes := p.GenerateFixes(findings)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}

	fix := fixes[0]
	if fix.Category != "auth" {
		t.Errorf("expected category 'auth', got %q", fix.Category)
	}
	if fix.Priority != 2 {
		t.Errorf("expected priority 2, got %d", fix.Priority)
	}
	if fix.EstimatedEffort != "trivial" {
		t.Errorf("expected effort 'trivial', got %q", fix.EstimatedEffort)
	}
	if !strings.Contains(fix.FixCode, "os.Getenv") {
		t.Errorf("expected fix code to mention os.Getenv, got %q", fix.FixCode)
	}
}

// =====================================================================
// 5. Missing validation finding generates middleware fix
// =====================================================================

func TestGenerateFixes_MissingValidation(t *testing.T) {
	p := NewFixPipeline()
	findings := []Finding{
		{
			Concern:  "missing input validation on request body",
			Severity: SeverityMedium,
			File:     "handlers/users.go",
			Line:     25,
			Message:  "unsanitized user input passed to business logic",
			CWE:      "CWE-20",
		},
	}

	fixes := p.GenerateFixes(findings)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}

	fix := fixes[0]
	if fix.Category != "input-validation" {
		t.Errorf("expected category 'input-validation', got %q", fix.Category)
	}
	if fix.Priority != 3 {
		t.Errorf("expected priority 3, got %d", fix.Priority)
	}
	if fix.EstimatedEffort != "moderate" {
		t.Errorf("expected effort 'moderate', got %q", fix.EstimatedEffort)
	}
	if !strings.Contains(fix.FixCode, "validator") {
		t.Errorf("expected fix code to mention validator, got %q", fix.FixCode)
	}
}

// =====================================================================
// 6. Weak crypto finding generates algorithm replacement fix
// =====================================================================

func TestGenerateFixes_WeakCrypto(t *testing.T) {
	p := NewFixPipeline()
	findings := []Finding{
		{
			Concern:  "weak hash algorithm used for checksum",
			Severity: SeverityHigh,
			File:     "auth/hash.go",
			Line:     12,
			Message:  "md5 used for hashing sensitive data",
			CWE:      "CWE-327",
		},
	}

	fixes := p.GenerateFixes(findings)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}

	fix := fixes[0]
	if fix.Category != "crypto" {
		t.Errorf("expected category 'crypto', got %q", fix.Category)
	}
	if fix.Priority != 2 {
		t.Errorf("expected priority 2, got %d", fix.Priority)
	}
	if !strings.Contains(fix.FixCode, "sha256") {
		t.Errorf("expected fix code to mention sha256, got %q", fix.FixCode)
	}
	if !strings.Contains(fix.Title, "Replace") {
		t.Errorf("expected title to mention replacement, got %q", fix.Title)
	}
}

// =====================================================================
// 7. Path traversal finding generates filepath.Clean fix
// =====================================================================

func TestGenerateFixes_PathTraversal(t *testing.T) {
	p := NewFixPipeline()
	findings := []Finding{
		{
			Concern:  "path traversal via user-controlled file path",
			Severity: SeverityHigh,
			File:     "handlers/files.go",
			Line:     30,
			Message:  "directory traversal possible through unsanitized input",
			CWE:      "CWE-22",
		},
	}

	fixes := p.GenerateFixes(findings)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}

	fix := fixes[0]
	if fix.Category != "input-validation" {
		t.Errorf("expected category 'input-validation', got %q", fix.Category)
	}
	if fix.Priority != 2 {
		t.Errorf("expected priority 2, got %d", fix.Priority)
	}
	if !strings.Contains(fix.FixCode, "filepath.Clean") {
		t.Errorf("expected fix code to mention filepath.Clean, got %q", fix.FixCode)
	}
}

// =====================================================================
// 8. SSRF finding generates allowlist fix
// =====================================================================

func TestGenerateFixes_SSRF(t *testing.T) {
	p := NewFixPipeline()
	findings := []Finding{
		{
			Concern:  "ssrf via user-supplied URL",
			Severity: SeverityHigh,
			File:     "client/fetch.go",
			Line:     18,
			Message:  "server-side request forgery possible through unvalidated URL",
			CWE:      "CWE-918",
		},
	}

	fixes := p.GenerateFixes(findings)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}

	fix := fixes[0]
	if fix.Category != "ssrf" {
		t.Errorf("expected category 'ssrf', got %q", fix.Category)
	}
	if fix.Priority != 2 {
		t.Errorf("expected priority 2, got %d", fix.Priority)
	}
	if !strings.Contains(fix.FixCode, "allowedHosts") && !strings.Contains(fix.FixCode, "allowlist") {
		t.Errorf("expected fix code to mention allowlist/allowedHosts, got %q", fix.FixCode)
	}
}

// =====================================================================
// 9. Custom rule registration and matching
// =====================================================================

func TestAddRule_CustomRuleMatches(t *testing.T) {
	p := NewFixPipeline()

	customRule := FixRule{
		MatchFn: func(f Finding) bool {
			return strings.Contains(strings.ToLower(f.Concern), "no unit tests")
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:           "Add unit tests for uncovered code",
				Description:     "Missing test coverage",
				FixCode:         "func TestFoo(t *testing.T) { ... }",
				Confidence:      0.75,
				Category:        "testing",
				Severity:        f.Severity.String(),
				EstimatedEffort: "moderate",
				Priority:        4,
			}
		},
	}
	p.AddRule(customRule)

	findings := []Finding{
		{
			Concern:  "no unit tests for handler",
			Severity: SeverityLow,
			File:     "handlers/foo.go",
			Line:     10,
			Message:  "function lacks test coverage",
		},
	}

	fixes := p.GenerateFixes(findings)
	// Only the custom rule should match -- none of the built-in rules match.
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix from custom rule, got %d", len(fixes))
	}
	if fixes[0].Category != "testing" {
		t.Errorf("expected category 'testing', got %q", fixes[0].Category)
	}
	if fixes[0].Priority != 4 {
		t.Errorf("expected priority 4, got %d", fixes[0].Priority)
	}
}

func TestAddRule_ConcurrentSafety(t *testing.T) {
	p := NewFixPipeline()
	done := make(chan struct{})
	go func() {
		p.AddRule(FixRule{
			MatchFn:   func(Finding) bool { return false },
			Generator: func(Finding) FixSuggestion { return FixSuggestion{} },
		})
		close(done)
	}()
	// Read rules concurrently
	_ = p.GenerateFixes(nil)
	<-done
}

// =====================================================================
// 10. Multiple findings sorted by priority then confidence
// =====================================================================

func TestGenerateFixes_SortedByPriorityThenConfidence(t *testing.T) {
	p := NewFixPipeline()

	findings := []Finding{
		// SSRF: priority 2, confidence 0.80
		{
			Concern:  "ssrf vulnerability",
			Severity: SeverityHigh,
			File:     "a.go",
			Line:     1,
			Message:  "server-side request forgery",
			CWE:      "CWE-918",
		},
		// SQL injection: priority 1, confidence 0.85
		{
			Concern:  "sql injection",
			Severity: SeverityHigh,
			File:     "b.go",
			Line:     1,
			Message:  "sql injection via string concat",
			CWE:      "CWE-89",
		},
		// XSS: priority 1, confidence 0.85
		{
			Concern:  "xss",
			Severity: SeverityHigh,
			File:     "c.go",
			Line:     1,
			Message:  "cross-site scripting",
			CWE:      "CWE-79",
		},
		// Input validation: priority 3, confidence 0.80
		{
			Concern:  "missing validation",
			Severity: SeverityMedium,
			File:     "d.go",
			Line:     1,
			Message:  "input validation missing",
			CWE:      "CWE-20",
		},
	}

	fixes := p.GenerateFixes(findings)
	if len(fixes) != 4 {
		t.Fatalf("expected 4 fixes, got %d", len(fixes))
	}

	// Priority 1 items should come first, then 2, then 3.
	for i := 0; i < len(fixes)-1; i++ {
		if fixes[i].Priority > fixes[i+1].Priority {
			t.Errorf("fix[%d].Priority=%d > fix[%d].Priority=%d", i, fixes[i].Priority, i+1, fixes[i+1].Priority)
		}
		if fixes[i].Priority == fixes[i+1].Priority && fixes[i].Confidence < fixes[i+1].Confidence {
			t.Errorf("same priority but fix[%d].Confidence=%f < fix[%d].Confidence=%f",
				i, fixes[i].Confidence, i+1, fixes[i+1].Confidence)
		}
	}
}

// =====================================================================
// 11. Deduplication: same finding matched by multiple rules keeps highest confidence
// =====================================================================

func TestGenerateFixes_DeduplicationKeepsHighestConfidence(t *testing.T) {
	p := NewFixPipeline()

	// Register two custom rules that both match "sql injection" findings but
	// produce different confidence values.
	p.AddRule(FixRule{
		MatchFn: func(f Finding) bool {
			return strings.Contains(strings.ToLower(f.Concern), "sql injection")
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:      "Low-confidence custom fix",
				Confidence: 0.50,
				Category:   "custom-low",
				Priority:   1,
			}
		},
	})
	p.AddRule(FixRule{
		MatchFn: func(f Finding) bool {
			return strings.Contains(strings.ToLower(f.Concern), "sql injection")
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:      "High-confidence custom fix",
				Confidence: 0.95,
				Category:   "custom-high",
				Priority:   1,
			}
		},
	})

	findings := []Finding{
		{
			Concern:  "sql injection in handler",
			Severity: SeverityHigh,
			File:     "handler.go",
			Line:     10,
			Message:  "sql injection",
			CWE:      "CWE-89",
		},
	}

	fixes := p.GenerateFixes(findings)
	// All rules (built-in + 2 custom) match, but they all produce a fix for
	// the same finding ID. Only the highest-confidence one should survive.
	if len(fixes) != 1 {
		t.Fatalf("expected 1 deduplicated fix, got %d", len(fixes))
	}
	if fixes[0].Category != "custom-high" {
		t.Errorf("expected highest-confidence fix to win, got category %q (confidence %f)",
			fixes[0].Category, fixes[0].Confidence)
	}
}

func TestGenerateFixes_DeduplicationSameConfidenceKeepsEarlierRule(t *testing.T) {
	p := NewFixPipeline()

	// Two custom rules with identical confidence -- the first registered should win.
	p.AddRule(FixRule{
		MatchFn: func(f Finding) bool {
			return f.Concern == "custom-concern"
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:      "First rule",
				Confidence: 0.80,
				Category:   "first",
				Priority:   1,
			}
		},
	})
	p.AddRule(FixRule{
		MatchFn: func(f Finding) bool {
			return f.Concern == "custom-concern"
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:      "Second rule",
				Confidence: 0.80,
				Category:   "second",
				Priority:   1,
			}
		},
	})

	findings := []Finding{
		{
			Concern:  "custom-concern",
			Severity: SeverityMedium,
			File:     "test.go",
			Line:     5,
			Message:  "test finding",
		},
	}

	fixes := p.GenerateFixes(findings)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 deduplicated fix, got %d", len(fixes))
	}
	if fixes[0].Category != "first" {
		t.Errorf("expected earlier rule to win on tie, got category %q", fixes[0].Category)
	}
}

// =====================================================================
// 12. No matching rules returns empty slice
// =====================================================================

func TestGenerateFixes_NoMatchingRules(t *testing.T) {
	p := NewFixPipeline()

	findings := []Finding{
		{
			Concern:  "naming convention violation",
			Severity: SeverityInfo,
			File:     "style.go",
			Line:     1,
			Message:  "function name uses camelCase instead of snake_case",
		},
	}

	fixes := p.GenerateFixes(findings)
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes for non-matching finding, got %d", len(fixes))
	}
}

func TestGenerateFixes_EmptyFindings(t *testing.T) {
	p := NewFixPipeline()
	fixes := p.GenerateFixes(nil)
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes for nil findings, got %d", len(fixes))
	}

	fixes = p.GenerateFixes([]Finding{})
	if len(fixes) != 0 {
		t.Errorf("expected 0 fixes for empty findings, got %d", len(fixes))
	}
}

// =====================================================================
// 13. String() output format
// =====================================================================

func TestFixSuggestion_String(t *testing.T) {
	fix := FixSuggestion{
		Title:           "Use parameterized queries",
		FindingID:       "db/query.go:42:sql injection",
		Severity:        "high",
		EstimatedEffort: "easy",
		Priority:        1,
		Confidence:      0.85,
		Description:     "Replace string concatenation with parameterized queries.",
		FixCode:         "query := \"SELECT * FROM t WHERE id = $1\"\nrows, err := db.Query(query, id)",
		Category:        "injection",
	}

	out := fix.String()

	// Verify required sections are present.
	checks := []struct {
		label string
		want  string
	}{
		{"category+title", "[injection] Use parameterized queries"},
		{"finding", "Finding:   db/query.go:42:sql injection"},
		{"severity", "Severity:  high"},
		{"effort", "Effort:    easy"},
		{"priority", "Priority:  1"},
		{"confidence", "Confidence: 85%"},
		{"description", "Description: Replace string concatenation with parameterized queries."},
	}
	for _, c := range checks {
		if !strings.Contains(out, c.want) {
			t.Errorf("String() missing %q\n\nGot:\n%s", c.label, out)
		}
	}

	// FixCode section should be present.
	if !strings.Contains(out, "  Suggested Fix:") {
		t.Error("String() missing 'Suggested Fix:' section")
	}
}

func TestFixSuggestion_String_NoFixCode(t *testing.T) {
	fix := FixSuggestion{
		Title:       "Informational note",
		FindingID:   "note.go:1:info",
		Severity:    "info",
		Description: "Just a note.",
		Category:    "info",
	}

	out := fix.String()
	if strings.Contains(out, "Suggested Fix:") {
		t.Error("String() should not contain 'Suggested Fix:' when FixCode is empty")
	}
	if !strings.Contains(out, "[info] Informational note") {
		t.Errorf("String() missing expected header, got:\n%s", out)
	}
}
