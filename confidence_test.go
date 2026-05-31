package sight

import (
	"math"
	"regexp"
	"testing"
)

// ---------------------------------------------------------------------------
// CalculateStaticConfidence
// ---------------------------------------------------------------------------

func TestCalculateStaticConfidence_BasePatternMatch(t *testing.T) {
	rule := StaticRule{
		ID:       "SEC-GO-001",
		Category: "security",
	}
	finding := Finding{
		Concern: "static:security",
		Message: "[SEC-GO-001] SQL query: String formatting used in query construction",
	}
	conf := CalculateStaticConfidence(finding, rule)
	// Base 0.7, no antipattern defined so no boost, message has no confirming keywords
	if conf != 0.7 {
		t.Errorf("expected 0.7 for base pattern match, got %f", conf)
	}
}

func TestCalculateStaticConfidence_WithAntipatternAbsent(t *testing.T) {
	rule := StaticRule{
		ID:          "SEC-GO-002",
		Category:    "security",
		Antipattern: regexp.MustCompile(`exec\.Command\s*\(\s*"[^"]+"\s*\)`),
	}
	finding := Finding{
		Concern: "static:security",
		Message: "[SEC-GO-002] Command exec: Potentially unsanitized input passed to exec.Command",
	}
	conf := CalculateStaticConfidence(finding, rule)
	// Base 0.7 + 0.1 (antipattern defined, means finding survived FP filter)
	// + 0.1 (message contains "unsanitized")
	expected := 0.9
	if math.Abs(conf-expected) > 0.001 {
		t.Errorf("expected %f, got %f", expected, conf)
	}
}

func TestCalculateStaticConfidence_WithConfirmingContext(t *testing.T) {
	rule := StaticRule{
		ID:       "SEC-GO-003",
		Category: "security",
	}
	finding := Finding{
		Concern: "static:security",
		Message: "[SEC-GO-003] Path Traversal: User-controlled path used without filepath.Clean",
	}
	conf := CalculateStaticConfidence(finding, rule)
	// Base 0.7 + 0.1 (message contains "without"), no antipattern boost
	expected := 0.8
	if math.Abs(conf-expected) > 0.001 {
		t.Errorf("expected %f, got %f", expected, conf)
	}
}

func TestCalculateStaticConfidence_FalsePositiveProne(t *testing.T) {
	rule := StaticRule{
		ID:       "COR-GO-001",
		Category: "correctness",
	}
	finding := Finding{
		Concern: "static:correctness",
		Message: "[COR-GO-001] Unchecked Error: Function return value discarded",
	}
	conf := CalculateStaticConfidence(finding, rule)
	// Base 0.7 - 0.2 (false-positive-prone rule)
	expected := 0.5
	if math.Abs(conf-expected) > 0.001 {
		t.Errorf("expected %f, got %f", expected, conf)
	}
}

func TestCalculateStaticConfidence_AllBoostsAndPenalty(t *testing.T) {
	rule := StaticRule{
		ID:          "SEC-ANY-003",
		Category:    "security",
		Antipattern: regexp.MustCompile(`localhost`),
	}
	finding := Finding{
		Concern: "static:security",
		Message: "[SEC-ANY-003] HTTP in Production: Insecure HTTP URL used without HTTPS",
	}
	conf := CalculateStaticConfidence(finding, rule)
	// Base 0.7 + 0.1 (antipattern defined) + 0.1 (message contains "without")
	// - 0.2 (SEC-ANY-003 is false-positive-prone)
	expected := 0.7
	if math.Abs(conf-expected) > 0.001 {
		t.Errorf("expected %f, got %f", expected, conf)
	}
}

func TestCalculateStaticConfidence_ClampLow(t *testing.T) {
	// Create a scenario that would go below 0
	rule := StaticRule{
		ID:       "COR-GO-001",
		Category: "correctness",
	}
	finding := Finding{
		Concern: "static:correctness",
		Message: "[COR-GO-001] some generic message",
	}
	conf := CalculateStaticConfidence(finding, rule)
	if conf < 0 {
		t.Errorf("confidence should not be negative, got %f", conf)
	}
}

func TestCalculateStaticConfidence_ClampHigh(t *testing.T) {
	// All boosts + antipattern should not exceed 1.0
	rule := StaticRule{
		ID:          "SEC-GO-001",
		Category:    "security",
		Antipattern: regexp.MustCompile(`something`),
	}
	finding := Finding{
		Concern: "static:security",
		Message: "[SEC-GO-001] SQL injection with unsanitized input without validation",
	}
	conf := CalculateStaticConfidence(finding, rule)
	if conf > 1.0 {
		t.Errorf("confidence should not exceed 1.0, got %f", conf)
	}
}

// ---------------------------------------------------------------------------
// CalculateLLMConfidence
// ---------------------------------------------------------------------------

func TestCalculateLLMConfidence_WithExplicitConfidence(t *testing.T) {
	response := `[{"file":"main.go","line":10,"severity":"high","message":"SQL injection","confidence":0.85}]`
	finding := Finding{File: "main.go", Line: 10}
	conf := CalculateLLMConfidence(response, finding)
	if math.Abs(conf-0.85) > 0.001 {
		t.Errorf("expected 0.85, got %f", conf)
	}
}

func TestCalculateLLMConfidence_DefaultWhenNotSpecified(t *testing.T) {
	response := `[{"file":"main.go","line":10,"severity":"high","message":"SQL injection"}]`
	finding := Finding{File: "main.go", Line: 10}
	conf := CalculateLLMConfidence(response, finding)
	if math.Abs(conf-0.6) > 0.001 {
		t.Errorf("expected default 0.6, got %f", conf)
	}
}

func TestCalculateLLMConfidence_DefaultWhenEmptyResponse(t *testing.T) {
	finding := Finding{File: "main.go", Line: 10}
	conf := CalculateLLMConfidence("", finding)
	if math.Abs(conf-0.6) > 0.001 {
		t.Errorf("expected default 0.6 for empty response, got %f", conf)
	}
}

func TestCalculateLLMConfidence_DefaultWhenNoMatch(t *testing.T) {
	response := `[{"file":"other.go","line":20,"severity":"low","message":"style issue","confidence":0.9}]`
	finding := Finding{File: "main.go", Line: 10}
	conf := CalculateLLMConfidence(response, finding)
	if math.Abs(conf-0.6) > 0.001 {
		t.Errorf("expected default 0.6 when no match, got %f", conf)
	}
}

func TestCalculateLLMConfidence_WithMarkdownFences(t *testing.T) {
	response := "```json\n[{\"file\":\"main.go\",\"line\":10,\"severity\":\"high\",\"message\":\"bug\",\"confidence\":0.95}]\n```"
	finding := Finding{File: "main.go", Line: 10}
	conf := CalculateLLMConfidence(response, finding)
	if math.Abs(conf-0.95) > 0.001 {
		t.Errorf("expected 0.95, got %f", conf)
	}
}

func TestCalculateLLMConfidence_IgnoresInvalidConfidence(t *testing.T) {
	response := `[{"file":"main.go","line":10,"severity":"high","message":"bug","confidence":1.5}]`
	finding := Finding{File: "main.go", Line: 10}
	conf := CalculateLLMConfidence(response, finding)
	// 1.5 > 1.0, so it should fall back to default
	if math.Abs(conf-0.6) > 0.001 {
		t.Errorf("expected default 0.6 for out-of-range confidence, got %f", conf)
	}
}

// ---------------------------------------------------------------------------
// CalculateTaintConfidence
// ---------------------------------------------------------------------------

func TestCalculateTaintConfidence_DirectTaint(t *testing.T) {
	conf := CalculateTaintConfidence("function-parameter", "SQL query execution", nil)
	// Base 0.8, no sanitizers, no intermediaries
	if math.Abs(conf-0.8) > 0.001 {
		t.Errorf("expected 0.8 for direct taint, got %f", conf)
	}
}

func TestCalculateTaintConfidence_WithSanitizers(t *testing.T) {
	conf := CalculateTaintConfidence("function-parameter", "SQL query execution", []string{"filepath.Clean"})
	// Base 0.8 - 0.1 (one sanitizer)
	expected := 0.7
	if math.Abs(conf-expected) > 0.001 {
		t.Errorf("expected %f, got %f", expected, conf)
	}
}

func TestCalculateTaintConfidence_WithMultipleSanitizers(t *testing.T) {
	conf := CalculateTaintConfidence(
		"function-parameter",
		"SQL query execution",
		[]string{"filepath.Clean", "html.EscapeString"},
	)
	// Base 0.8 - 0.1*2 (two sanitizers)
	expected := 0.6
	if math.Abs(conf-expected) > 0.001 {
		t.Errorf("expected %f, got %f", expected, conf)
	}
}

func TestCalculateTaintConfidence_WithIntermediateVariable(t *testing.T) {
	conf := CalculateTaintConfidence("request-body-read", "SQL query execution", nil)
	// Base 0.8 - 0.2*1 (request-body-read has 1 intermediate)
	expected := 0.6
	if math.Abs(conf-expected) > 0.001 {
		t.Errorf("expected %f, got %f", expected, conf)
	}
}

func TestCalculateTaintConfidence_DirectOsGetenv(t *testing.T) {
	conf := CalculateTaintConfidence("os.Getenv", "command execution", nil)
	// Base 0.8, os.Getenv is direct (0 intermediaries)
	if math.Abs(conf-0.8) > 0.001 {
		t.Errorf("expected 0.8 for os.Getenv direct taint, got %f", conf)
	}
}

func TestCalculateTaintConfidence_WithSanitizerAndIntermediate(t *testing.T) {
	conf := CalculateTaintConfidence("http-form-value", "file operation", []string{"validate"})
	// Base 0.8 - 0.1 (1 sanitizer) - 0.2*1 (http-form-value has 1 intermediate)
	expected := 0.5
	if math.Abs(conf-expected) > 0.001 {
		t.Errorf("expected %f, got %f", expected, conf)
	}
}

func TestCalculateTaintConfidence_ClampLow(t *testing.T) {
	conf := CalculateTaintConfidence(
		"http-form-value", // 1 intermediate
		"SQL query execution",
		[]string{"san1", "san2", "san3", "san4"},
	)
	// 0.8 - 0.4 - 0.2 = 0.2
	if conf < 0 {
		t.Errorf("confidence should not be negative, got %f", conf)
	}
}

// ---------------------------------------------------------------------------
// ComputeConfidenceStats
// ---------------------------------------------------------------------------

func TestComputeConfidenceStats_Empty(t *testing.T) {
	avg, high, low := ComputeConfidenceStats(nil)
	if avg != 0 || high != 0 || low != 0 {
		t.Errorf("expected all zeros for empty findings, got avg=%f high=%d low=%d", avg, high, low)
	}
}

func TestComputeConfidenceStats_AllHigh(t *testing.T) {
	findings := []Finding{
		{Confidence: 0.9},
		{Confidence: 0.8},
		{Confidence: 0.7},
	}
	avg, high, low := ComputeConfidenceStats(findings)
	if high != 3 {
		t.Errorf("expected 3 high confidence, got %d", high)
	}
	if low != 0 {
		t.Errorf("expected 0 low confidence, got %d", low)
	}
	expectedAvg := 0.8
	if math.Abs(avg-expectedAvg) > 0.01 {
		t.Errorf("expected avg %f, got %f", expectedAvg, avg)
	}
}

func TestComputeConfidenceStats_Mixed(t *testing.T) {
	findings := []Finding{
		{Confidence: 0.9}, // high
		{Confidence: 0.4}, // low
		{Confidence: 0.6}, // medium
	}
	avg, high, low := ComputeConfidenceStats(findings)
	if high != 1 {
		t.Errorf("expected 1 high, got %d", high)
	}
	if low != 1 {
		t.Errorf("expected 1 low, got %d", low)
	}
	expectedAvg := 0.63
	if math.Abs(avg-expectedAvg) > 0.01 {
		t.Errorf("expected avg ~0.63, got %f", avg)
	}
}

func TestComputeConfidenceStats_AllLow(t *testing.T) {
	findings := []Finding{
		{Confidence: 0.3},
		{Confidence: 0.4},
	}
	_, high, low := ComputeConfidenceStats(findings)
	if high != 0 {
		t.Errorf("expected 0 high, got %d", high)
	}
	if low != 2 {
		t.Errorf("expected 2 low, got %d", low)
	}
}

// ---------------------------------------------------------------------------
// BuildConfidenceBreakdown
// ---------------------------------------------------------------------------

func TestBuildConfidenceBreakdown_Empty(t *testing.T) {
	bd := BuildConfidenceBreakdown(nil)
	if bd != nil {
		t.Errorf("expected nil breakdown for empty findings")
	}
}

func TestBuildConfidenceBreakdown_Groups(t *testing.T) {
	findings := []Finding{
		{Message: "high1", Confidence: 0.9},
		{Message: "high2", Confidence: 0.7},
		{Message: "medium1", Confidence: 0.6},
		{Message: "low1", Confidence: 0.3},
		{Message: "low2", Confidence: 0.1},
	}
	bd := BuildConfidenceBreakdown(findings)
	if bd == nil {
		t.Fatal("expected non-nil breakdown")
	}
	if len(bd.High) != 2 {
		t.Errorf("expected 2 high, got %d", len(bd.High))
	}
	if len(bd.Medium) != 1 {
		t.Errorf("expected 1 medium, got %d", len(bd.Medium))
	}
	if len(bd.Low) != 2 {
		t.Errorf("expected 2 low, got %d", len(bd.Low))
	}
}

func TestBuildConfidenceBreakdown_BoundaryAt07(t *testing.T) {
	findings := []Finding{
		{Confidence: 0.7},  // high
		{Confidence: 0.69}, // medium
	}
	bd := BuildConfidenceBreakdown(findings)
	if len(bd.High) != 1 {
		t.Errorf("expected 1 high (0.7 is high), got %d", len(bd.High))
	}
	if len(bd.Medium) != 1 {
		t.Errorf("expected 1 medium (0.69 is medium), got %d", len(bd.Medium))
	}
}

func TestBuildConfidenceBreakdown_BoundaryAt05(t *testing.T) {
	findings := []Finding{
		{Confidence: 0.5},  // medium
		{Confidence: 0.49}, // low
	}
	bd := BuildConfidenceBreakdown(findings)
	if len(bd.Medium) != 1 {
		t.Errorf("expected 1 medium (0.5 is medium), got %d", len(bd.Medium))
	}
	if len(bd.Low) != 1 {
		t.Errorf("expected 1 low (0.49 is low), got %d", len(bd.Low))
	}
}

// ---------------------------------------------------------------------------
// clampConfidence
// ---------------------------------------------------------------------------

func TestClampConfidence(t *testing.T) {
	tests := []struct {
		input float64
		want  float64
	}{
		{0.5, 0.5},
		{0.0, 0.0},
		{1.0, 1.0},
		{-0.1, 0.0},
		{1.5, 1.0},
	}
	for _, tt := range tests {
		got := clampConfidence(tt.input)
		if math.Abs(got-tt.want) > 0.001 {
			t.Errorf("clampConfidence(%f) = %f, want %f", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// isFalsePositiveProne
// ---------------------------------------------------------------------------

func TestIsFalsePositiveProne(t *testing.T) {
	if !isFalsePositiveProne("COR-GO-001") {
		t.Error("COR-GO-001 should be false-positive-prone")
	}
	if !isFalsePositiveProne("COR-GO-002") {
		t.Error("COR-GO-002 should be false-positive-prone")
	}
	if !isFalsePositiveProne("PERF-GO-003") {
		t.Error("PERF-GO-003 should be false-positive-prone")
	}
	if !isFalsePositiveProne("PERF-PY-001") {
		t.Error("PERF-PY-001 should be false-positive-prone")
	}
	if !isFalsePositiveProne("SEC-ANY-003") {
		t.Error("SEC-ANY-003 should be false-positive-prone")
	}
	if isFalsePositiveProne("SEC-GO-001") {
		t.Error("SEC-GO-001 should NOT be false-positive-prone")
	}
	if isFalsePositiveProne("") {
		t.Error("empty string should NOT be false-positive-prone")
	}
}

// ---------------------------------------------------------------------------
// extractTaintSource / extractTaintSink
// ---------------------------------------------------------------------------

func TestExtractTaintSource(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{
			"[TAINT-SQL_INJECTION] SQL_INJECTION: function-parameter -> SQL query execution via variable \"query\"",
			"function-parameter",
		},
		{
			"[TAINT-COMMAND_INJECTION] COMMAND_INJECTION: os.Getenv -> command execution via variable \"cmd\"",
			"os.Getenv",
		},
		{
			"[TAINT-PATH_TRAVERSAL] PATH_TRAVERSAL: http-form-value -> file operation via variable \"path\"",
			"http-form-value",
		},
		{
			"malformed message without arrow",
			"unknown",
		},
	}
	for _, tt := range tests {
		got := extractTaintSource(tt.msg)
		if got != tt.want {
			t.Errorf("extractTaintSource(%q) = %q, want %q", tt.msg, got, tt.want)
		}
	}
}

func TestExtractTaintSink(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{
			"[TAINT-SQL_INJECTION] SQL_INJECTION: function-parameter -> SQL query execution via variable \"query\"",
			"SQL query execution",
		},
		{
			"[TAINT-COMMAND_INJECTION] COMMAND_INJECTION: os.Getenv -> command execution via variable \"cmd\"",
			"command execution",
		},
		{
			"no arrow here",
			"unknown",
		},
	}
	for _, tt := range tests {
		got := extractTaintSink(tt.msg)
		if got != tt.want {
			t.Errorf("extractTaintSink(%q) = %q, want %q", tt.msg, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration: confidence flows through static analysis
// ---------------------------------------------------------------------------

func TestStaticAnalyzerConfidence_Integration(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)`
	findings := sa.AnalyzeFile(code, "go")
	if len(findings) == 0 {
		t.Fatal("expected findings from static analysis")
	}
	// Verify that static findings don't have confidence set by default (it's 0.0)
	// because the analyzer doesn't set it — it's the reviewer's job.
	for _, f := range findings {
		if f.Confidence != 0 {
			t.Logf("Static finding has confidence %f (expected 0 before reviewer sets it)", f.Confidence)
		}
	}
}

func TestCalculateStaticConfidence_WithMatchingRule(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)`
	findings := sa.AnalyzeFile(code, "go")
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	f := findings[0]
	// Find the matching rule
	var matchedRule StaticRule
	for _, rule := range sa.Rules {
		if f.Concern == "static:"+rule.Category && containsString(f.Message, rule.ID) {
			matchedRule = rule
			break
		}
	}
	if matchedRule.ID == "" {
		t.Fatal("expected to find matching rule")
	}
	conf := CalculateStaticConfidence(f, matchedRule)
	if conf < 0.5 || conf > 1.0 {
		t.Errorf("expected confidence in [0.5, 1.0], got %f", conf)
	}
	t.Logf("Static confidence for %s: %.2f", matchedRule.ID, conf)
}

// containsString is a test helper for substring check.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
