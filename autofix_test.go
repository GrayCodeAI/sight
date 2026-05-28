package sight

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// --- mockProvider for autofix tests ---

type fixMockProvider struct {
	response string
	err      error
}

func (m *fixMockProvider) Chat(_ context.Context, _ []Message, _ ChatOpts) (*Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &Response{Content: m.response, TokensUsed: 42}, nil
}

// --- helpers ---

func testFinding(severity Severity, file string, line int, msg string) Finding {
	return Finding{
		Concern:  "security",
		Severity: severity,
		File:     file,
		Line:     line,
		Message:  msg,
	}
}

const sampleDiff = `diff --git a/handler.go b/handler.go
index abc1234..def5678 100644
--- a/handler.go
+++ b/handler.go
@@ -10,6 +10,10 @@ func handleRequest(w http.ResponseWriter, r *http.Request) {
 	userID := r.URL.Query().Get("id")

-	user, err := db.GetUser(userID)
+	query := "SELECT * FROM users WHERE id = '" + userID + "'"
+	user, err := db.RawQuery(query)
+	if err != nil {
+		log.Printf("Error: %v, query: %s", err, query)
+	}

 	json.NewEncoder(w).Encode(user)
 }
`

// =====================================================================
// 1. Auto-fix generation
// =====================================================================

func TestSuggestFixes_ValidResponse(t *testing.T) {
	provider := &fixMockProvider{
		response: "FIXED:\nquery := \"SELECT * FROM users WHERE id = $1\"\nuser, err := db.Query(query, userID)\nEXPLANATION: Use parameterized queries to prevent SQL injection.",
	}
	af := NewAutoFix(provider)

	findings := []Finding{
		testFinding(SeverityHigh, "handler.go", 13, "SQL injection via string concatenation"),
	}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}

	s := suggestions[0]
	if s.Finding.File != findings[0].File || s.Finding.Line != findings[0].Line {
		t.Errorf("suggestion finding mismatch: got file=%s line=%d, want file=%s line=%d",
			s.Finding.File, s.Finding.Line, findings[0].File, findings[0].Line)
	}
	if !strings.Contains(s.FixedCode, "db.Query") {
		t.Errorf("expected fixed code to contain 'db.Query', got %q", s.FixedCode)
	}
	if s.Explanation == "" {
		t.Error("expected non-empty explanation")
	}
	if s.Confidence != 0.7 {
		t.Errorf("expected confidence 0.7, got %f", s.Confidence)
	}
}

func TestSuggestFixes_MultipleFindings(t *testing.T) {
	provider := &fixMockProvider{
		response: "FIXED:\nfixed code here\nEXPLANATION: Fixed the issue.",
	}
	af := NewAutoFix(provider)

	findings := []Finding{
		testFinding(SeverityHigh, "handler.go", 13, "SQL injection"),
		testFinding(SeverityMedium, "handler.go", 16, "Info leak in logs"),
	}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 2 {
		t.Fatalf("expected 2 suggestions, got %d", len(suggestions))
	}
}

func TestSuggestFixes_SkipsSeverityInfo(t *testing.T) {
	provider := &fixMockProvider{
		response: "FIXED:\nfixed code\nEXPLANATION: Because.",
	}
	af := NewAutoFix(provider)

	findings := []Finding{
		testFinding(SeverityInfo, "handler.go", 10, "FYI: consider renaming"),
		testFinding(SeverityHigh, "handler.go", 13, "SQL injection"),
	}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion (info skipped), got %d", len(suggestions))
	}
}

// =====================================================================
// 2. Diff application / extraction
// =====================================================================

func TestExtractRelevantDiff_FindsCorrectFile(t *testing.T) {
	result := extractRelevantDiff(sampleDiff, "handler.go", 13)
	if result == "" {
		t.Fatal("expected non-empty relevant diff")
	}
	// With line 13 and +-5 window, lines 8-18 are included. The error handling
	// and JSON encoding lines fall in that range.
	if !strings.Contains(result, "Encode") {
		t.Errorf("expected relevant diff to include nearby content, got %q", result)
	}
}

func TestExtractRelevantDiff_DifferentFile(t *testing.T) {
	result := extractRelevantDiff(sampleDiff, "other.go", 5)
	if result != "" {
		t.Errorf("expected empty diff for non-matching file, got %q", result)
	}
}

func TestExtractRelevantDiff_LineWindowExtraction(t *testing.T) {
	// Create a diff with many lines to test the +-5 line window.
	// Note: extractRelevantDiff counts lines after the +++ header, including
	// the @@ hunk header line itself. So content after @@ starts at count 2.
	var b strings.Builder
	b.WriteString("diff --git a/big.go b/big.go\n--- a/big.go\n+++ b/big.go\n")
	b.WriteString("@@ -1,20 +1,20 @@\n")
	for i := 1; i <= 20; i++ {
		b.WriteString(fmt.Sprintf(" line %d context\n", i))
	}
	b.WriteString("+added line\n")

	result := extractRelevantDiff(b.String(), "big.go", 10)
	if result == "" {
		t.Fatal("expected non-empty relevant diff for line 10")
	}
	// With the @@ header counted as the first line, "line N context" is at count N+1.
	// For target line 10 with +-5, window is [5, 15], capturing lines at counts 5-15,
	// which correspond to "line 4" through "line 14".
	if !strings.Contains(result, "line 4 context") {
		t.Errorf("expected result to contain 'line 4 context', got %q", result)
	}
	if !strings.Contains(result, "line 14 context") {
		t.Errorf("expected result to contain 'line 14 context', got %q", result)
	}
	// Lines outside the window should be excluded
	if strings.Contains(result, "line 1 context") {
		t.Errorf("should not contain lines outside window, got %q", result)
	}
}

func TestExtractRelevantDiff_Truncation(t *testing.T) {
	// Build a very long diff to test the 500-char truncation
	var b strings.Builder
	b.WriteString("diff --git a/big.go b/big.go\n--- a/big.go\n+++ b/big.go\n")
	b.WriteString("@@ -1,50 +1,50 @@\n")
	for i := 1; i <= 50; i++ {
		b.WriteString(fmt.Sprintf(" this is a long context line number %d with extra padding text to make it longer\n", i))
	}

	result := extractRelevantDiff(b.String(), "big.go", 25)
	if len(result) > 500 {
		t.Errorf("expected truncated result <= 500 chars, got %d chars", len(result))
	}
}

// =====================================================================
// 3. Edge cases
// =====================================================================

func TestSuggestFixes_EmptyDiff(t *testing.T) {
	provider := &fixMockProvider{
		response: "FIXED:\nfixed\nEXPLANATION: Done.",
	}
	af := NewAutoFix(provider)
	findings := []Finding{testFinding(SeverityHigh, "handler.go", 13, "bug")}

	suggestions, err := af.SuggestFixes(context.Background(), findings, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still produce a suggestion since the diff is just passed to the prompt
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion even with empty diff, got %d", len(suggestions))
	}
}

func TestSuggestFixes_SingleLineFile(t *testing.T) {
	singleLineDiff := "diff --git a/one.go b/one.go\n--- a/one.go\n+++ b/one.go\n@@ -1 +1 @@\n-old\n+new\n"
	provider := &fixMockProvider{
		response: "FIXED:\nnew\nEXPLANATION: Simple fix.",
	}
	af := NewAutoFix(provider)
	findings := []Finding{testFinding(SeverityHigh, "one.go", 1, "issue on single line")}

	suggestions, err := af.SuggestFixes(context.Background(), findings, singleLineDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
	if suggestions[0].FixedCode != "new" {
		t.Errorf("expected fixed code 'new', got %q", suggestions[0].FixedCode)
	}
}

func TestSuggestFixes_SpecialCharactersInDiff(t *testing.T) {
	specialDiff := `diff --git a/special.go b/special.go
--- a/special.go
+++ b/special.go
@@ -1,3 +1,3 @@
 func main() {
-	fmt.Println("hello \"world\" <html>&amp;")
+	fmt.Println("replaced with unicode: éèê")
 }
`
	provider := &fixMockProvider{
		response: "FIXED:\nfmt.Println(\"fixed\")\nEXPLANATION: Removed special chars.",
	}
	af := NewAutoFix(provider)
	findings := []Finding{testFinding(SeverityMedium, "special.go", 2, "special characters issue")}

	suggestions, err := af.SuggestFixes(context.Background(), findings, specialDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
}

func TestSuggestFixes_SpecialCharactersInFindingMessage(t *testing.T) {
	provider := &fixMockProvider{
		response: "FIXED:\nfixed code\nEXPLANATION: Because \"quotes\" and <html>.",
	}
	af := NewAutoFix(provider)
	findings := []Finding{{
		Concern:  "security",
		Severity: SeverityCritical,
		File:     "handler.go",
		Line:     13,
		Message:  `XSS via unescaped user input: <script>alert("xss")</script>`,
	}}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
}

func TestExtractRelevantDiff_EmptyDiff(t *testing.T) {
	result := extractRelevantDiff("", "handler.go", 13)
	if result != "" {
		t.Errorf("expected empty result for empty diff, got %q", result)
	}
}

// =====================================================================
// 4. Multiple fixes on the same file
// =====================================================================

func TestSuggestFixes_MultipleFixesSameFile(t *testing.T) {
	callCount := 0
	provider := &fixMockProvider{
		response: "FIXED:\nfixed code\nEXPLANATION: Fix applied.",
	}
	af := NewAutoFix(provider)

	findings := []Finding{
		testFinding(SeverityHigh, "handler.go", 13, "SQL injection"),
		testFinding(SeverityHigh, "handler.go", 15, "Info leak"),
		testFinding(SeverityMedium, "handler.go", 20, "Missing error check"),
	}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	_ = callCount
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 3 {
		t.Fatalf("expected 3 suggestions for same file, got %d", len(suggestions))
	}

	// Each suggestion should carry the values from its corresponding finding
	for i, s := range suggestions {
		if s.Finding.File != findings[i].File || s.Finding.Line != findings[i].Line {
			t.Errorf("suggestion %d: finding mismatch, got file=%s line=%d want file=%s line=%d",
				i, s.Finding.File, s.Finding.Line, findings[i].File, findings[i].Line)
		}
	}
}

func TestSuggestFixes_MultipleFixesDifferentFiles(t *testing.T) {
	multiFileDiff := `diff --git a/auth.go b/auth.go
--- a/auth.go
+++ b/auth.go
@@ -5,3 +5,3 @@
 func login(user, pass string) {
-	check(user + pass)
+	check(user, pass)
 }
diff --git a/db.go b/db.go
--- a/db.go
+++ b/db.go
@@ -10,3 +10,3 @@
 func query(sql string) {
-	run(sql)
+	run(sql)
 }
`
	provider := &fixMockProvider{
		response: "FIXED:\nfixed\nEXPLANATION: Done.",
	}
	af := NewAutoFix(provider)

	findings := []Finding{
		testFinding(SeverityHigh, "auth.go", 6, "Auth issue"),
		testFinding(SeverityHigh, "db.go", 11, "DB issue"),
	}

	suggestions, err := af.SuggestFixes(context.Background(), findings, multiFileDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 2 {
		t.Fatalf("expected 2 suggestions, got %d", len(suggestions))
	}
}

// =====================================================================
// 5. Conflict detection — overlapping findings at same line
// =====================================================================

func TestSuggestFixes_OverlappingFindingsSameLine(t *testing.T) {
	provider := &fixMockProvider{
		response: "FIXED:\nfixed code\nEXPLANATION: Resolved.",
	}
	af := NewAutoFix(provider)

	// Two findings pointing at exactly the same file and line
	findings := []Finding{
		testFinding(SeverityHigh, "handler.go", 13, "SQL injection"),
		testFinding(SeverityCritical, "handler.go", 13, "Buffer overflow at same line"),
	}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both suggestions should be produced — conflict resolution is left to the consumer
	if len(suggestions) != 2 {
		t.Fatalf("expected 2 suggestions for overlapping findings, got %d", len(suggestions))
	}
	// Verify they reference different findings
	if suggestions[0].Finding.Message == suggestions[1].Finding.Message {
		t.Error("overlapping suggestions should reference distinct findings")
	}
}

func TestSuggestFixes_AdjacentLineFindings(t *testing.T) {
	provider := &fixMockProvider{
		response: "FIXED:\nfixed\nEXPLANATION: Fixed.",
	}
	af := NewAutoFix(provider)

	findings := []Finding{
		testFinding(SeverityHigh, "handler.go", 13, "Line 13 issue"),
		testFinding(SeverityHigh, "handler.go", 14, "Line 14 issue"),
	}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 2 {
		t.Fatalf("expected 2 suggestions for adjacent lines, got %d", len(suggestions))
	}
}

// =====================================================================
// 6. Invalid input / parseFixResponse edge cases
// =====================================================================

func TestParseFixResponse_NoFIXEDMarker(t *testing.T) {
	f := &Finding{File: "test.go", Line: 1, Message: "test"}
	result := parseFixResponse("This is just a normal response without the marker.", f)
	if result != nil {
		t.Error("expected nil when FIXED: marker is missing")
	}
}

func TestParseFixResponse_EmptyFixedCode(t *testing.T) {
	f := &Finding{File: "test.go", Line: 1, Message: "test"}
	result := parseFixResponse("FIXED:\n\nEXPLANATION: explanation here", f)
	if result != nil {
		t.Error("expected nil when fixed code is empty")
	}
}

func TestParseFixResponse_OnlyFIXEDNoEXPLANATION(t *testing.T) {
	f := &Finding{File: "test.go", Line: 1, Message: "test"}
	result := parseFixResponse("FIXED:\nfmt.Println(\"hello\")", f)
	if result == nil {
		t.Fatal("expected non-nil when FIXED is present without EXPLANATION")
	}
	if result.FixedCode != "fmt.Println(\"hello\")" {
		t.Errorf("unexpected fixed code: %q", result.FixedCode)
	}
	if result.Explanation != "" {
		t.Errorf("expected empty explanation, got %q", result.Explanation)
	}
}

func TestParseFixResponse_BothFIXEDAndEXPLANATION(t *testing.T) {
	f := &Finding{File: "test.go", Line: 1, Message: "test"}
	resp := "FIXED:\nx := 42\nEXPLANATION: The answer to everything."
	result := parseFixResponse(resp, f)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.FixedCode != "x := 42" {
		t.Errorf("expected 'x := 42', got %q", result.FixedCode)
	}
	if result.Explanation != "The answer to everything." {
		t.Errorf("expected 'The answer to everything.', got %q", result.Explanation)
	}
}

func TestParseFixResponse_EXPLANATIONBeforeFIXED(t *testing.T) {
	// Edge case: EXPLANATION appears before FIXED in the text
	f := &Finding{File: "test.go", Line: 1, Message: "test"}
	resp := "EXPLANATION: some note\nFIXED:\nreal fix code"
	result := parseFixResponse(resp, f)
	if result == nil {
		t.Fatal("expected non-nil even when EXPLANATION comes first")
	}
	// When explIdx < fixedIdx, only FIXED code is extracted (no explanation split)
	if result.FixedCode == "" {
		t.Error("expected non-empty fixed code")
	}
}

func TestParseFixResponse_EmptyResponse(t *testing.T) {
	f := &Finding{File: "test.go", Line: 1, Message: "test"}
	if result := parseFixResponse("", f); result != nil {
		t.Error("expected nil for empty response")
	}
}

func TestParseFixResponse_WhitespaceOnlyFixedCode(t *testing.T) {
	f := &Finding{File: "test.go", Line: 1, Message: "test"}
	result := parseFixResponse("FIXED:   \n   \nEXPLANATION: Note", f)
	if result != nil {
		t.Error("expected nil when fixed code is only whitespace")
	}
}

func TestParseFixResponse_NilFinding(t *testing.T) {
	// The function takes *Finding and stores it in the suggestion; nil finding
	// should still work since it just stores the pointer.
	result := parseFixResponse("FIXED:\nsome code\nEXPLANATION: why", nil)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Finding != nil {
		t.Error("expected nil finding to be stored as-is")
	}
}

func TestParseFixResponse_WhitespacePadding(t *testing.T) {
	f := &Finding{File: "test.go", Line: 1, Message: "test"}
	// Response with extra whitespace around markers
	resp := "  FIXED:  \n  code here  \n  EXPLANATION:  reason here  "
	result := parseFixResponse(resp, f)
	if result == nil {
		t.Fatal("expected non-nil result with whitespace padding")
	}
	if result.FixedCode != "code here" {
		t.Errorf("expected 'code here', got %q", result.FixedCode)
	}
}

func TestSuggestFixes_ProviderReturnsError(t *testing.T) {
	provider := &fixMockProvider{err: fmt.Errorf("rate limited")}
	af := NewAutoFix(provider)

	findings := []Finding{testFinding(SeverityHigh, "handler.go", 13, "bug")}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 0 {
		t.Errorf("expected 0 suggestions on provider error, got %d", len(suggestions))
	}
}

func TestSuggestFixes_ProviderReturnsNilResponse(t *testing.T) {
	// Use a provider that returns (nil, nil) to test the nil response path
	provider := &nilResponseProvider{}
	af := NewAutoFix(provider)

	findings := []Finding{testFinding(SeverityHigh, "handler.go", 13, "bug")}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 0 {
		t.Errorf("expected 0 suggestions on nil response, got %d", len(suggestions))
	}
}

// nilResponseProvider returns (nil, nil) to simulate a nil LLM response.
type nilResponseProvider struct{}

func (n *nilResponseProvider) Chat(_ context.Context, _ []Message, _ ChatOpts) (*Response, error) {
	return nil, nil
}

func TestSuggestFixes_ProviderReturnsEmptyContent(t *testing.T) {
	provider := &fixMockProvider{response: ""}
	af := NewAutoFix(provider)

	findings := []Finding{testFinding(SeverityHigh, "handler.go", 13, "bug")}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 0 {
		t.Errorf("expected 0 suggestions on empty content, got %d", len(suggestions))
	}
}

// =====================================================================
// 7. Nil provider / empty findings (SuggestFixes guards)
// =====================================================================

func TestSuggestFixes_NilProvider(t *testing.T) {
	af := NewAutoFix(nil)
	findings := []Finding{testFinding(SeverityHigh, "handler.go", 13, "bug")}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if suggestions != nil {
		t.Errorf("expected nil suggestions with nil provider, got %v", suggestions)
	}
}

func TestSuggestFixes_EmptyFindings(t *testing.T) {
	provider := &fixMockProvider{response: "FIXED:\ncode\nEXPLANATION: fix"}
	af := NewAutoFix(provider)

	suggestions, err := af.SuggestFixes(context.Background(), nil, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if suggestions != nil {
		t.Errorf("expected nil suggestions with nil findings, got %v", suggestions)
	}
}

func TestSuggestFixes_AllInfoFindings(t *testing.T) {
	provider := &fixMockProvider{response: "FIXED:\ncode\nEXPLANATION: fix"}
	af := NewAutoFix(provider)

	findings := []Finding{
		testFinding(SeverityInfo, "handler.go", 10, "FYI 1"),
		testFinding(SeverityInfo, "handler.go", 11, "FYI 2"),
	}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 0 {
		t.Errorf("expected 0 suggestions when all findings are info, got %d", len(suggestions))
	}
}

// =====================================================================
// 8. Confidence and structure validation
// =====================================================================

func TestFixSuggestion_ConfidenceAlwaysSeven(t *testing.T) {
	provider := &fixMockProvider{
		response: "FIXED:\ncode\nEXPLANATION: fix.",
	}
	af := NewAutoFix(provider)

	findings := []Finding{
		testFinding(SeverityLow, "handler.go", 10, "minor issue"),
		testFinding(SeverityCritical, "handler.go", 13, "critical issue"),
	}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range suggestions {
		if s.Confidence != 0.7 {
			t.Errorf("expected confidence 0.7 for all suggestions, got %f", s.Confidence)
		}
	}
}

func TestSuggestFixes_FindingValueIdentity(t *testing.T) {
	provider := &fixMockProvider{
		response: "FIXED:\ncode\nEXPLANATION: fix.",
	}
	af := NewAutoFix(provider)

	findings := []Finding{
		testFinding(SeverityHigh, "a.go", 1, "finding A"),
		testFinding(SeverityHigh, "b.go", 2, "finding B"),
	}

	suggestions, err := af.SuggestFixes(context.Background(), findings, sampleDiff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Note: SuggestFixes iterates by value, so the Finding pointer points to a
	// copy. Verify that the values match, not the pointers.
	for i, s := range suggestions {
		if s.Finding.File != findings[i].File || s.Finding.Line != findings[i].Line || s.Finding.Message != findings[i].Message {
			t.Errorf("suggestion %d: finding values should match input slice element", i)
		}
	}
}

// =====================================================================
// 9. ExtractRelevantDiff — multi-file diff handling
// =====================================================================

func TestExtractRelevantDiff_MultiFileDiff(t *testing.T) {
	multiDiff := `diff --git a/auth.go b/auth.go
--- a/auth.go
+++ b/auth.go
@@ -1,5 +1,5 @@
 package auth
-func old() {}
+func new() {}
diff --git a/db.go b/db.go
--- a/db.go
+++ b/db.go
@@ -1,5 +1,5 @@
 package db
-func queryOld() {}
+func queryNew() {}
`
	// Should extract only the db.go part
	result := extractRelevantDiff(multiDiff, "db.go", 3)
	if result == "" {
		t.Fatal("expected non-empty result for db.go")
	}
	if strings.Contains(result, "auth") {
		t.Errorf("should not contain auth.go content, got %q", result)
	}
}

func TestExtractRelevantDiff_UnknownFileInDiff(t *testing.T) {
	result := extractRelevantDiff(sampleDiff, "nonexistent.go", 1)
	if result != "" {
		t.Errorf("expected empty for nonexistent file, got %q", result)
	}
}

// =====================================================================
// 10. NewAutoFix constructor
// =====================================================================

func TestNewAutoFix(t *testing.T) {
	provider := &fixMockProvider{response: ""}
	af := NewAutoFix(provider)
	if af == nil {
		t.Fatal("expected non-nil AutoFix")
	}
	if af.provider != provider {
		t.Error("expected provider to be stored")
	}
}

func TestNewAutoFix_NilProvider(t *testing.T) {
	af := NewAutoFix(nil)
	if af == nil {
		t.Fatal("expected non-nil AutoFix even with nil provider")
	}
}
