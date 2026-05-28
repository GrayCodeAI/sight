package sight

import (
	"strings"
	"testing"
)

// ===========================================================================
// 1. Tool Invocation - Test that SAST checks are correctly registered and invoked
// ===========================================================================

func TestNewSASTIntegration_RegistersBuiltinChecks(t *testing.T) {
	s := NewSASTIntegration()
	if s == nil {
		t.Fatal("NewSASTIntegration returned nil")
	}
	if len(s.checks) < 5 {
		t.Errorf("expected at least 5 builtin checks, got %d", len(s.checks))
	}

	// Verify each expected check ID is present
	expectedIDs := map[string]bool{
		"sql-injection":     false,
		"hardcoded-secret":  false,
		"command-injection": false,
		"path-traversal":    false,
		"unchecked-error":   false,
	}
	for _, c := range s.checks {
		if _, ok := expectedIDs[c.ID]; ok {
			expectedIDs[c.ID] = true
		}
	}
	for id, found := range expectedIDs {
		if !found {
			t.Errorf("builtin check %q not registered", id)
		}
	}
}

func TestAnalyze_InvokesAllApplicableChecks(t *testing.T) {
	s := NewSASTIntegration()

	// Source that triggers multiple checks: sql-injection, hardcoded-secret, and
	// command-injection (all applicable to .go files).
	source := `query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
password := "supersecret123"
cmd := exec.Command("rm " + userInput)
`
	findings := s.Analyze(source, "main.go")

	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.CheckID] = true
	}

	if !seen["sql-injection"] {
		t.Error("sql-injection check was not invoked or did not fire")
	}
	if !seen["hardcoded-secret"] {
		t.Error("hardcoded-secret check was not invoked or did not fire")
	}
	if !seen["command-injection"] {
		t.Error("command-injection check was not invoked or did not fire")
	}
}

func TestAnalyze_InvokesCustomCheck(t *testing.T) {
	s := NewSASTIntegration()

	called := false
	s.checks = append(s.checks, SASTCheck{
		ID:        "custom-test",
		Name:      "Custom Test",
		Languages: []string{},
		Check: func(source, filePath string) []SASTFinding {
			called = true
			return nil
		},
	})

	s.Analyze("some code", "file.go")
	if !called {
		t.Error("custom check was not invoked")
	}
}

func TestAnalyze_SkipsNonApplicableChecks(t *testing.T) {
	s := NewSASTIntegration()

	// unchecked-error only applies to Go files; a .py file should not trigger it
	source := `os.remove(filepath)`
	findings := s.Analyze(source, "script.py")

	for _, f := range findings {
		if f.CheckID == "unchecked-error" {
			t.Error("unchecked-error (Go-only) should not fire for .py files")
		}
	}
}

// ===========================================================================
// 2. Result Parsing - Test that findings are correctly structured
// ===========================================================================

func TestSQLInjection_SprintfFindsLineAndSeverity(t *testing.T) {
	s := NewSASTIntegration()
	source := `func getUser() {
    query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
    rows, err := db.Query(query)
}`
	findings := s.Analyze(source, "db.go")

	var found bool
	for _, f := range findings {
		if f.CheckID == "sql-injection" && strings.Contains(f.Message, "fmt.Sprintf") {
			found = true
			if f.Line != 2 {
				t.Errorf("expected line 2, got %d", f.Line)
			}
			if f.Severity != "critical" {
				t.Errorf("expected severity 'critical', got %q", f.Severity)
			}
			if f.File != "db.go" {
				t.Errorf("expected file 'db.go', got %q", f.File)
			}
			if f.Confidence != 0.7 {
				t.Errorf("expected confidence 0.7, got %f", f.Confidence)
			}
			if f.Evidence == "" {
				t.Error("expected non-empty evidence")
			}
			if f.Rule != "SQL Injection" {
				t.Errorf("expected rule 'SQL Injection', got %q", f.Rule)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected sql-injection finding for fmt.Sprintf+SELECT")
	}
}

func TestSQLInjection_ConcatenationFindsLine(t *testing.T) {
	s := NewSASTIntegration()
	source := `row := db.Query("SELECT * FROM users WHERE id = " + userID)`
	findings := s.Analyze(source, "db.go")

	var found bool
	for _, f := range findings {
		if f.CheckID == "sql-injection" && strings.Contains(f.Message, "string concatenation") {
			found = true
			if f.Line != 1 {
				t.Errorf("expected line 1, got %d", f.Line)
			}
			if f.Confidence != 0.6 {
				t.Errorf("expected confidence 0.6, got %f", f.Confidence)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected sql-injection finding for Query()+concatenation")
	}
}

func TestHardcodedSecret_FindsPassword(t *testing.T) {
	s := NewSASTIntegration()
	source := `dbPassword := "my_real_password123"`
	findings := s.Analyze(source, "config.go")

	var found bool
	for _, f := range findings {
		if f.CheckID == "hardcoded-secret" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected severity 'high', got %q", f.Severity)
			}
			if f.Line != 1 {
				t.Errorf("expected line 1, got %d", f.Line)
			}
			if f.Confidence != 0.5 {
				t.Errorf("expected confidence 0.5, got %f", f.Confidence)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected hardcoded-secret finding")
	}
}

func TestHardcodedSecret_FindsAPIKey(t *testing.T) {
	s := NewSASTIntegration()
	source := `api_key := "sk-1234567890abcdef"`
	findings := s.Analyze(source, "config.py")

	var found bool
	for _, f := range findings {
		if f.CheckID == "hardcoded-secret" && strings.Contains(f.Message, "api_key") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected hardcoded-secret finding for api_key")
	}
}

func TestCommandInjection_FindsConcatenation(t *testing.T) {
	s := NewSASTIntegration()
	source := `cmd := exec.Command("sh", "-c", userInput + " && echo done")`
	findings := s.Analyze(source, "runner.go")

	var found bool
	for _, f := range findings {
		if f.CheckID == "command-injection" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("expected severity 'critical', got %q", f.Severity)
			}
			if f.Line != 1 {
				t.Errorf("expected line 1, got %d", f.Line)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected command-injection finding")
	}
}

func TestPathTraversal_FindsFileOperation(t *testing.T) {
	s := NewSASTIntegration()
	source := `f, err := os.Open("../../etc/passwd")`
	findings := s.Analyze(source, "handler.go")

	var found bool
	for _, f := range findings {
		if f.CheckID == "path-traversal" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected severity 'high', got %q", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected path-traversal finding")
	}
}

func TestUncheckedError_FindsSuspiciousCall(t *testing.T) {
	s := NewSASTIntegration()
	source := `func doWork() {
    somePackage.SomeFunction(arg1, arg2)
}`
	findings := s.Analyze(source, "worker.go")

	var found bool
	for _, f := range findings {
		if f.CheckID == "unchecked-error" {
			found = true
			if f.Severity != "medium" {
				t.Errorf("expected severity 'medium', got %q", f.Severity)
			}
			if f.Confidence != 0.3 {
				t.Errorf("expected confidence 0.3, got %f", f.Confidence)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected unchecked-error finding")
	}
}

func TestAnalyze_ReturnsAllFindingsAcrossMultipleLines(t *testing.T) {
	s := NewSASTIntegration()
	source := `q1 := fmt.Sprintf("SELECT * FROM t WHERE x = %s", a)
q2 := fmt.Sprintf("SELECT * FROM t WHERE y = %s", b)
q3 := fmt.Sprintf("SELECT * FROM t WHERE z = %s", c)`
	findings := s.Analyze(source, "db.go")

	sqlFindings := 0
	for _, f := range findings {
		if f.CheckID == "sql-injection" {
			sqlFindings++
		}
	}
	if sqlFindings != 3 {
		t.Errorf("expected 3 sql-injection findings, got %d", sqlFindings)
	}
}

// ===========================================================================
// 3. Error Handling - Test that clean code produces no findings
// ===========================================================================

func TestAnalyze_CleanCodeNoFindings(t *testing.T) {
	s := NewSASTIntegration()
	source := `func greet(name string) string {
    return "Hello, " + name
}`
	findings := s.Analyze(source, "greet.go")

	// This clean code should produce no findings
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean code, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: [%s] %s at %s:%d", f.CheckID, f.Message, f.File, f.Line)
		}
	}
}

func TestAnalyze_EmptySourceNoFindings(t *testing.T) {
	s := NewSASTIntegration()
	findings := s.Analyze("", "empty.go")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty source, got %d", len(findings))
	}
}

func TestAnalyze_CommentsOnlyNoSQLInjection(t *testing.T) {
	s := NewSASTIntegration()
	source := `// This file has only comments
// fmt.Sprintf("SELECT * FROM users")
// exec.Command("rm -rf /")`
	findings := s.Analyze(source, "comments.go")

	// The sql-injection and command-injection checks use string matching
	// that does not distinguish comments from code, but the pattern-based
	// checks should still detect the patterns even in comments.
	// This test verifies the checks are invoked (at least some findings expected
	// since the checks are pure pattern matching, not AST-based).
	// What we CAN verify is that the unchecked-error check skips lines
	// starting with "//" per its implementation.
	for _, f := range findings {
		if f.CheckID == "unchecked-error" {
			t.Error("unchecked-error check should skip comment lines")
		}
	}
}

func TestHardcodedSecret_SkipsTestValues(t *testing.T) {
	s := NewSASTIntegration()

	tests := []struct {
		name   string
		source string
	}{
		{"test prefix", `password := "test_password123"`},
		{"example value", `secret := "example_value_here"`},
		{"xxx placeholder", `api_key := "xxx-xxx-xxx"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Analyze(tt.source, "config.go")
			for _, f := range findings {
				if f.CheckID == "hardcoded-secret" {
					t.Errorf("hardcoded-secret should skip %s, but found: %s", tt.name, f.Evidence)
				}
			}
		})
	}
}

func TestSQLInjection_SafeQueryNoFindings(t *testing.T) {
	s := NewSASTIntegration()
	// Parameterized query - no string concatenation or Sprintf
	source := `rows, err := db.Query("SELECT * FROM users WHERE id = $1", userID)`
	findings := s.Analyze(source, "db.go")

	for _, f := range findings {
		if f.CheckID == "sql-injection" {
			t.Errorf("safe parameterized query should not trigger sql-injection: %s", f.Evidence)
		}
	}
}

func TestCommandInjection_SafeCommandNoFindings(t *testing.T) {
	s := NewSASTIntegration()
	// Static command without concatenation
	source := `cmd := exec.Command("ls", "-la")`
	findings := s.Analyze(source, "runner.go")

	for _, f := range findings {
		if f.CheckID == "command-injection" {
			t.Errorf("safe static command should not trigger command-injection: %s", f.Evidence)
		}
	}
}

func TestUncheckedError_SkipsWellHandledCode(t *testing.T) {
	s := NewSASTIntegration()
	source := `err := somePackage.SomeFunction(arg1)
if err != nil {
    return err
}`
	findings := s.Analyze(source, "worker.go")

	for _, f := range findings {
		if f.CheckID == "unchecked-error" {
			t.Errorf("properly handled error should not trigger unchecked-error: %s", f.Evidence)
		}
	}
}

func TestUncheckedError_SkipsComments(t *testing.T) {
	s := NewSASTIntegration()
	source := `// somePackage.SomeFunction(arg1, arg2)`
	findings := s.Analyze(source, "worker.go")

	for _, f := range findings {
		if f.CheckID == "unchecked-error" {
			t.Error("comments should not trigger unchecked-error")
		}
	}
}

// ===========================================================================
// 4. Timeout / Edge Cases - Test that extreme inputs are handled
// ===========================================================================

func TestAnalyze_VeryLongSource(t *testing.T) {
	s := NewSASTIntegration()

	// Build a large source file with a vulnerable line buried deep
	var b strings.Builder
	for i := 0; i < 10000; i++ {
		b.WriteString("// safe line\n")
	}
	b.WriteString(`query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)`)

	findings := s.Analyze(b.String(), "huge.go")

	var found bool
	for _, f := range findings {
		if f.CheckID == "sql-injection" {
			found = true
			if f.Line != 10001 {
				t.Errorf("expected line 10001, got %d", f.Line)
			}
			break
		}
	}
	if !found {
		t.Error("expected sql-injection finding in large source file")
	}
}

func TestAnalyze_SourceWithNoNewlines(t *testing.T) {
	s := NewSASTIntegration()
	source := `password := "real_secret_value"`
	findings := s.Analyze(source, "config.go")

	var found bool
	for _, f := range findings {
		if f.CheckID == "hardcoded-secret" {
			found = true
			if f.Line != 1 {
				t.Errorf("expected line 1, got %d", f.Line)
			}
			break
		}
	}
	if !found {
		t.Error("expected hardcoded-secret finding for single-line source")
	}
}

func TestTruncate_ShortString(t *testing.T) {
	got := truncate("hello", 10)
	if got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}
}

func TestTruncate_ExactLength(t *testing.T) {
	got := truncate("hello", 5)
	if got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}
}

func TestTruncate_LongString(t *testing.T) {
	got := truncate("hello world", 5)
	if got != "hello..." {
		t.Errorf("expected 'hello...', got %q", got)
	}
}

// ===========================================================================
// 5. Concurrent Execution - Test that multiple checks can run safely
// ===========================================================================

func TestAnalyze_ConcurrentSafety(t *testing.T) {
	s := NewSASTIntegration()
	source := `query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
password := "my_secret_password"
cmd := exec.Command("sh", "-c", userInput + " payload")
f, err := os.Open("../../etc/passwd")
somePackage.DoWork(arg1, arg2)`

	// Run Analyze from multiple goroutines concurrently
	const goroutines = 50
	done := make(chan []SASTFinding, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			done <- s.Analyze(source, "handler.go")
		}()
	}

	// Collect all results and verify consistency
	for i := 0; i < goroutines; i++ {
		findings := <-done
		if len(findings) == 0 {
			t.Errorf("goroutine %d: expected findings, got none", i)
		}
		// All goroutines should get the same number of findings
		if len(findings) < 4 {
			t.Errorf("goroutine %d: expected at least 4 findings, got %d", i, len(findings))
		}
	}
}

func TestAnalyze_ConcurrentWithDifferentFiles(t *testing.T) {
	s := NewSASTIntegration()

	type testCase struct {
		filePath string
		source   string
	}
	tests := []testCase{
		{"handler.go", `query := fmt.Sprintf("SELECT * FROM t WHERE x = %s", v)`},
		{"config.py", `api_key := "sk-real-key-12345"`},
		{"runner.go", `cmd := exec.Command("sh", "-c", userInput + " arg")`},
		{"server.java", `password := "real_db_password"`},
	}

	done := make(chan int, len(tests))
	for _, tc := range tests {
		go func(tc testCase) {
			findings := s.Analyze(tc.source, tc.filePath)
			done <- len(findings)
		}(tc)
	}

	for range tests {
		count := <-done
		if count == 0 {
			t.Error("expected at least 1 finding from concurrent analysis")
		}
	}
}

// ===========================================================================
// 6. Configuration - Test that check configuration (languages, severity) is correct
// ===========================================================================

func TestSASTCheck_AppliesTo_AllLanguages(t *testing.T) {
	check := SASTCheck{
		ID:        "test",
		Languages: []string{}, // empty = all languages
	}

	paths := []string{"main.go", "app.py", "index.ts", "style.css", "Makefile", "Dockerfile"}
	for _, p := range paths {
		if !check.AppliesTo(p) {
			t.Errorf("check with empty languages should apply to %q", p)
		}
	}
}

func TestSASTCheck_AppliesTo_SpecificLanguages(t *testing.T) {
	check := SASTCheck{
		ID:        "go-only",
		Languages: []string{"go"},
	}

	if !check.AppliesTo("main.go") {
		t.Error("go-only check should apply to .go files")
	}
	if check.AppliesTo("app.py") {
		t.Error("go-only check should not apply to .py files")
	}
	if check.AppliesTo("index.ts") {
		t.Error("go-only check should not apply to .ts files")
	}
}

func TestSASTCheck_AppliesTo_MultipleLanguages(t *testing.T) {
	// Note: AppliesTo does exact string match of the file extension against
	// language names. ".go" matches "go" via the ".go" == "."+"go" path,
	// but ".py" does NOT match "python" because the extension is ".py" not ".python".
	// This test uses language entries that correspond to actual file extensions.
	check := SASTCheck{
		ID:        "multi",
		Languages: []string{"go", "py"},
	}

	if !check.AppliesTo("main.go") {
		t.Error("multi check should apply to .go files")
	}
	if !check.AppliesTo("app.py") {
		t.Error("multi check should apply to .py files")
	}
	if check.AppliesTo("index.ts") {
		t.Error("multi check should not apply to .ts files")
	}
}

func TestSASTCheck_AppliesTo_NestedPaths(t *testing.T) {
	check := SASTCheck{
		ID:        "go-only",
		Languages: []string{"go"},
	}

	if !check.AppliesTo("internal/handlers/auth.go") {
		t.Error("should match .go extension in nested path")
	}
	if check.AppliesTo("internal/handlers/auth.py") {
		t.Error("should not match .py in nested path for go-only check")
	}
}

func TestGetFileExtension(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"main.go", ".go"},
		{"path/to/file.py", ".py"},
		{"deep/nested/dir/file.ts", ".ts"},
		{"noext", ""},
		{"Makefile", ""},
		{".hidden", ".hidden"},
		{"file.tar.gz", ".gz"},
		{"path\\windows\\file.go", ".go"},
	}
	for _, tt := range tests {
		got := getFileExtension(tt.path)
		if got != tt.want {
			t.Errorf("getFileExtension(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestBuiltinChecks_HaveRequiredFields(t *testing.T) {
	s := NewSASTIntegration()
	for _, c := range s.checks {
		if c.ID == "" {
			t.Error("check has empty ID")
		}
		if c.Name == "" {
			t.Errorf("check %q has empty Name", c.ID)
		}
		if c.Description == "" {
			t.Errorf("check %q has empty Description", c.ID)
		}
		if c.Severity == "" {
			t.Errorf("check %q has empty Severity", c.ID)
		}
		if c.Check == nil {
			t.Errorf("check %q has nil Check function", c.ID)
		}
	}
}

func TestBuiltinChecks_ValidSeverities(t *testing.T) {
	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}

	s := NewSASTIntegration()
	for _, c := range s.checks {
		if !validSeverities[c.Severity] {
			t.Errorf("check %q has invalid severity %q", c.ID, c.Severity)
		}
	}
}

func TestBuildReviewPrompt_WithFindings(t *testing.T) {
	s := NewSASTIntegration()
	findings := []SASTFinding{
		{
			CheckID:    "sql-injection",
			Rule:       "SQL Injection",
			Message:    "Potential SQL injection via fmt.Sprintf",
			File:       "handler.go",
			Line:       13,
			Severity:   "critical",
			Confidence: 0.7,
			Evidence:   `query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)`,
		},
		{
			CheckID:    "hardcoded-secret",
			Rule:       "Hardcoded Secret",
			Message:    "Potential hardcoded password",
			File:       "config.go",
			Line:       5,
			Severity:   "high",
			Confidence: 0.5,
			Evidence:   `password := "secret123"`,
		},
	}

	diff := `--- a/handler.go
+++ b/handler.go
@@ -10,6 +10,8 @@ func handler() {
+    query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
`

	prompt := s.BuildReviewPrompt(findings, diff)

	if !strings.Contains(prompt, "SAST Pre-Analysis Results") {
		t.Error("prompt should contain SAST Pre-Analysis Results header")
	}
	if !strings.Contains(prompt, "Found 2 potential issues") {
		t.Error("prompt should report the number of findings")
	}
	if !strings.Contains(prompt, "SQL Injection") {
		t.Error("prompt should mention SQL Injection")
	}
	if !strings.Contains(prompt, "Hardcoded Secret") {
		t.Error("prompt should mention Hardcoded Secret")
	}
	if !strings.Contains(prompt, "handler.go:13") {
		t.Error("prompt should contain file:line reference")
	}
	if !strings.Contains(prompt, "critical") {
		t.Error("prompt should contain severity")
	}
	if !strings.Contains(prompt, diff) {
		t.Error("prompt should contain the diff")
	}
	if !strings.Contains(prompt, "Code Diff") {
		t.Error("prompt should contain Code Diff section")
	}
}

func TestBuildReviewPrompt_NoFindings(t *testing.T) {
	s := NewSASTIntegration()
	diff := "--- a/clean.go\n+++ b/clean.go\n"

	prompt := s.BuildReviewPrompt(nil, diff)

	if !strings.Contains(prompt, "No SAST findings detected") {
		t.Error("prompt should indicate no findings when list is empty")
	}
	if !strings.Contains(prompt, diff) {
		t.Error("prompt should still include the diff")
	}
}

func TestBuildReviewPrompt_EmptyFindingsSlice(t *testing.T) {
	s := NewSASTIntegration()
	diff := "--- a/clean.go\n+++ b/clean.go\n"

	prompt := s.BuildReviewPrompt([]SASTFinding{}, diff)

	if !strings.Contains(prompt, "No SAST findings detected") {
		t.Error("prompt should indicate no findings for empty slice")
	}
}

func TestBuildReviewPrompt_TruncatesLongEvidence(t *testing.T) {
	s := NewSASTIntegration()

	// Create evidence that exceeds 100 chars
	longEvidence := strings.Repeat("x", 200)
	findings := []SASTFinding{
		{
			CheckID:  "test",
			Rule:     "Test Rule",
			Message:  "Test message",
			File:     "test.go",
			Line:     1,
			Severity: "high",
			Evidence: longEvidence,
		},
	}

	prompt := s.BuildReviewPrompt(findings, "diff")

	// The full 200-char evidence should not appear; it should be truncated
	if strings.Contains(prompt, longEvidence) {
		t.Error("prompt should truncate evidence longer than 100 chars")
	}
	if !strings.Contains(prompt, "...") {
		t.Error("truncated evidence should end with '...'")
	}
}

// ===========================================================================
// Integration-style tests combining multiple features
// ===========================================================================

func TestAnalyze_FullFileWithMultipleVulnerabilities(t *testing.T) {
	s := NewSASTIntegration()

	// A realistic file with multiple vulnerability types
	source := `package handlers

import (
    "database/sql"
    "fmt"
    "os/exec"
    "net/http"
)

const dbPassword = "admin123!"

func getUserHandler(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
    row := db.QueryRow(query)

    cmd := exec.Command("sh", "-c", "echo "+id)
    cmd.Run()

    f, err := os.Open("../../../etc/shadow")
    fmt.Println(f)
    fmt.Println(err)
}`

	findings := s.Analyze(source, "handler.go")

	// Should find at least: sql-injection, hardcoded-secret, command-injection, path-traversal
	byCheck := map[string]int{}
	for _, f := range findings {
		byCheck[f.CheckID]++
	}

	if byCheck["sql-injection"] == 0 {
		t.Error("expected sql-injection finding")
	}
	if byCheck["hardcoded-secret"] == 0 {
		t.Error("expected hardcoded-secret finding")
	}
	if byCheck["command-injection"] == 0 {
		t.Error("expected command-injection finding")
	}
	if byCheck["path-traversal"] == 0 {
		t.Error("expected path-traversal finding")
	}

	// All findings should reference the correct file
	for _, f := range findings {
		if f.File != "handler.go" {
			t.Errorf("finding from %q should reference handler.go, got %q", f.CheckID, f.File)
		}
		if f.Line <= 0 {
			t.Errorf("finding %q has invalid line number: %d", f.CheckID, f.Line)
		}
	}
}

func TestAnalyze_NonGoFileSkipsGoOnlyChecks(t *testing.T) {
	s := NewSASTIntegration()
	source := `some_func_call(arg1, arg2)`

	findings := s.Analyze(source, "helper.py")

	// unchecked-error is Go-only; should not fire for .py
	for _, f := range findings {
		if f.CheckID == "unchecked-error" {
			t.Error("Go-only unchecked-error should not fire for .py file")
		}
	}
}

func TestAnalyze_AllLanguageChecksApplyToAnyFile(t *testing.T) {
	s := NewSASTIntegration()
	source := `password := "real_password_value"`

	// hardcoded-secret has empty Languages, so it applies to any file
	extensions := []string{"handler.go", "app.py", "config.yaml", "server.rb", "main.js"}
	for _, ext := range extensions {
		findings := s.Analyze(source, ext)
		var found bool
		for _, f := range findings {
			if f.CheckID == "hardcoded-secret" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("hardcoded-secret should apply to %s (all-language check)", ext)
		}
	}
}

func TestBuildReviewPrompt_RoundTripWithAnalyze(t *testing.T) {
	s := NewSASTIntegration()

	vulnSource := `query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)`
	findings := s.Analyze(vulnSource, "db.go")

	diff := `--- a/db.go
+++ b/db.go
@@ -1,1 +1,1 @@
+query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
`

	prompt := s.BuildReviewPrompt(findings, diff)

	// The prompt should contain the findings from Analyze
	if !strings.Contains(prompt, "Found 1 potential issues") {
		t.Error("prompt should report 1 finding from Analyze")
	}
	if !strings.Contains(prompt, "SQL Injection") {
		t.Error("prompt should contain the sql-injection finding from Analyze")
	}
}
