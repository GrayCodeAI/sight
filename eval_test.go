package sight_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/GrayCodeAI/sight"
)

// evalMockProvider returns a fixed set of findings for every Chat call.
type evalMockProvider struct {
	findings []mockFinding
}

type mockFinding struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	EndLine   int    `json:"end_line,omitempty"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Fix       string `json:"fix,omitempty"`
	Reasoning string `json:"reasoning,omitempty"`
}

func (p *evalMockProvider) Chat(_ context.Context, _ []sight.Message, _ sight.ChatOpts) (*sight.Response, error) {
	data, _ := json.Marshal(p.findings)
	return &sight.Response{Content: string(data), TokensUsed: 100}, nil
}

// sampleDiff is a minimal valid unified diff for eval tests.
const sampleDiff = `diff --git a/app.go b/app.go
index aaa1111..bbb2222 100644
--- a/app.go
+++ b/app.go
@@ -1,4 +1,6 @@
 package app

+func unsafe() { exec("rm -rf /") }
+
 func main() {}
`

func newEvalProvider() *evalMockProvider {
	return &evalMockProvider{
		findings: []mockFinding{
			{
				File:     "app.go",
				Line:     3,
				Severity: "critical",
				Message:  "Command injection: unsanitized shell execution",
			},
			{
				File:     "app.go",
				Line:     3,
				Severity: "medium",
				Message:  "Hardcoded destructive command",
			},
		},
	}
}

func evalOpts(p sight.Provider) []sight.Option {
	return []sight.Option{
		sight.WithProvider(p),
		sight.WithConcerns("security"),
		sight.WithParallel(false),
		sight.WithGitContext(false),
	}
}

func TestRunEval_ExpectationPass(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "detects command injection",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MessageContains: "command injection"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Passed {
		t.Errorf("expected pass, got failures: %v", results[0].Failures)
	}
}

func TestRunEval_ExpectationFail(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "expects buffer overflow (not present)",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MessageContains: "buffer overflow"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if results[0].Passed {
		t.Error("expected failure, got pass")
	}
	if len(results[0].Failures) != 1 {
		t.Errorf("expected 1 failure description, got %d", len(results[0].Failures))
	}
}

func TestRunEval_ConcernMatch(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "concern filter",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{Concern: "security", MessageContains: "injection"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("expected pass, got failures: %v", results[0].Failures)
	}
}

func TestRunEval_MinSeverity(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "severity at least high",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MinSeverity: "high", MessageContains: "injection"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("expected pass (critical >= high), got failures: %v", results[0].Failures)
	}
}

func TestRunEval_MinSeverityTooHigh(t *testing.T) {
	// Provider returns a "medium" finding; we require "critical".
	provider := &evalMockProvider{
		findings: []mockFinding{
			{File: "app.go", Line: 3, Severity: "medium", Message: "some issue"},
		},
	}
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "severity too low",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MinSeverity: "critical"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if results[0].Passed {
		t.Error("expected failure (medium < critical), got pass")
	}
}

func TestRunEval_FileMatch(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "file filter",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{File: "app.go"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("expected pass, got failures: %v", results[0].Failures)
	}
}

func TestRunEval_DenialPass(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "no false positive for XSS",
				Diff: sampleDiff,
				DenyFindings: []sight.EvalDenial{
					{MessageContains: "cross-site scripting"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("expected pass (XSS not found), got failures: %v", results[0].Failures)
	}
}

func TestRunEval_DenialFail(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "deny injection findings",
				Diff: sampleDiff,
				DenyFindings: []sight.EvalDenial{
					{MessageContains: "injection"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if results[0].Passed {
		t.Error("expected failure (injection finding exists), got pass")
	}
}

func TestRunEval_DenialByConcern(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "deny style concern (not present)",
				Diff: sampleDiff,
				DenyFindings: []sight.EvalDenial{
					{Concern: "style"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("expected pass (no style findings), got failures: %v", results[0].Failures)
	}
}

func TestRunEval_MultipleCases(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "case 1: pass",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MessageContains: "injection"},
				},
			},
			{
				Name: "case 2: fail",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MessageContains: "does not exist"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if !results[0].Passed {
		t.Error("case 1 should pass")
	}
	if results[1].Passed {
		t.Error("case 2 should fail")
	}
}

func TestRunEval_CombinedExpectAndDeny(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "expect injection, deny XSS",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MessageContains: "injection"},
				},
				DenyFindings: []sight.EvalDenial{
					{MessageContains: "XSS"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("expected pass, got failures: %v", results[0].Failures)
	}
}

func TestRunEval_NilSuite(t *testing.T) {
	results, err := sight.RunEval(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results for nil suite, got %v", results)
	}
}

func TestRunEval_EmptySuite(t *testing.T) {
	results, err := sight.RunEval(context.Background(), &sight.EvalSuite{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results for empty suite, got %v", results)
	}
}

func TestRunEval_FindingsPopulated(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "check findings are returned",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MessageContains: "injection"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if len(results[0].Findings) == 0 {
		t.Error("expected findings to be populated in eval result")
	}
}

func TestParseEvalSuite(t *testing.T) {
	raw := `{
		"cases": [
			{
				"name": "sql injection test",
				"diff": "diff --git a/f.go b/f.go\n--- a/f.go\n+++ b/f.go\n@@ -1 +1 @@\n-safe\n+unsafe",
				"expect_findings": [
					{"concern": "security", "min_severity": "high", "message_contains": "SQL"}
				],
				"deny_findings": [
					{"message_contains": "style issue"}
				]
			}
		]
	}`

	suite, err := sight.ParseEvalSuite([]byte(raw))
	if err != nil {
		t.Fatalf("ParseEvalSuite error: %v", err)
	}
	if len(suite.Cases) != 1 {
		t.Fatalf("expected 1 case, got %d", len(suite.Cases))
	}
	c := suite.Cases[0]
	if c.Name != "sql injection test" {
		t.Errorf("unexpected name: %s", c.Name)
	}
	if len(c.ExpectFindings) != 1 {
		t.Fatalf("expected 1 expectation, got %d", len(c.ExpectFindings))
	}
	if c.ExpectFindings[0].Concern != "security" {
		t.Errorf("expected concern=security, got %s", c.ExpectFindings[0].Concern)
	}
	if c.ExpectFindings[0].MinSeverity != "high" {
		t.Errorf("expected min_severity=high, got %s", c.ExpectFindings[0].MinSeverity)
	}
	if c.ExpectFindings[0].MessageContains != "SQL" {
		t.Errorf("expected message_contains=SQL, got %s", c.ExpectFindings[0].MessageContains)
	}
	if len(c.DenyFindings) != 1 {
		t.Fatalf("expected 1 denial, got %d", len(c.DenyFindings))
	}
	if c.DenyFindings[0].MessageContains != "style issue" {
		t.Errorf("expected message_contains='style issue', got %s", c.DenyFindings[0].MessageContains)
	}
}

func TestLoadEvalSuite(t *testing.T) {
	suiteJSON := `{
		"cases": [
			{
				"name": "loaded from file",
				"diff": "diff --git a/x.go b/x.go\n--- a/x.go\n+++ b/x.go\n@@ -1 +1 @@\n-old\n+new",
				"expect_findings": [{"message_contains": "test"}]
			}
		]
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "suite.json")
	if err := os.WriteFile(path, []byte(suiteJSON), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	suite, err := sight.LoadEvalSuite(path)
	if err != nil {
		t.Fatalf("LoadEvalSuite error: %v", err)
	}
	if len(suite.Cases) != 1 {
		t.Fatalf("expected 1 case, got %d", len(suite.Cases))
	}
	if suite.Cases[0].Name != "loaded from file" {
		t.Errorf("unexpected name: %s", suite.Cases[0].Name)
	}
}

func TestLoadEvalSuite_FileNotFound(t *testing.T) {
	_, err := sight.LoadEvalSuite("/nonexistent/path/suite.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseEvalSuite_InvalidJSON(t *testing.T) {
	_, err := sight.ParseEvalSuite([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestEvalSummary(t *testing.T) {
	results := []sight.EvalResult{
		{Case: "a", Passed: true},
		{Case: "b", Passed: true},
		{Case: "c", Passed: false, Failures: []string{"missed finding"}},
	}

	passed, failed, rate := sight.EvalSummary(results)
	if passed != 2 {
		t.Errorf("expected 2 passed, got %d", passed)
	}
	if failed != 1 {
		t.Errorf("expected 1 failed, got %d", failed)
	}
	// rate should be 2/3 ~= 0.6667
	if rate < 0.66 || rate > 0.67 {
		t.Errorf("expected rate ~0.6667, got %f", rate)
	}
}

func TestEvalSummary_AllPass(t *testing.T) {
	results := []sight.EvalResult{
		{Case: "a", Passed: true},
		{Case: "b", Passed: true},
	}

	passed, failed, rate := sight.EvalSummary(results)
	if passed != 2 || failed != 0 || rate != 1.0 {
		t.Errorf("expected 2/0/1.0, got %d/%d/%f", passed, failed, rate)
	}
}

func TestEvalSummary_AllFail(t *testing.T) {
	results := []sight.EvalResult{
		{Case: "a", Passed: false},
	}

	passed, failed, rate := sight.EvalSummary(results)
	if passed != 0 || failed != 1 || rate != 0.0 {
		t.Errorf("expected 0/1/0.0, got %d/%d/%f", passed, failed, rate)
	}
}

func TestEvalSummary_Empty(t *testing.T) {
	passed, failed, rate := sight.EvalSummary(nil)
	if passed != 0 || failed != 0 || rate != 0.0 {
		t.Errorf("expected 0/0/0.0, got %d/%d/%f", passed, failed, rate)
	}
}

func TestRunEval_CaseInsensitiveMatch(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "case insensitive message",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MessageContains: "COMMAND INJECTION"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("expected case-insensitive match to pass, got failures: %v", results[0].Failures)
	}
}

func TestRunEval_MultipleExpectations(t *testing.T) {
	provider := newEvalProvider()
	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "both expectations must match",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MessageContains: "injection"},
					{MessageContains: "destructive"},
				},
			},
		},
	}

	results, err := sight.RunEval(context.Background(), suite, evalOpts(provider)...)
	if err != nil {
		t.Fatalf("RunEval error: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("expected both expectations to match, got failures: %v", results[0].Failures)
	}
}

func TestRunEval_ContextCancelled(t *testing.T) {
	provider := newEvalProvider()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	suite := &sight.EvalSuite{
		Cases: []sight.EvalCase{
			{
				Name: "cancelled",
				Diff: sampleDiff,
				ExpectFindings: []sight.EvalExpectation{
					{MessageContains: "injection"},
				},
			},
		},
	}

	_, err := sight.RunEval(ctx, suite, evalOpts(provider)...)
	if err == nil {
		t.Error("expected context cancellation error")
	}
}
