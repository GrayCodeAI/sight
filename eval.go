package sight

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// EvalCase defines a single test case for evaluating review quality.
type EvalCase struct {
	Name           string            `json:"name"`
	Diff           string            `json:"diff"`
	ExpectFindings []EvalExpectation `json:"expect_findings"`
	DenyFindings   []EvalDenial      `json:"deny_findings"`
}

// EvalExpectation defines what we expect the reviewer to find.
type EvalExpectation struct {
	Concern         string `json:"concern,omitempty"`
	MinSeverity     string `json:"min_severity,omitempty"`
	MessageContains string `json:"message_contains,omitempty"`
	File            string `json:"file,omitempty"`
}

// EvalDenial defines what the reviewer should NOT report (false positive check).
type EvalDenial struct {
	MessageContains string `json:"message_contains,omitempty"`
	Concern         string `json:"concern,omitempty"`
}

// EvalResult is the outcome of running one eval case.
type EvalResult struct {
	Case     string    `json:"case"`
	Passed   bool      `json:"passed"`
	Failures []string  `json:"failures,omitempty"`
	Findings []Finding `json:"findings"`
}

// EvalSuite is a collection of eval cases.
type EvalSuite struct {
	Cases []EvalCase `json:"cases"`
}

// RunEval executes an evaluation suite against the reviewer with the given options.
// For each case it runs Review() on the diff, then checks expectations and denials.
func RunEval(ctx context.Context, suite *EvalSuite, opts ...Option) ([]EvalResult, error) {
	if suite == nil || len(suite.Cases) == 0 {
		return nil, nil
	}

	results := make([]EvalResult, 0, len(suite.Cases))

	for _, ec := range suite.Cases {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		er := EvalResult{Case: ec.Name}

		reviewResult, err := Review(ctx, ec.Diff, opts...)
		if err != nil {
			er.Failures = append(er.Failures, fmt.Sprintf("review error: %v", err))
			results = append(results, er)
			continue
		}

		er.Findings = reviewResult.Findings

		// Check expectations: each must be matched by at least one finding.
		for i, exp := range ec.ExpectFindings {
			if !matchExpectation(exp, reviewResult.Findings) {
				er.Failures = append(er.Failures,
					fmt.Sprintf("expect_findings[%d]: no finding matched %s", i, describeExpectation(exp)))
			}
		}

		// Check denials: none should be matched by any finding.
		for i, deny := range ec.DenyFindings {
			if matchDenial(deny, reviewResult.Findings) {
				er.Failures = append(er.Failures,
					fmt.Sprintf("deny_findings[%d]: found unexpected match for %s", i, describeDenial(deny)))
			}
		}

		er.Passed = len(er.Failures) == 0
		results = append(results, er)
	}

	return results, nil
}

// LoadEvalSuite loads eval cases from a JSON file.
func LoadEvalSuite(path string) (*EvalSuite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading eval suite: %w", err)
	}
	return ParseEvalSuite(data)
}

// ParseEvalSuite parses eval cases from JSON bytes.
func ParseEvalSuite(data []byte) (*EvalSuite, error) {
	var suite EvalSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		return nil, fmt.Errorf("parsing eval suite: %w", err)
	}
	return &suite, nil
}

// EvalSummary returns pass/fail counts and overall success rate.
func EvalSummary(results []EvalResult) (passed, failed int, rate float64) {
	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}
	total := passed + failed
	if total > 0 {
		rate = float64(passed) / float64(total)
	}
	return
}

// matchExpectation returns true if at least one finding matches all non-empty
// fields in the expectation.
func matchExpectation(exp EvalExpectation, findings []Finding) bool {
	for _, f := range findings {
		if matchesSingleExpectation(exp, f) {
			return true
		}
	}
	return false
}

func matchesSingleExpectation(exp EvalExpectation, f Finding) bool {
	if exp.Concern != "" && !strings.EqualFold(f.Concern, exp.Concern) {
		return false
	}
	if exp.MinSeverity != "" {
		minSev := ParseSeverity(exp.MinSeverity)
		if !f.Severity.AtLeast(minSev) {
			return false
		}
	}
	if exp.MessageContains != "" && !strings.Contains(
		strings.ToLower(f.Message), strings.ToLower(exp.MessageContains),
	) {
		return false
	}
	if exp.File != "" && !strings.EqualFold(f.File, exp.File) {
		return false
	}
	return true
}

// matchDenial returns true if any finding matches all non-empty fields in the denial.
func matchDenial(deny EvalDenial, findings []Finding) bool {
	for _, f := range findings {
		if matchesSingleDenial(deny, f) {
			return true
		}
	}
	return false
}

func matchesSingleDenial(deny EvalDenial, f Finding) bool {
	if deny.Concern != "" && !strings.EqualFold(f.Concern, deny.Concern) {
		return false
	}
	if deny.MessageContains != "" && !strings.Contains(
		strings.ToLower(f.Message), strings.ToLower(deny.MessageContains),
	) {
		return false
	}
	return true
}

func describeExpectation(exp EvalExpectation) string {
	var parts []string
	if exp.Concern != "" {
		parts = append(parts, fmt.Sprintf("concern=%q", exp.Concern))
	}
	if exp.MinSeverity != "" {
		parts = append(parts, fmt.Sprintf("min_severity=%q", exp.MinSeverity))
	}
	if exp.MessageContains != "" {
		parts = append(parts, fmt.Sprintf("message_contains=%q", exp.MessageContains))
	}
	if exp.File != "" {
		parts = append(parts, fmt.Sprintf("file=%q", exp.File))
	}
	if len(parts) == 0 {
		return "{}"
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func describeDenial(deny EvalDenial) string {
	var parts []string
	if deny.Concern != "" {
		parts = append(parts, fmt.Sprintf("concern=%q", deny.Concern))
	}
	if deny.MessageContains != "" {
		parts = append(parts, fmt.Sprintf("message_contains=%q", deny.MessageContains))
	}
	if len(parts) == 0 {
		return "{}"
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
