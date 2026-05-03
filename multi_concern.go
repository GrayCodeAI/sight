package sight

import "strings"

type ConcernType string

const (
	ConcernSecurity        ConcernType = "security"
	ConcernCorrectness     ConcernType = "correctness"
	ConcernPerformance     ConcernType = "performance"
	ConcernMaintainability ConcernType = "maintainability"
	ConcernStyle           ConcernType = "style"
	ConcernTestCoverage    ConcernType = "test_coverage"
)

type ConcernSpec struct {
	Type          ConcernType
	SystemPrompt  string
	Enabled       bool
	MinConfidence float64
}

func DefaultConcerns() []ConcernSpec {
	return []ConcernSpec{
		{
			Type:          ConcernSecurity,
			SystemPrompt:  "You are a security auditor. Focus on: injection vulnerabilities, authentication/authorization flaws, data exposure, unsafe deserialization, SSRF, path traversal. Cite CWE IDs when applicable.",
			Enabled:       true,
			MinConfidence: 0.7,
		},
		{
			Type:          ConcernCorrectness,
			SystemPrompt:  "You are a correctness reviewer. Focus on: logic errors, off-by-one, null/nil dereferences, race conditions, incorrect error handling, missing edge cases, broken contracts.",
			Enabled:       true,
			MinConfidence: 0.6,
		},
		{
			Type:          ConcernPerformance,
			SystemPrompt:  "You are a performance reviewer. Focus on: unnecessary allocations, O(n^2) algorithms where O(n) suffices, missing caching opportunities, N+1 queries, unbounded growth.",
			Enabled:       true,
			MinConfidence: 0.7,
		},
		{
			Type:          ConcernMaintainability,
			SystemPrompt:  "You are a maintainability reviewer. Focus on: overly complex functions (high cyclomatic complexity), unclear naming, missing abstractions, tight coupling, code that will be hard to change.",
			Enabled:       true,
			MinConfidence: 0.6,
		},
		{
			Type:          ConcernStyle,
			SystemPrompt:  "You are a style reviewer. Focus only on significant style issues: inconsistent naming conventions, dead code, unused imports, formatting that hinders readability.",
			Enabled:       false,
			MinConfidence: 0.8,
		},
		{
			Type:          ConcernTestCoverage,
			SystemPrompt:  "You are a test coverage reviewer. Focus on: new code without corresponding tests, untested error paths, functions with complex logic but no unit tests.",
			Enabled:       true,
			MinConfidence: 0.6,
		},
	}
}

func RouteConcerns(diff string, allConcerns []ConcernSpec) []ConcernSpec {
	lower := strings.ToLower(diff)
	var activated []ConcernSpec

	for _, c := range allConcerns {
		if !c.Enabled {
			continue
		}

		switch c.Type {
		case ConcernSecurity:
			if containsSecuritySignals(lower) {
				activated = append(activated, c)
			}
		case ConcernTestCoverage:
			if containsNewCode(lower) && !containsTestCode(lower) {
				activated = append(activated, c)
			}
		case ConcernPerformance:
			if containsPerformanceSignals(lower) {
				activated = append(activated, c)
			}
		default:
			activated = append(activated, c)
		}
	}

	if len(activated) == 0 {
		for _, c := range allConcerns {
			if c.Enabled && (c.Type == ConcernCorrectness || c.Type == ConcernMaintainability) {
				activated = append(activated, c)
			}
		}
	}

	return activated
}

func containsSecuritySignals(diff string) bool {
	signals := []string{"auth", "password", "token", "secret", "crypto", "hash",
		"session", "cookie", "cors", "csrf", "sql", "exec", "eval", "inject",
		"sanitize", "escape", "permission", "role", "admin"}
	for _, s := range signals {
		if strings.Contains(diff, s) {
			return true
		}
	}
	return false
}

func containsNewCode(diff string) bool {
	lines := strings.Split(diff, "\n")
	addedFunctions := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "+") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "func ") || strings.Contains(lower, "def ") ||
				strings.Contains(lower, "function ") {
				addedFunctions++
			}
		}
	}
	return addedFunctions > 0
}

func containsTestCode(diff string) bool {
	return strings.Contains(diff, "_test.go") || strings.Contains(diff, "test_") ||
		strings.Contains(diff, ".test.") || strings.Contains(diff, "spec.")
}

func containsPerformanceSignals(diff string) bool {
	signals := []string{"loop", "for ", "while", "range", "append", "map[",
		"query", "select ", "join", "cache", "pool", "buffer", "batch"}
	for _, s := range signals {
		if strings.Contains(diff, s) {
			return true
		}
	}
	return false
}
