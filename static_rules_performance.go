package sight

import "regexp"

// performanceRules returns built-in performance rules across all languages.
func performanceRules() []StaticRule {
	return []StaticRule{
		// =====================================================================
		// PERFORMANCE
		// =====================================================================
		{
			ID:          "PERF-GO-001",
			Name:        "String Concat in Loop",
			Description: "String concatenation with += in a loop causes quadratic allocation",
			Language:    "go",
			Pattern:     regexp.MustCompile(`\w+\s*\+=\s*(?:"|\w+)`),
			Antipattern: regexp.MustCompile(`(?:int|float|byte|rune|uint|count|total|sum|num|idx|index|offset|i\s*\+)`),
			Severity:    "low",
			Category:    "performance",
			CWE:         "",
			Fix:         "Use strings.Builder for string concatenation in loops",
		},
		{
			ID:          "PERF-GO-002",
			Name:        "Unbounded Allocation",
			Description: "Slice allocation with user-controlled size without bounds check",
			Language:    "go",
			Pattern:     regexp.MustCompile(`make\s*\(\s*\[\]\w+\s*,\s*(?:req\.|r\.|input|param|query|size|length|count|n\b)`),
			Antipattern: regexp.MustCompile(`(?:maxSize|maxLen|cap|min\(|max\(|limit|<=|>=|<\s*\d|>\s*\d)`),
			Severity:    "medium",
			Category:    "performance",
			CWE:         "CWE-789",
			Fix:         "Validate and cap allocation sizes to prevent denial of service via memory exhaustion",
		},
		{
			ID:          "PERF-GO-003",
			Name:        "N+1 Query Pattern",
			Description: "Database query inside a loop suggests N+1 query problem",
			Language:    "go",
			Pattern:     regexp.MustCompile(`(?:\.Query|\.Exec|\.Get|\.Find|\.First|\.Select|\.Where)\s*\(`),
			Antipattern: regexp.MustCompile(`(?:batch|bulk|IN\s*\(|ids|Preload|Join)`),
			Severity:    "medium",
			Category:    "performance",
			CWE:         "",
			Fix:         "Batch database queries outside the loop; use IN clauses or JOINs",
		},
		{
			ID:          "PERF-PY-001",
			Name:        "N+1 Query Pattern (Python)",
			Description: "Database query inside a loop suggests N+1 query problem",
			Language:    "python",
			Pattern:     regexp.MustCompile(`(?:\.execute|\.query|\.filter|\.get|session\.)\s*\(`),
			Antipattern: regexp.MustCompile(`(?:bulk|batch|in_|prefetch|select_related|join)`),
			Severity:    "medium",
			Category:    "performance",
			CWE:         "",
			Fix:         "Use select_related/prefetch_related (Django) or eager loading (SQLAlchemy) to batch queries",
		},
		{
			ID:          "PERF-ANY-001",
			Name:        "Synchronous Sleep",
			Description: "Hardcoded sleep/delay found; consider exponential backoff or event-driven approach",
			Language:    "any",
			Pattern:     regexp.MustCompile(`(?:time\.Sleep|sleep\(|setTimeout.*\d{4,}|Thread\.sleep)`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|spec|mock|backoff|retry)`),
			Severity:    "low",
			Category:    "performance",
			CWE:         "",
			Fix:         "Use exponential backoff for retries or event-driven signaling instead of fixed sleeps",
		},
	}
}
