package sight

import (
	"encoding/json"
	"math"
	"strings"
)

// CalculateStaticConfidence computes a confidence score for a finding produced
// by a static analysis rule.
//
// Base:
//   - 0.7 for pattern matches (default)
//   - 0.9 for exact matches (when the rule pattern is a simple string literal)
//
// Boosts (applied on top of base):
//   - +0.1 if the rule's antipattern is absent (i.e., the antipattern was not
//     triggered, meaning the finding survived the false-positive filter)
//   - +0.1 if the finding's message contains confirming context keywords
//
// Penalties:
//   - -0.2 if the rule ID belongs to a known false-positive-prone set
//     (e.g., COR-GO-001 unchecked error, COR-GO-002 goroutine leak)
//
// The result is clamped to [0.0, 1.0].
func CalculateStaticConfidence(finding Finding, rule StaticRule) float64 {
	conf := 0.7 // base for pattern matches

	// Boost: antipattern absent means the finding survived the FP filter,
	// which is a positive signal. If the rule has no antipattern defined,
	// we don't boost because there was no FP check to pass.
	if rule.Antipattern != nil {
		conf += 0.1
	}

	// Boost: if the message contains confirming context keywords that
	// strengthen the finding, add a boost.
	msg := strings.ToLower(finding.Message)
	if strings.Contains(msg, "without") || strings.Contains(msg, "unsanitized") ||
		strings.Contains(msg, "injection") || strings.Contains(msg, "traversal") ||
		strings.Contains(msg, "hardcoded") || strings.Contains(msg, "disabled") ||
		strings.Contains(msg, "deprecated") {
		conf += 0.1
	}

	// Penalty: certain rule IDs are known to be false-positive-prone.
	if isFalsePositiveProne(rule.ID) {
		conf -= 0.2
	}

	return clampConfidence(conf)
}

// isFalsePositiveProne returns true for rule IDs known to produce frequent
// false positives in practice.
func isFalsePositiveProne(id string) bool {
	switch id {
	case "COR-GO-001", // unchecked error — very noisy on benign calls
		"COR-GO-002", // goroutine leak — often uses channels not visible in single line
		"PERF-GO-003", // N+1 query — false positives on non-loop contexts
		"PERF-PY-001", // N+1 query Python — same reason
		"SEC-ANY-003": // HTTP in production — false positives on documentation/strings
		return true
	}
	return false
}

// CalculateLLMConfidence computes a confidence score for a finding produced
// by the LLM review pipeline.
//
// It parses the raw LLM response JSON for an explicit "confidence" field. If
// the LLM provided a confidence value (0.0-1.0) for this finding, it is used
// directly. Otherwise the default of 0.6 is returned.
func CalculateLLMConfidence(responseJSON string, finding Finding) float64 {
	if responseJSON == "" {
		return 0.6
	}

	type confItem struct {
		File       string  `json:"file"`
		Line       int     `json:"line"`
		Confidence float64 `json:"confidence"`
	}

	// Try to parse the response as a JSON array.
	jsonStr := responseJSON
	// Strip markdown fences if present.
	if idx := strings.Index(jsonStr, "```"); idx != -1 {
		jsonStr = strings.TrimSpace(jsonStr[idx:])
		if end := strings.Index(jsonStr[3:], "```"); end != -1 {
			jsonStr = jsonStr[3:end+3]
		}
	}
	start := strings.Index(jsonStr, "[")
	end := strings.LastIndex(jsonStr, "]")
	if start >= 0 && end > start {
		jsonStr = jsonStr[start : end+1]
	}

	var items []confItem
	if err := json.Unmarshal([]byte(jsonStr), &items); err != nil {
		return 0.6
	}

	// Match by file and line.
	for _, item := range items {
		if item.File == finding.File && item.Line == finding.Line {
			if item.Confidence > 0 && item.Confidence <= 1.0 {
				return item.Confidence
			}
		}
	}

	return 0.6
}

// CalculateTaintConfidence computes a confidence score for a finding produced
// by taint analysis.
//
// Base: 0.8 for direct taint (source -> sink with no intermediaries).
//
// Degrade:
//   - -0.1 per sanitizer present in the taint path
//   - -0.2 per intermediate variable between source and sink
//
// The result is clamped to [0.0, 1.0].
func CalculateTaintConfidence(source, sink string, sanitizers []string) float64 {
	conf := 0.8 // base for direct taint

	// Degrade for each sanitizer present in the path.
	for range sanitizers {
		conf -= 0.1
	}

	// Count intermediate variables from the source name.
	// A "direct" source like "function-parameter" has no intermediaries.
	// A source like "function-parameter" that propagated through x → y → query
	// would have 2 intermediaries.
	intermediates := countIntermediates(source)
	conf -= 0.2 * float64(intermediates)

	return clampConfidence(conf)
}

// countIntermediates estimates the number of intermediate variables from
// the taint source description.
func countIntermediates(source string) int {
	// Source descriptions like "function-parameter" are direct.
	// Source descriptions like "request-body-read" indicate one step.
	// We use heuristics based on known source names.
	switch source {
	case "function-parameter":
		return 0 // direct
	case "os.Args", "os.Getenv", "flag-arg":
		return 0 // direct
	case "request-body-read", "http-form-value", "json-decode":
		return 1 // goes through request object
	case "stdin-read":
		return 0
	default:
		return 1 // conservative default
	}
}

// ComputeConfidenceStats calculates aggregate confidence statistics from a
// slice of findings.
func ComputeConfidenceStats(findings []Finding) (avg float64, highCount, lowCount int) {
	if len(findings) == 0 {
		return 0, 0, 0
	}

	var total float64
	for _, f := range findings {
		total += f.Confidence
		if f.Confidence >= 0.7 {
			highCount++
		}
		if f.Confidence < 0.5 {
			lowCount++
		}
	}
	avg = total / float64(len(findings))
	// Round to 2 decimal places for cleaner output.
	avg = math.Round(avg*100) / 100
	return avg, highCount, lowCount
}

// BuildConfidenceBreakdown groups findings into confidence bands.
func BuildConfidenceBreakdown(findings []Finding) *ConfidenceBreakdown {
	if len(findings) == 0 {
		return nil
	}

	bd := &ConfidenceBreakdown{}
	for _, f := range findings {
		switch {
		case f.Confidence >= 0.7:
			bd.High = append(bd.High, f)
		case f.Confidence >= 0.5:
			bd.Medium = append(bd.Medium, f)
		default:
			bd.Low = append(bd.Low, f)
		}
	}
	return bd
}

// clampConfidence clamps a confidence value to [0.0, 1.0].
func clampConfidence(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1.0 {
		return 1.0
	}
	return v
}
