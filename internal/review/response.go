package review

import (
	"encoding/json"
	"strings"
)

// rawFinding represents the JSON structure expected from the LLM.
type rawFinding struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	EndLine   int    `json:"end_line"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Fix       string `json:"fix"`
	Reasoning string `json:"reasoning"`
}

// ParseResponse extracts structured findings from the LLM response text.
// It handles common formatting quirks: markdown code blocks, leading text, etc.
func ParseResponse(response string, concernName string) []Finding {
	jsonStr := extractJSON(response)
	if jsonStr == "" {
		return nil
	}

	var raw []rawFinding
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil
	}

	var findings []Finding
	for _, r := range raw {
		if r.Message == "" || r.File == "" {
			continue
		}
		findings = append(findings, Finding{
			Concern:   concernName,
			Severity:  parseSeverity(r.Severity),
			File:      r.File,
			Line:      r.Line,
			EndLine:   r.EndLine,
			Message:   r.Message,
			Fix:       r.Fix,
			Reasoning: r.Reasoning,
		})
	}

	return findings
}

// extractJSON finds and returns the JSON array from potentially wrapped response text.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)

	if strings.Contains(s, "```json") {
		parts := strings.SplitN(s, "```json", 2)
		if len(parts) == 2 {
			end := strings.Index(parts[1], "```")
			if end != -1 {
				s = strings.TrimSpace(parts[1][:end])
			} else {
				s = strings.TrimSpace(parts[1])
			}
		}
	} else if strings.Contains(s, "```") {
		parts := strings.SplitN(s, "```", 2)
		if len(parts) == 2 {
			rest := parts[1]
			if idx := strings.Index(rest, "\n"); idx != -1 {
				rest = rest[idx+1:]
			}
			end := strings.Index(rest, "```")
			if end != -1 {
				s = strings.TrimSpace(rest[:end])
			} else {
				s = strings.TrimSpace(rest)
			}
		}
	}

	start := strings.Index(s, "[")
	if start == -1 {
		return ""
	}
	end := strings.LastIndex(s, "]")
	if end == -1 || end <= start {
		return ""
	}

	return s[start : end+1]
}

func parseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityInfo
	}
}
