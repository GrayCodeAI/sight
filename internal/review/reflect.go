package review

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ReflectSystemPrompt is the system prompt for the self-reflection pass.
const ReflectSystemPrompt = `You are reviewing a set of code review findings for accuracy and relevance.
Your job is to FILTER OUT false positives, refine severity, and score each finding.

For each finding, decide:
1. KEEP — the finding is valid and actionable
2. DROP — the finding is a false positive, too vague, or not actionable
3. ADJUST — the finding is valid but severity should change

Also assign a numeric score from 1 to 10 indicating the confidence and importance:
- 1-3: low confidence or low importance (likely noise)
- 4-6: moderate confidence, worth noting
- 7-9: high confidence, should be addressed
- 10: certain and critical

Respond with a JSON array of kept/adjusted findings:
[
  {
    "index": 0,
    "action": "keep|drop|adjust",
    "severity": "critical|high|medium|low|info",
    "score": 7,
    "message": "refined message (or original if unchanged)",
    "reason": "why you kept/dropped/adjusted this"
  }
]

Drop findings that:
- Reference line numbers that don't exist in the diff
- Are generic advice not specific to the actual code
- Flag intentional patterns (e.g., empty error handling with a comment)
- Duplicate another finding's message

Adjust severity when:
- A "critical" finding is actually just a code smell → downgrade
- A "low" finding is actually exploitable → upgrade`

// BuildReflectPrompt constructs the prompt for self-reflection.
func BuildReflectPrompt(findings []Finding, diffContext string) string {
	var b strings.Builder
	b.WriteString("Review these findings for accuracy. The original diff context is provided below.\n\n")
	b.WriteString("## Findings to validate:\n\n")

	for i, f := range findings {
		b.WriteString(fmt.Sprintf("%d. [%s][%s] %s:%d — %s\n",
			i, severityStr(f.Severity), f.Concern, f.File, f.Line, f.Message))
		if f.Fix != "" {
			b.WriteString(fmt.Sprintf("   Fix: %s\n", f.Fix))
		}
	}

	b.WriteString("\n## Original diff (for context):\n\n```diff\n")
	if len(diffContext) > 8000 {
		b.WriteString(diffContext[:8000])
		b.WriteString("\n... (truncated)\n")
	} else {
		b.WriteString(diffContext)
	}
	b.WriteString("```\n")

	return b.String()
}

// ReflectResult holds the LLM's validation of a finding.
type ReflectResult struct {
	Index    int    `json:"index"`
	Action   string `json:"action"`
	Severity string `json:"severity"`
	Score    int    `json:"score"`
	Message  string `json:"message"`
	Reason   string `json:"reason"`
}

// ParseReflectResponse parses the self-reflection LLM response.
func ParseReflectResponse(response string) []ReflectResult {
	jsonStr := extractReflectJSON(response)
	if jsonStr == "" {
		return nil
	}

	var results []ReflectResult
	if err := json.Unmarshal([]byte(jsonStr), &results); err != nil {
		return nil
	}
	return results
}

// ApplyReflection filters and adjusts findings based on reflection results.
func ApplyReflection(findings []Finding, reflections []ReflectResult) []Finding {
	return ApplyReflectionWithScore(findings, reflections, 0)
}

// ApplyReflectionWithScore filters and adjusts findings based on reflection results.
// Findings with a score below minScore are dropped. A minScore of 0 disables
// score-based filtering.
func ApplyReflectionWithScore(findings []Finding, reflections []ReflectResult, minScore int) []Finding {
	if len(reflections) == 0 {
		return findings
	}

	actions := make(map[int]ReflectResult)
	for _, r := range reflections {
		actions[r.Index] = r
	}

	var result []Finding
	for i, f := range findings {
		r, exists := actions[i]
		if !exists {
			result = append(result, f)
			continue
		}

		switch r.Action {
		case "drop":
			continue
		case "adjust":
			f.Severity = parseSeverity(r.Severity)
			if r.Message != "" {
				f.Message = r.Message
			}
			// Filter by score threshold
			if minScore > 0 && r.Score > 0 && r.Score < minScore {
				continue
			}
			result = append(result, f)
		default: // "keep"
			if r.Message != "" && r.Message != f.Message {
				f.Message = r.Message
			}
			// Filter by score threshold
			if minScore > 0 && r.Score > 0 && r.Score < minScore {
				continue
			}
			result = append(result, f)
		}
	}

	return result
}

func severityStr(s Severity) string {
	names := [...]string{"info", "low", "medium", "high", "critical"}
	if int(s) < len(names) {
		return names[s]
	}
	return "unknown"
}

func extractReflectJSON(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "```json") {
		parts := strings.SplitN(s, "```json", 2)
		if len(parts) == 2 {
			end := strings.Index(parts[1], "```")
			if end != -1 {
				s = strings.TrimSpace(parts[1][:end])
			}
		}
	}
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start == -1 || end == -1 || end <= start {
		return ""
	}
	return s[start : end+1]
}
