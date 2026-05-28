package review

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// maxFieldLen is the maximum length for extracted regex fields to prevent
// unbounded memory consumption from malformed LLM output.
const maxFieldLen = 2000

// Package-level compiled regexes for regex extraction (avoids recompilation in hot path).
var (
	regexFileRe   = regexp.MustCompile(`"file"\s*:\s*"([^"]+)"`)
	regexLineRe   = regexp.MustCompile(`"line"\s*:\s*(\d+)`)
	regexSevRe    = regexp.MustCompile(`"severity"\s*:\s*"([^"]+)"`)
	regexMsgRe    = regexp.MustCompile(`"message"\s*:\s*"([^"]+)"`)
	regexFixRe    = regexp.MustCompile(`"fix"\s*:\s*"([^"]+)"`)
	regexReasonRe = regexp.MustCompile(`"reasoning"\s*:\s*"([^"]+)"`)
	regexCweRe    = regexp.MustCompile(`"cwe"\s*:\s*"([^"]*)"`)
	regexBlockRe  = regexp.MustCompile(`\{[^{}]+\}`)
	// trailingCommaRe strips trailing commas before ] and } in JSON.
	trailingCommaRe = regexp.MustCompile(`,\s*([}\]])`)
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
	CWE       string `json:"cwe"`
}

// ParseResponse extracts structured findings from the LLM response text.
// It handles common formatting quirks: markdown code blocks, leading text, etc.
// If strict JSON parsing fails, it applies lenient fixes and then falls back
// to regex extraction.
func ParseResponse(response string, concernName string) []Finding {
	jsonStr := extractJSON(response)
	if jsonStr == "" {
		// Last resort: try regex extraction on the raw response.
		return regexExtractFindings(response, concernName)
	}

	var raw []rawFinding

	// First attempt: strict JSON parse.
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		// Second attempt: lenient JSON fix then parse.
		fixed := lenientJSON(jsonStr)
		if err2 := json.Unmarshal([]byte(fixed), &raw); err2 != nil {
			// Third attempt: regex fallback.
			return regexExtractFindings(response, concernName)
		}
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
			CWE:       r.CWE,
		})
	}

	return findings
}

// lenientJSON applies common fixes to malformed JSON from LLM output:
// - Strips trailing commas before ] and }
// - Removes JavaScript-style // line comments inside JSON
// - Fixes unescaped newlines inside string values
func lenientJSON(s string) string {
	// Remove JavaScript-style // comments (lines where // appears outside strings).
	// We handle this line-by-line to avoid mangling URLs in string values.
	lines := strings.Split(s, "\n")
	var cleaned []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		cleaned = append(cleaned, line)
	}
	s = strings.Join(cleaned, "\n")

	// Fix unescaped newlines inside string values by replacing literal
	// newlines between unmatched quotes. We do a simple approach: replace
	// any newline that sits between a non-closing context with \n.
	// A more targeted fix: replace \n inside JSON string values.
	var result strings.Builder
	inString := false
	escaped := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			result.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			result.WriteByte(ch)
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			result.WriteByte(ch)
			continue
		}
		if ch == '\n' && inString {
			result.WriteString("\\n")
			continue
		}
		result.WriteByte(ch)
	}
	s = result.String()

	// Strip trailing commas before ] and }.
	s = trailingCommaRe.ReplaceAllString(s, "$1")

	return s
}

// regexExtractFindings attempts to extract findings via regex when JSON parsing
// fails entirely. It looks for file, line, severity, and message patterns.
func regexExtractFindings(s string, concernName string) []Finding {
	// Split on object boundaries to find individual findings.
	// We look for blocks that contain at least "file" and "message".
	blocks := regexBlockRe.FindAllString(s, -1)
	if len(blocks) == 0 {
		return nil
	}

	var findings []Finding
	for _, block := range blocks {
		fileMatch := regexFileRe.FindStringSubmatch(block)
		msgMatch := regexMsgRe.FindStringSubmatch(block)
		if fileMatch == nil || msgMatch == nil {
			continue
		}

		f := Finding{
			Concern: concernName,
			File:    capStr(fileMatch[1], maxFieldLen),
			Message: capStr(msgMatch[1], maxFieldLen),
		}

		if lineMatch := regexLineRe.FindStringSubmatch(block); lineMatch != nil {
			f.Line, _ = strconv.Atoi(lineMatch[1])
		}
		if sevMatch := regexSevRe.FindStringSubmatch(block); sevMatch != nil {
			f.Severity = parseSeverity(sevMatch[1])
		}
		if fixMatch := regexFixRe.FindStringSubmatch(block); fixMatch != nil {
			f.Fix = capStr(fixMatch[1], maxFieldLen)
		}
		if reasonMatch := regexReasonRe.FindStringSubmatch(block); reasonMatch != nil {
			f.Reasoning = capStr(reasonMatch[1], maxFieldLen)
		}
		if cweMatch := regexCweRe.FindStringSubmatch(block); cweMatch != nil {
			f.CWE = cweMatch[1]
		}

		findings = append(findings, f)
	}

	return findings
}

// capStr truncates s to maxLen if it exceeds maxLen.
func capStr(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// extractJSON finds and returns the JSON array from potentially wrapped response text.
func extractJSON(s string) string {
	return ExtractJSONArray(s)
}

// ExtractJSONArray finds and returns the first JSON array from potentially
// wrapped LLM response text. Handles markdown code fences and leading/trailing text.
func ExtractJSONArray(s string) string {
	s = stripCodeFences(s)

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

// ExtractJSONObject finds and returns the first JSON object from potentially
// wrapped LLM response text. Handles markdown code fences and leading/trailing text.
func ExtractJSONObject(s string) string {
	s = stripCodeFences(s)

	start := strings.Index(s, "{")
	if start == -1 {
		return ""
	}
	end := strings.LastIndex(s, "}")
	if end == -1 || end <= start {
		return ""
	}
	return s[start : end+1]
}

// stripCodeFences removes ```json ... ``` or ``` ... ``` wrappers from s.
func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)

	if strings.Contains(s, "```json") {
		parts := strings.SplitN(s, "```json", 2)
		if len(parts) == 2 {
			end := strings.Index(parts[1], "```")
			if end != -1 {
				return strings.TrimSpace(parts[1][:end])
			}
			return strings.TrimSpace(parts[1])
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
				return strings.TrimSpace(rest[:end])
			}
			return strings.TrimSpace(rest)
		}
	}
	return s
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
