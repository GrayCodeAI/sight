package sight

import (
	"fmt"
	"regexp"
	"strings"
)

// StaticRule defines a pattern-based static analysis rule that can catch common
// issues without invoking an LLM. Rules are matched against diff content or full
// file content before the LLM review pass, saving tokens on obvious issues.
type StaticRule struct {
	ID          string         // unique identifier, e.g. "SEC-GO-001"
	Name        string         // short human-readable name
	Description string         // detailed explanation
	Language    string         // "go", "python", "typescript", "javascript", "any"
	Pattern     *regexp.Regexp // primary detection pattern
	Antipattern *regexp.Regexp // if this also matches the same line, suppress the finding
	Severity    string         // "critical", "high", "medium", "low"
	Category    string         // "security", "correctness", "performance"
	CWE         string         // e.g., "CWE-89"
	Fix         string         // suggested fix description
}

// StaticAnalyzer runs pattern-based rules against code before the LLM review.
type StaticAnalyzer struct {
	Rules []StaticRule
}

// NewStaticAnalyzer creates a StaticAnalyzer preloaded with the default rule set.
func NewStaticAnalyzer() *StaticAnalyzer {
	return &StaticAnalyzer{
		Rules: defaultRules(),
	}
}

// Analyze runs all matching rules against a unified diff string and returns findings.
// Only added lines (starting with "+") are checked. The language parameter filters
// rules to those matching the language or "any".
func (sa *StaticAnalyzer) Analyze(diff string, language string) []Finding {
	var findings []Finding

	// Parse diff to extract added lines with file and line info
	type diffLine struct {
		file    string
		lineNum int
		text    string
	}

	var lines []diffLine
	var currentFile string
	var lineNum int

	for _, raw := range strings.Split(diff, "\n") {
		if strings.HasPrefix(raw, "+++ b/") {
			currentFile = strings.TrimPrefix(raw, "+++ b/")
			lineNum = 0
			continue
		}
		if strings.HasPrefix(raw, "+++ ") {
			currentFile = strings.TrimPrefix(raw, "+++ ")
			lineNum = 0
			continue
		}
		if strings.HasPrefix(raw, "@@ ") {
			// Parse hunk header for line number: @@ -a,b +c,d @@
			lineNum = parseHunkNewStart(raw) - 1
			continue
		}
		if strings.HasPrefix(raw, "+") && !strings.HasPrefix(raw, "+++") {
			lineNum++
			lines = append(lines, diffLine{
				file:    currentFile,
				lineNum: lineNum,
				text:    raw[1:], // strip leading "+"
			})
		} else if !strings.HasPrefix(raw, "-") {
			lineNum++
		}
	}

	lang := strings.ToLower(language)
	for _, rule := range sa.Rules {
		if rule.Language != "any" && rule.Language != lang {
			continue
		}
		for _, dl := range lines {
			if rule.Pattern.MatchString(dl.text) {
				// Check antipattern — if it matches, this is a false positive
				if rule.Antipattern != nil && rule.Antipattern.MatchString(dl.text) {
					continue
				}
				findings = append(findings, Finding{
					Concern:  "static:" + rule.Category,
					Severity: ParseSeverity(rule.Severity),
					File:     dl.file,
					Line:     dl.lineNum,
					Message:  fmt.Sprintf("[%s] %s: %s", rule.ID, rule.Name, rule.Description),
					Fix:      rule.Fix,
					CWE:      rule.CWE,
				})
			}
		}
	}

	return findings
}

// AnalyzeFile runs all matching rules against a full file's content.
// Each line is checked independently. The language parameter filters rules.
func (sa *StaticAnalyzer) AnalyzeFile(content string, language string) []Finding {
	var findings []Finding
	lang := strings.ToLower(language)

	lines := strings.Split(content, "\n")
	for _, rule := range sa.Rules {
		if rule.Language != "any" && rule.Language != lang {
			continue
		}
		for i, line := range lines {
			if rule.Pattern.MatchString(line) {
				if rule.Antipattern != nil && rule.Antipattern.MatchString(line) {
					continue
				}
				findings = append(findings, Finding{
					Concern:  "static:" + rule.Category,
					Severity: ParseSeverity(rule.Severity),
					File:     "",
					Line:     i + 1,
					Message:  fmt.Sprintf("[%s] %s: %s", rule.ID, rule.Name, rule.Description),
					Fix:      rule.Fix,
					CWE:      rule.CWE,
				})
			}
		}
	}

	return findings
}

// AnalyzeFileWithPath is like AnalyzeFile but sets the File field on findings.
func (sa *StaticAnalyzer) AnalyzeFileWithPath(content string, language string, path string) []Finding {
	findings := sa.AnalyzeFile(content, language)
	for i := range findings {
		findings[i].File = path
	}
	return findings
}

// DetectLanguage guesses the language from a file path extension.
func DetectLanguage(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".go"):
		return "go"
	case strings.HasSuffix(lower, ".py"):
		return "python"
	case strings.HasSuffix(lower, ".ts"):
		return "typescript"
	case strings.HasSuffix(lower, ".tsx"):
		return "typescript"
	case strings.HasSuffix(lower, ".js"):
		return "javascript"
	case strings.HasSuffix(lower, ".jsx"):
		return "javascript"
	case strings.HasSuffix(lower, ".rs"):
		return "rust"
	case strings.HasSuffix(lower, ".java"):
		return "java"
	case strings.HasSuffix(lower, ".c") || strings.HasSuffix(lower, ".h"):
		return "c"
	case strings.HasSuffix(lower, ".cpp") || strings.HasSuffix(lower, ".hpp") || strings.HasSuffix(lower, ".cc") || strings.HasSuffix(lower, ".cxx"):
		return "cpp"
	case strings.HasSuffix(lower, ".rb"):
		return "ruby"
	case strings.HasSuffix(lower, ".sql"):
		return "sql"
	default:
		return "any"
	}
}

// parseHunkNewStart extracts the new-file start line from a hunk header.
// Format: @@ -old,count +new,count @@
func parseHunkNewStart(header string) int {
	// Find "+N" after the first space
	idx := strings.Index(header, "+")
	if idx < 0 {
		return 1
	}
	rest := header[idx+1:]
	var n int
	for _, ch := range rest {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		} else {
			break
		}
	}
	if n == 0 {
		return 1
	}
	return n
}

// defaultRules and the built-in rule set live in static_rules_defaults.go.
