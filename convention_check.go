package sight

import (
	"fmt"
	"regexp"
	"strings"
)

// ConventionChecker validates diffs against a set of project conventions.
// Integrates with yaad: load conventions from yaad's memory graph and
// check if the diff violates any of them.
type ConventionChecker struct {
	conventions []Convention
}

// Convention is a coding rule to enforce during review.
type Convention struct {
	Name        string
	Description string
	Pattern     string // regex pattern that indicates violation
	FilePattern string // only check files matching this glob
	Severity    Severity
}

// NewConventionChecker creates a checker with the given conventions.
func NewConventionChecker(conventions []Convention) *ConventionChecker {
	return &ConventionChecker{conventions: conventions}
}

// FromStrings creates conventions from simple string rules (e.g., from yaad memories).
func ConventionsFromStrings(rules []string) []Convention {
	var conventions []Convention
	for _, rule := range rules {
		conv := parseConvention(rule)
		if conv.Name != "" {
			conventions = append(conventions, conv)
		}
	}
	return conventions
}

// Check validates a diff against all conventions and returns findings.
func (cc *ConventionChecker) Check(diff string) []Finding {
	if len(cc.conventions) == 0 {
		return nil
	}

	var findings []Finding
	lines := strings.Split(diff, "\n")
	currentFile := ""

	for lineNum, line := range lines {
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			continue
		}
		// Only check added lines
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		addedContent := line[1:]

		for _, conv := range cc.conventions {
			if conv.FilePattern != "" && !matchGlob(currentFile, conv.FilePattern) {
				continue
			}
			if conv.Pattern != "" {
				re, err := regexp.Compile(conv.Pattern)
				if err != nil {
					continue
				}
				if re.MatchString(addedContent) {
					findings = append(findings, Finding{
						File:     currentFile,
						Line:     lineNum,
						Severity: conv.Severity,
						Message:  fmt.Sprintf("Convention violation: %s — %s", conv.Name, conv.Description),
					})
				}
			}
		}
	}

	return findings
}

func parseConvention(rule string) Convention {
	lower := strings.ToLower(rule)
	conv := Convention{Severity: SeverityMedium}

	// "Never use X" → detect X in added lines
	if idx := strings.Index(lower, "never use "); idx >= 0 {
		thing := extractPhrase(lower[idx+10:])
		conv.Name = "no-" + strings.ReplaceAll(thing, " ", "-")
		conv.Description = rule
		conv.Pattern = `(?i)\b` + regexp.QuoteMeta(thing) + `\b`
		return conv
	}

	// "Don't use X" or "Avoid X"
	for _, prefix := range []string{"don't use ", "do not use ", "avoid "} {
		if idx := strings.Index(lower, prefix); idx >= 0 {
			thing := extractPhrase(lower[idx+len(prefix):])
			conv.Name = "avoid-" + strings.ReplaceAll(thing, " ", "-")
			conv.Description = rule
			conv.Pattern = `(?i)\b` + regexp.QuoteMeta(thing) + `\b`
			return conv
		}
	}

	// "Use X not Y" → detect Y
	if strings.Contains(lower, " not ") {
		parts := strings.SplitN(lower, " not ", 2)
		if len(parts) == 2 {
			bad := extractPhrase(parts[1])
			conv.Name = "prefer-alternative"
			conv.Description = rule
			conv.Pattern = `(?i)\b` + regexp.QuoteMeta(bad) + `\b`
			return conv
		}
	}

	return conv
}

func extractPhrase(s string) string {
	s = strings.TrimSpace(s)
	// Take up to first punctuation or end
	end := strings.IndexAny(s, ".,;!?()")
	if end > 0 {
		s = s[:end]
	}
	if len(s) > 40 {
		s = s[:40]
	}
	return strings.TrimSpace(s)
}

func matchGlob(path, pattern string) bool {
	// Simple glob matching: * matches any sequence
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		ext := pattern[1:]
		return strings.HasSuffix(path, ext)
	}
	return strings.Contains(path, pattern)
}

// SecurityConcerns returns security-focused review concerns.
func SecurityConcerns() []string {
	return []string{
		"SQL injection vulnerabilities (unsanitized user input in queries)",
		"XSS vulnerabilities (unescaped output in HTML templates)",
		"Command injection (user input in exec/system calls)",
		"Path traversal (user input in file paths without sanitization)",
		"Hardcoded secrets (API keys, passwords, tokens in source)",
		"Insecure crypto (MD5, SHA1 for security, weak random)",
		"Missing authentication/authorization checks",
		"SSRF vulnerabilities (user-controlled URLs in server requests)",
		"Race conditions (shared state without synchronization)",
		"Resource leaks (unclosed connections, files, channels)",
	}
}
