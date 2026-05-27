package sight

import (
	"fmt"
	"strings"
)

// SASTIntegration combines Static Application Security Testing (SAST) with
// LLM-based review. Research shows this hybrid approach reduces false
// positives by 91% compared to SAST alone (SAST-Genius, IEEE S&P 2025).
type SASTIntegration struct {
	checks []SASTCheck
}

// SASTCheck represents a static analysis check.
type SASTCheck struct {
	ID          string
	Name        string
	Description string
	Severity    string // "critical", "high", "medium", "low"
	Languages   []string
	Pattern     string // regex or keyword pattern
	Check       func(source string, filePath string) []SASTFinding
}

// SASTFinding represents a finding from static analysis.
type SASTFinding struct {
	CheckID    string
	Rule       string
	Message    string
	File       string
	Line       int
	Severity   string
	Confidence float64 // 0-1
	Evidence   string  // the suspicious code
}

// NewSASTIntegration creates a SAST integration with built-in security checks.
func NewSASTIntegration() *SASTIntegration {
	s := &SASTIntegration{}
	s.registerBuiltinChecks()
	return s
}

// Analyze runs all SAST checks on the given source code.
func (s *SASTIntegration) Analyze(source string, filePath string) []SASTFinding {
	var findings []SASTFinding

	for _, check := range s.checks {
		if !check.AppliesTo(filePath) {
			continue
		}

		results := check.Check(source, filePath)
		findings = append(findings, results...)
	}

	return findings
}

// BuildReviewPrompt builds an enhanced review prompt that includes SAST findings.
// This is the key innovation from SAST-Genius: SAST findings guide the LLM's
// attention to suspicious code, reducing false positives by 91%.
func (s *SASTIntegration) BuildReviewPrompt(sastFindings []SASTFinding, diff string) string {
	var prompt strings.Builder

	prompt.WriteString("## SAST Pre-Analysis Results\n\n")
	prompt.WriteString("The following static analysis findings were detected. ")
	prompt.WriteString("Use these to guide your review, but verify each finding. ")
	prompt.WriteString("Many SAST findings are false positives - use your judgment.\n\n")

	if len(sastFindings) == 0 {
		prompt.WriteString("No SAST findings detected. Focus on code quality and logic.\n\n")
	} else {
		prompt.WriteString(fmt.Sprintf("Found %d potential issues:\n\n", len(sastFindings)))
		for _, f := range sastFindings {
			prompt.WriteString(fmt.Sprintf("- **%s** [%s] in %s:%d\n  %s\n  Evidence: `%s`\n\n",
				f.Rule, f.Severity, f.File, f.Line, f.Message, truncate(f.Evidence, 100)))
		}
	}

	prompt.WriteString("## Code Diff\n\n")
	prompt.WriteString(diff)

	return prompt.String()
}

// registerBuiltinChecks adds common security and quality checks.
func (s *SASTIntegration) registerBuiltinChecks() {
	// SQL Injection
	s.checks = append(s.checks, SASTCheck{
		ID:          "sql-injection",
		Name:        "SQL Injection",
		Description: "Potential SQL injection via string concatenation",
		Severity:    "critical",
		Languages:   []string{"go", "python", "java", "php", "ruby"},
		Check: func(source, filePath string) []SASTFinding {
			var findings []SASTFinding
			lines := strings.Split(source, "\n")
			for i, line := range lines {
				if strings.Contains(line, "fmt.Sprintf") && strings.Contains(line, "SELECT") {
					findings = append(findings, SASTFinding{
						CheckID:    "sql-injection",
						Rule:       "SQL Injection",
						Message:    "Potential SQL injection via fmt.Sprintf",
						File:       filePath,
						Line:       i + 1,
						Severity:   "critical",
						Confidence: 0.7,
						Evidence:   strings.TrimSpace(line),
					})
				}
				if strings.Contains(line, "Query(") && strings.Contains(line, "+") {
					findings = append(findings, SASTFinding{
						CheckID:    "sql-injection",
						Rule:       "SQL Injection",
						Message:    "Potential SQL injection via string concatenation",
						File:       filePath,
						Line:       i + 1,
						Severity:   "critical",
						Confidence: 0.6,
						Evidence:   strings.TrimSpace(line),
					})
				}
			}
			return findings
		},
	})

	// Hardcoded Secrets
	s.checks = append(s.checks, SASTCheck{
		ID:          "hardcoded-secret",
		Name:        "Hardcoded Secret",
		Description: "Potential hardcoded API key, password, or token",
		Severity:    "high",
		Languages:   []string{},
		Check: func(source, filePath string) []SASTFinding {
			var findings []SASTFinding
			lines := strings.Split(source, "\n")
			secretPatterns := []string{"password", "secret", "api_key", "apikey", "token", "private_key"}
			for i, line := range lines {
				lower := strings.ToLower(line)
				for _, pattern := range secretPatterns {
					if strings.Contains(lower, pattern) && strings.Contains(line, "=") && strings.Contains(line, "\"") {
						// Check if it looks like an assignment with a real value
						if !strings.Contains(lower, "test") && !strings.Contains(lower, "example") && !strings.Contains(lower, "xxx") {
							findings = append(findings, SASTFinding{
								CheckID:    "hardcoded-secret",
								Rule:       "Hardcoded Secret",
								Message:    fmt.Sprintf("Potential hardcoded %s", pattern),
								File:       filePath,
								Line:       i + 1,
								Severity:   "high",
								Confidence: 0.5,
								Evidence:   strings.TrimSpace(line),
							})
						}
					}
				}
			}
			return findings
		},
	})

	// Command Injection
	s.checks = append(s.checks, SASTCheck{
		ID:          "command-injection",
		Name:        "Command Injection",
		Description: "Potential command injection via unsanitized input",
		Severity:    "critical",
		Languages:   []string{"go", "python", "ruby", "php"},
		Check: func(source, filePath string) []SASTFinding {
			var findings []SASTFinding
			lines := strings.Split(source, "\n")
			for i, line := range lines {
				if strings.Contains(line, "exec.Command") && strings.Contains(line, "+") {
					findings = append(findings, SASTFinding{
						CheckID:    "command-injection",
						Rule:       "Command Injection",
						Message:    "Potential command injection via string concatenation",
						File:       filePath,
						Line:       i + 1,
						Severity:   "critical",
						Confidence: 0.6,
						Evidence:   strings.TrimSpace(line),
					})
				}
			}
			return findings
		},
	})

	// Path Traversal
	s.checks = append(s.checks, SASTCheck{
		ID:          "path-traversal",
		Name:        "Path Traversal",
		Description: "Potential path traversal vulnerability",
		Severity:    "high",
		Languages:   []string{},
		Check: func(source, filePath string) []SASTFinding {
			var findings []SASTFinding
			lines := strings.Split(source, "\n")
			for i, line := range lines {
				if strings.Contains(line, "../") || strings.Contains(line, "..\\\\") {
					if strings.Contains(line, "Open") || strings.Contains(line, "Read") || strings.Contains(line, "Write") {
						findings = append(findings, SASTFinding{
							CheckID:    "path-traversal",
							Rule:       "Path Traversal",
							Message:    "Potential path traversal with ../ in file operation",
							File:       filePath,
							Line:       i + 1,
							Severity:   "high",
							Confidence: 0.5,
							Evidence:   strings.TrimSpace(line),
						})
					}
				}
			}
			return findings
		},
	})

	// Error Handling
	s.checks = append(s.checks, SASTCheck{
		ID:          "unchecked-error",
		Name:        "Unchecked Error",
		Description: "Error return value not checked",
		Severity:    "medium",
		Languages:   []string{"go"},
		Check: func(source, filePath string) []SASTFinding {
			var findings []SASTFinding
			lines := strings.Split(source, "\n")
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				// Go-specific: function call on its own line without assignment
				if strings.Contains(trimmed, "(") && strings.Contains(trimmed, ")") &&
					!strings.Contains(trimmed, ":=") && !strings.Contains(trimmed, "=") &&
					!strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "defer") &&
					!strings.HasPrefix(trimmed, "go ") && !strings.HasPrefix(trimmed, "if ") &&
					!strings.HasPrefix(trimmed, "for ") && !strings.HasPrefix(trimmed, "return ") &&
					!strings.HasPrefix(trimmed, "func ") && len(trimmed) > 10 {
					// This is a heuristic - many false positives possible
					findings = append(findings, SASTFinding{
						CheckID:    "unchecked-error",
						Rule:       "Unchecked Error",
						Message:    "Possible unchecked error return",
						File:       filePath,
						Line:       i + 1,
						Severity:   "medium",
						Confidence: 0.3,
						Evidence:   trimmed,
					})
				}
			}
			return findings
		},
	})
}

// AppliesTo checks if the SAST check applies to the given file.
func (c *SASTCheck) AppliesTo(filePath string) bool {
	if len(c.Languages) == 0 {
		return true // applies to all languages
	}

	ext := getFileExtension(filePath)
	for _, lang := range c.Languages {
		if ext == lang || ext == "."+lang {
			return true
		}
	}
	return false
}

func getFileExtension(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i:]
		}
		if path[i] == '/' || path[i] == '\\' {
			return ""
		}
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Compile-time check
var _ = truncate
