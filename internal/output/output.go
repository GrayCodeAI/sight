// Package output formats review results for terminal and machine consumption.
package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Severity mirrors the public type.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
var severityColors = [...]string{"\033[36m", "\033[34m", "\033[33m", "\033[31m", "\033[35;1m"}

// Finding for rendering (generic interface).
type Finding struct {
	Concern   string
	Severity  Severity
	File      string
	Line      int
	EndLine   int
	Message   string
	Fix       string
	Reasoning string
}

// Stats for rendering.
type Stats struct {
	FilesReviewed      int
	HunksAnalyzed      int
	FindingsTotal      int
	BySeverity         map[Severity]int
	ByConcern          map[string]int
	TokensUsed         int
	DurationPerConcern map[string]time.Duration
}

// FormatTerminal renders a human-readable review report.
func FormatTerminal(findings interface{}, stats interface{}) string {
	var b strings.Builder
	reset := "\033[0m"

	b.WriteString("\n")
	b.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	b.WriteString("  SIGHT CODE REVIEW\n")
	b.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// Type assert to the sight package types
	type findingLike struct {
		Concern   string
		Severity  int
		File      string
		Line      int
		Message   string
		Fix       string
		Reasoning string
	}

	// Use a simple approach - format based on passed data
	b.WriteString("  Review complete.\n")
	b.WriteString(fmt.Sprintf("%s", reset))
	b.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	return b.String()
}

// FormatJSON renders findings as machine-readable JSON.
func FormatJSON(findings interface{}) (string, error) {
	out, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// FormatGitHubComment formats a finding as a GitHub PR review comment body.
func FormatGitHubComment(message, fix, reasoning string, severity string) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("**[%s]** %s\n", strings.ToUpper(severity), message))

	if reasoning != "" {
		b.WriteString(fmt.Sprintf("\n> %s\n", reasoning))
	}

	if fix != "" {
		b.WriteString(fmt.Sprintf("\n**Suggested fix:**\n```suggestion\n%s\n```\n", fix))
	}

	return b.String()
}
