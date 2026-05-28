// Package output formats review results for terminal and machine consumption.
package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Finding for rendering.
type Finding struct {
	Concern   string
	Severity  int
	File      string
	Line      int
	EndLine   int
	Message   string
	Fix       string
	Reasoning string
	CWE       string
}

// Stats for rendering.
type Stats struct {
	FilesReviewed      int
	HunksAnalyzed      int
	FindingsTotal      int
	BySeverity         map[int]int
	ByConcern          map[string]int
	TokensUsed         int
	DurationPerConcern map[string]time.Duration
}

var (
	severityNames  = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	severityColors = [...]string{"\033[36m", "\033[34m", "\033[33m", "\033[31m", "\033[35;1m"}
)

const (
	reset = "\033[0m"
	bold  = "\033[1m"
	dim   = "\033[2m"
)

// FormatTerminal renders a human-readable review report with ANSI colors.
func FormatTerminal(findings []Finding, stats Stats) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(bold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + reset + "\n")
	b.WriteString(bold + "  SIGHT CODE REVIEW" + reset + "\n")
	b.WriteString(fmt.Sprintf("  %d files, %d hunks analyzed", stats.FilesReviewed, stats.HunksAnalyzed))
	if stats.TokensUsed > 0 {
		b.WriteString(fmt.Sprintf(" (%d tokens used)", stats.TokensUsed))
	}
	b.WriteString("\n")
	b.WriteString(bold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + reset + "\n\n")

	if len(findings) == 0 {
		b.WriteString("  \033[32m✓ No issues found.\033[0m\n\n")
		return b.String()
	}

	grouped := map[int][]Finding{}
	order := []int{4, 3, 2, 1, 0} // critical, high, medium, low, info
	for _, f := range findings {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}

	for _, sev := range order {
		items := grouped[sev]
		if len(items) == 0 {
			continue
		}
		color := "\033[36m"
		if sev < len(severityColors) {
			color = severityColors[sev]
		}
		name := "UNKNOWN"
		if sev < len(severityNames) {
			name = severityNames[sev]
		}

		b.WriteString(fmt.Sprintf("  %s%s%s (%d)\n\n", color+bold, name, reset, len(items)))

		for _, f := range items {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
				if f.EndLine > 0 && f.EndLine != f.Line {
					loc = fmt.Sprintf("%s:%d-%d", f.File, f.Line, f.EndLine)
				}
			}

			b.WriteString(fmt.Sprintf("    %s%s%s %s\n", color, "●", reset, f.Message))
			b.WriteString(fmt.Sprintf("      %s%s%s", dim, loc, reset))
			if f.Concern != "" {
				b.WriteString(fmt.Sprintf("  %s[%s]%s", dim, f.Concern, reset))
			}
			b.WriteString("\n")

			if f.Reasoning != "" {
				b.WriteString(fmt.Sprintf("      %s▸ %s%s\n", dim, f.Reasoning, reset))
			}
			if f.Fix != "" {
				b.WriteString(fmt.Sprintf("      %s⚡ Fix: %s%s\n", "\033[32m", f.Fix, reset))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString(bold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + reset + "\n")
	b.WriteString(fmt.Sprintf("  SUMMARY: %d findings", len(findings)))

	parts := []string{}
	for _, sev := range order {
		count := stats.BySeverity[sev]
		if count > 0 {
			name := severityNames[sev]
			parts = append(parts, fmt.Sprintf("%d %s", count, name))
		}
	}
	if len(parts) > 0 {
		b.WriteString(" (" + strings.Join(parts, ", ") + ")")
	}
	b.WriteString("\n")

	if len(stats.DurationPerConcern) > 0 {
		dParts := []string{}
		for name, d := range stats.DurationPerConcern {
			dParts = append(dParts, fmt.Sprintf("%s:%s", name, d.Round(time.Millisecond)))
		}
		b.WriteString(fmt.Sprintf("  %sTiming: %s%s\n", dim, strings.Join(dParts, " | "), reset))
	}
	b.WriteString(bold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + reset + "\n")

	return b.String()
}

// FormatJSON renders findings as machine-readable JSON.
func FormatJSON(findings []Finding) (string, error) {
	out, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// SARIF 2.1.0 output types (package-level so they can reference each other).

type outputSarifLog struct {
	Version string              `json:"version"`
	Schema  string              `json:"$schema"`
	Runs    []outputSarifRun    `json:"runs"`
}

type outputSarifRun struct {
	Tool    outputSarifTool     `json:"tool"`
	Results []outputSarifResult `json:"results"`
}

type outputSarifTool struct {
	Driver outputSarifDriver `json:"driver"`
}

type outputSarifDriver struct {
	Name           string              `json:"name"`
	Version        string              `json:"version"`
	InformationURI string              `json:"informationUri,omitempty"`
	Rules          []outputSarifRule   `json:"rules,omitempty"`
}

type outputSarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription outputSarifMessage `json:"shortDescription"`
}

type outputSarifResult struct {
	RuleID    string               `json:"ruleId"`
	Level     string               `json:"level"`
	Message   outputSarifMessage    `json:"message"`
	Locations []outputSarifLocation `json:"locations,omitempty"`
}

type outputSarifMessage struct {
	Text string `json:"text"`
}

type outputSarifLocation struct {
	PhysicalLocation *outputSarifPhysicalLocation `json:"physicalLocation,omitempty"`
}

type outputSarifPhysicalLocation struct {
	ArtifactLocation outputSarifArtifactLocation `json:"artifactLocation"`
	Region           *outputSarifRegion          `json:"region,omitempty"`
}

type outputSarifArtifactLocation struct {
	URI string `json:"uri"`
}

type outputSarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
}

// FormatSARIF produces a SARIF 2.1.0 JSON report from findings.
func FormatSARIF(findings []Finding, version string) string {
	if version == "" {
		version = "dev"
	}

	severityToLevel := func(s int) string {
		switch {
		case s >= 4: // Critical
			return "error"
		case s >= 3: // High
			return "error"
		case s >= 2: // Medium
			return "warning"
		case s >= 1: // Low
			return "note"
		default: // Info
			return "none"
		}
	}

	ruleSet := make(map[string]bool)
	var rules []outputSarifRule
	for _, f := range findings {
		id := f.Concern
		if id == "" {
			id = "unknown"
		}
		if ruleSet[id] {
			continue
		}
		ruleSet[id] = true
		rules = append(rules, outputSarifRule{
			ID:               id,
			Name:             id,
			ShortDescription: outputSarifMessage{Text: id + " check"},
		})
	}

	var results []outputSarifResult
	for _, f := range findings {
		id := f.Concern
		if id == "" {
			id = "unknown"
		}
		msg := f.Message
		if f.Fix != "" {
			msg += "\n\nFix: " + f.Fix
		}
		r := outputSarifResult{
			RuleID:  id,
			Level:   severityToLevel(f.Severity),
			Message: outputSarifMessage{Text: msg},
		}
		if f.File != "" {
			region := &outputSarifRegion{}
			if f.Line > 0 {
				region.StartLine = f.Line
			}
			if f.EndLine > 0 && f.EndLine != f.Line {
				region.EndLine = f.EndLine
			}
			if region.StartLine == 0 {
				region = nil
			}
			r.Locations = append(r.Locations, outputSarifLocation{
				PhysicalLocation: &outputSarifPhysicalLocation{
					ArtifactLocation: outputSarifArtifactLocation{URI: f.File},
					Region:           region,
				},
			})
		}
		results = append(results, r)
	}

	log := outputSarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []outputSarifRun{{
			Tool: outputSarifTool{Driver: outputSarifDriver{
				Name:           "sight",
				Version:        version,
				InformationURI: "https://github.com/GrayCodeAI/sight",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return `{"error": "failed to generate SARIF"}`
	}
	return string(data)
}

// FormatGitHubReview formats all findings as a single GitHub PR review body.
func FormatGitHubReview(findings []Finding) string {
	if len(findings) == 0 {
		return "✅ No issues found."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("## Sight Review — %d findings\n\n", len(findings)))

	for _, f := range findings {
		sev := "INFO"
		if f.Severity < len(severityNames) {
			sev = severityNames[f.Severity]
		}
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		b.WriteString(fmt.Sprintf("- **[%s]** `%s` — %s\n", sev, loc, f.Message))
		if f.Fix != "" {
			b.WriteString(fmt.Sprintf("  - Fix: %s\n", f.Fix))
		}
	}

	return b.String()
}
