package sight

import (
	"encoding/json"
	"fmt"
)

// SARIF 2.1.0 output structures for sight findings.

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name,omitempty"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// GenerateSARIF produces a SARIF 2.1.0 JSON report from sight findings.
func GenerateSARIF(findings []Finding, version string) string {
	if version == "" {
		version = "dev"
	}

	// Build rules from unique concern names
	ruleSet := make(map[string]bool)
	var rules []sarifRule
	for _, f := range findings {
		concernID := f.Concern
		if concernID == "" {
			concernID = "unknown"
		}
		if ruleSet[concernID] {
			continue
		}
		ruleSet[concernID] = true
		rule := sarifRule{
			ID:               concernID,
			Name:             concernID,
			ShortDescription: sarifMessage{Text: fmt.Sprintf("%s check", concernID)},
		}
		rules = append(rules, rule)
	}

	var results []sarifResult
	for _, f := range findings {
		concernID := f.Concern
		if concernID == "" {
			concernID = "unknown"
		}
		level := severityToSARIFLevel(f.Severity)

		msg := f.Message
		if f.Fix != "" {
			msg += "\n\nFix: " + f.Fix
		}
		if f.Reasoning != "" {
			msg += "\n\nReasoning: " + f.Reasoning
		}

		result := sarifResult{
			RuleID:  concernID,
			Level:   level,
			Message: sarifMessage{Text: msg},
		}

		if f.File != "" {
			region := &sarifRegion{}
			if f.Line > 0 {
				region.StartLine = f.Line
			}
			if f.EndLine > 0 && f.EndLine != f.Line {
				region.EndLine = f.EndLine
			}
			// Only set region if we have at least a start line
			if region.StartLine == 0 {
				region = nil
			}
			loc := sarifLocation{
				PhysicalLocation: &sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
					Region:           region,
				},
			}
			result.Locations = append(result.Locations, loc)
		}

		results = append(results, result)
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "sight",
					Version:        version,
					InformationURI: "https://github.com/GrayCodeAI/sight",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to generate SARIF: %s"}`, err.Error())
	}
	return string(data)
}

func severityToSARIFLevel(s Severity) string {
	switch {
	case s >= SeverityCritical:
		return "error"
	case s >= SeverityHigh:
		return "error"
	case s >= SeverityMedium:
		return "warning"
	case s >= SeverityLow:
		return "note"
	default:
		return "none"
	}
}
