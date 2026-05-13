package sight

import (
	"encoding/json"
	"strings"
)

// SARIF 2.1.0 output support.
// This enables integration with GitHub Code Scanning, VS Code SARIF Viewer,
// and other tools that consume the OASIS SARIF standard.

// sarifLog is the top-level SARIF 2.1.0 structure.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun represents a single analysis run.
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

// sarifTool describes the analysis tool.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// sarifDriver describes the tool driver (primary component).
type sarifDriver struct {
	Name            string                `json:"name"`
	Version         string                `json:"version"`
	InformationURI  string                `json:"informationUri"`
	Rules           []sarifReportingDesc  `json:"rules,omitempty"`
	SemanticVersion string                `json:"semanticVersion"`
}

// sarifReportingDesc describes a rule in the tool.
type sarifReportingDesc struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription sarifMultiformat    `json:"shortDescription"`
	FullDescription  sarifMultiformat    `json:"fullDescription,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Help             *sarifMultiformat   `json:"help,omitempty"`
	Properties       *sarifRuleProps     `json:"properties,omitempty"`
}

// sarifRuleProps holds additional rule metadata.
type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

// sarifMultiformat is a text/markdown pair.
type sarifMultiformat struct {
	Text string `json:"text"`
}

// sarifResult is a single finding in SARIF format.
type sarifResult struct {
	RuleID    string            `json:"ruleId"`
	RuleIndex int               `json:"ruleIndex"`
	Level     string            `json:"level"`
	Message   sarifMultiformat  `json:"message"`
	Locations []sarifLocation   `json:"locations,omitempty"`
	Fixes     []sarifFix        `json:"fixes,omitempty"`
}

// sarifLocation describes where a result was found.
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLoc `json:"physicalLocation"`
}

// sarifPhysicalLoc has the artifact and region.
type sarifPhysicalLoc struct {
	ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
	Region           *sarifRegion     `json:"region,omitempty"`
}

// sarifArtifactLoc identifies the file.
type sarifArtifactLoc struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// sarifRegion identifies the line(s).
type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

// sarifFix describes a potential fix.
type sarifFix struct {
	Description sarifMultiformat `json:"description"`
}

// ToSARIF converts a slice of Finding values into a SARIF 2.1.0 JSON string.
// The output is compatible with GitHub Code Scanning, VS Code SARIF Viewer,
// and other SARIF-consuming tools.
func ToSARIF(findings []Finding) string {
	// Build rules index from findings
	type ruleKey struct {
		id string
	}
	ruleIndex := make(map[string]int)
	var rules []sarifReportingDesc

	for _, f := range findings {
		ruleID := extractRuleID(f.Message)
		if ruleID == "" {
			ruleID = f.Concern
		}
		if _, exists := ruleIndex[ruleID]; !exists {
			ruleIndex[ruleID] = len(rules)
			desc := sarifReportingDesc{
				ID:               ruleID,
				ShortDescription: sarifMultiformat{Text: extractRuleName(f.Message)},
				FullDescription:  sarifMultiformat{Text: f.Message},
			}
			if f.CWE != "" {
				desc.Properties = &sarifRuleProps{
					Tags: []string{"security", f.CWE},
				}
				desc.HelpURI = "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(f.CWE, "CWE-") + ".html"
			}
			rules = append(rules, desc)
		}
	}

	// Build results
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		ruleID := extractRuleID(f.Message)
		if ruleID == "" {
			ruleID = f.Concern
		}
		idx := ruleIndex[ruleID]

		result := sarifResult{
			RuleID:    ruleID,
			RuleIndex: idx,
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifMultiformat{Text: f.Message},
		}

		if f.File != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLoc{
					ArtifactLocation: sarifArtifactLoc{
						URI:       f.File,
						URIBaseID: "%SRCROOT%",
					},
				},
			}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{
					StartLine: f.Line,
					EndLine:   f.EndLine,
				}
				if f.EndLine == 0 {
					loc.PhysicalLocation.Region.EndLine = f.Line
				}
			}
			result.Locations = []sarifLocation{loc}
		}

		if f.Fix != "" {
			result.Fixes = []sarifFix{
				{Description: sarifMultiformat{Text: f.Fix}},
			}
		}

		results = append(results, result)
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "sight",
						Version:         "1.0.0",
						SemanticVersion: "1.0.0",
						InformationURI:  "https://github.com/GrayCodeAI/sight",
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

// severityToSARIFLevel maps sight Severity to SARIF level strings.
func severityToSARIFLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// extractRuleID pulls the rule ID from a message formatted as "[ID] Name: Description".
func extractRuleID(msg string) string {
	if !strings.HasPrefix(msg, "[") {
		return ""
	}
	end := strings.Index(msg, "]")
	if end < 0 {
		return ""
	}
	return msg[1:end]
}

// extractRuleName pulls the rule name from a message formatted as "[ID] Name: Description".
func extractRuleName(msg string) string {
	end := strings.Index(msg, "]")
	if end < 0 {
		return msg
	}
	rest := strings.TrimSpace(msg[end+1:])
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return rest
	}
	return strings.TrimSpace(rest[:colon])
}
