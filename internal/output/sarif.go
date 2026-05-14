package output

import (
	"encoding/json"
	"fmt"
)

// SARIF types per SARIF 2.1.0 specification.

type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription SARIFMultiformat `json:"shortDescription"`
	DefaultConfig    *SARIFRuleConfig `json:"defaultConfiguration,omitempty"`
}

type SARIFRuleConfig struct {
	Level string `json:"level"`
}

type SARIFMultiformat struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID    string               `json:"ruleId"`
	Level     string               `json:"level"`
	Message   SARIFMultiformat     `json:"message"`
	Locations []SARIFLocation      `json:"locations,omitempty"`
	Fixes     []SARIFFix           `json:"fixes,omitempty"`
	Taxa      []SARIFTaxaReference `json:"taxa,omitempty"`
}

// SARIFTaxaReference references an external taxonomy entry (e.g., CWE).
type SARIFTaxaReference struct {
	ID            string           `json:"id"`
	ToolComponent SARIFMultiformat `json:"toolComponent"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type SARIFFix struct {
	Description SARIFMultiformat      `json:"description"`
	Changes     []SARIFArtifactChange `json:"artifactChanges"`
}

type SARIFArtifactChange struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Replacements     []SARIFReplacement    `json:"replacements"`
}

type SARIFReplacement struct {
	DeletedRegion   SARIFRegion           `json:"deletedRegion"`
	InsertedContent *SARIFInsertedContent `json:"insertedContent,omitempty"`
}

type SARIFInsertedContent struct {
	Text string `json:"text"`
}

// FormatSARIF produces SARIF 2.1.0 JSON from review findings.
func FormatSARIF(findings []Finding) (string, error) {
	rules := buildSARIFRules(findings)
	results := make([]SARIFResult, 0, len(findings))

	for _, f := range findings {
		result := SARIFResult{
			RuleID:  fmt.Sprintf("sight/%s", f.Concern),
			Level:   sarifLevel(f.Severity),
			Message: SARIFMultiformat{Text: f.Message},
		}

		if f.File != "" {
			loc := SARIFLocation{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: f.File},
				},
			}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &SARIFRegion{
					StartLine: f.Line,
					EndLine:   f.EndLine,
				}
				if loc.PhysicalLocation.Region.EndLine == 0 {
					loc.PhysicalLocation.Region.EndLine = f.Line
				}
			}
			result.Locations = append(result.Locations, loc)
		}

		if f.Fix != "" {
			result.Fixes = append(result.Fixes, SARIFFix{
				Description: SARIFMultiformat{Text: f.Fix},
			})
		}

		if f.CWE != "" {
			result.Taxa = append(result.Taxa, SARIFTaxaReference{
				ID:            f.CWE,
				ToolComponent: SARIFMultiformat{Text: "CWE"},
			})
		}

		results = append(results, result)
	}

	log := SARIFLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "sight",
						Version:        "0.2.0",
						InformationURI: "https://github.com/GrayCodeAI/sight",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	out, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func buildSARIFRules(findings []Finding) []SARIFRule {
	seen := make(map[string]bool)
	var rules []SARIFRule

	for _, f := range findings {
		id := fmt.Sprintf("sight/%s", f.Concern)
		if seen[id] {
			continue
		}
		seen[id] = true
		rules = append(rules, SARIFRule{
			ID:               id,
			Name:             f.Concern,
			ShortDescription: SARIFMultiformat{Text: f.Concern + " analysis"},
			DefaultConfig:    &SARIFRuleConfig{Level: sarifLevel(f.Severity)},
		})
	}
	return rules
}

func sarifLevel(severity int) string {
	switch {
	case severity >= 3: // high, critical
		return "error"
	case severity == 2: // medium
		return "warning"
	default: // low, info
		return "note"
	}
}
