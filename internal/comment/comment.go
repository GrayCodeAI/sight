// Package comment maps review findings to inline diff positions.
package comment

import (
	"fmt"
	"strings"

	"github.com/GrayCodeAI/sight/internal/diff"
)

// Inline represents a comment positioned on a specific line in a diff.
type Inline struct {
	Path       string
	StartLine  int
	EndLine    int
	Body       string
	Suggestion string
}

// FindingInput is the input format for MapToInline.
type FindingInput struct {
	Concern   string
	Severity  int
	File      string
	Line      int
	EndLine   int
	Message   string
	Fix       string
	Reasoning string
}

// MapToInline converts findings to positioned inline comments.
// Only includes findings that map to valid positions in the diff.
func MapToInline(findings []FindingInput, files []diff.File) []Inline {
	var comments []Inline
	fileMap := buildFileMap(files)

	for _, f := range findings {
		diffFile, exists := fileMap[f.File]
		if !exists {
			continue
		}
		if !isInDiff(diffFile, f.Line) {
			continue
		}
		comments = append(comments, buildComment(f))
	}

	return comments
}

func buildFileMap(files []diff.File) map[string]diff.File {
	m := make(map[string]diff.File)
	for _, f := range files {
		m[f.Path] = f
	}
	return m
}

func isInDiff(file diff.File, line int) bool {
	for _, hunk := range file.Hunks {
		start := hunk.NewStart
		end := hunk.NewStart + hunk.NewCount
		if line >= start && line <= end {
			return true
		}
	}
	return false
}

func buildComment(f FindingInput) Inline {
	var body strings.Builder

	sevLabels := []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	sev := "INFO"
	if f.Severity >= 0 && f.Severity < len(sevLabels) {
		sev = sevLabels[f.Severity]
	}

	body.WriteString(fmt.Sprintf("**[%s]** %s\n", sev, f.Message))

	if f.Reasoning != "" {
		body.WriteString(fmt.Sprintf("\n> %s\n", f.Reasoning))
	}

	c := Inline{
		Path:      f.File,
		StartLine: f.Line,
		EndLine:   f.EndLine,
		Body:      body.String(),
	}

	if f.Fix != "" && looksLikeCode(f.Fix) {
		c.Suggestion = f.Fix
	} else if f.Fix != "" {
		c.Body += fmt.Sprintf("\n**Fix:** %s\n", f.Fix)
	}

	return c
}

func looksLikeCode(s string) bool {
	indicators := []string{":=", "func ", "if ", "for ", "return ", "{", "}", "//", "import", "var ", "const "}
	for _, ind := range indicators {
		if strings.Contains(s, ind) {
			return true
		}
	}
	return false
}
