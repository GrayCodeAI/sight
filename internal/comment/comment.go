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

// Finding mirrors the public Finding for internal use (avoids import cycle).
type Finding struct {
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
// It only includes findings that map to valid positions in the diff.
func MapToInline(findings interface{}, files []diff.File) []Inline {
	// Accept []Finding from the sight package via interface
	fs, ok := findings.([]struct {
		Concern   string
		Severity  int
		File      string
		Line      int
		EndLine   int
		Message   string
		Fix       string
		Reasoning string
	})

	if !ok {
		return mapGeneric(findings, files)
	}

	var comments []Inline
	fileMap := buildFileMap(files)

	for _, f := range fs {
		diffFile, exists := fileMap[f.File]
		if !exists {
			continue
		}
		if !isInDiff(diffFile, f.Line) {
			continue
		}
		comments = append(comments, buildComment(f.File, f.Line, f.EndLine, f.Message, f.Fix, f.Reasoning, f.Severity))
	}

	return comments
}

func mapGeneric(findings interface{}, files []diff.File) []Inline {
	return nil
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

func buildComment(path string, line, endLine int, message, fix, reasoning string, severity int) Inline {
	var body strings.Builder

	sevLabel := []string{"info", "low", "medium", "high", "critical"}
	sev := "info"
	if severity < len(sevLabel) {
		sev = sevLabel[severity]
	}

	body.WriteString(fmt.Sprintf("**[%s]** %s\n", strings.ToUpper(sev), message))

	if reasoning != "" {
		body.WriteString(fmt.Sprintf("\n> %s\n", reasoning))
	}

	comment := Inline{
		Path:      path,
		StartLine: line,
		EndLine:   endLine,
		Body:      body.String(),
	}

	if fix != "" && looksLikeCode(fix) {
		comment.Suggestion = fix
	} else if fix != "" {
		comment.Body += fmt.Sprintf("\n**Fix:** %s\n", fix)
	}

	return comment
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
