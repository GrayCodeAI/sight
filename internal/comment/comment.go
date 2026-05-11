// Package comment maps review findings to inline diff positions.
package comment

import (
	"fmt"
	"strings"

	"github.com/GrayCodeAI/sight/internal/diff"
)

// FilterMode controls which lines are eligible for comment placement.
// It determines how strictly findings must align with the diff to be
// included in the output.
type FilterMode int

const (
	// FilterAdded reports only on added lines (lines starting with +).
	// This is the most conservative mode and the default behavior.
	FilterAdded FilterMode = iota

	// FilterDiffContext reports on any line within the diff context,
	// including context lines (unchanged) surrounding the changes.
	FilterDiffContext

	// FilterFile reports on any line in a changed file, even lines
	// outside the diff hunks. Useful for whole-file analysis.
	FilterFile

	// FilterNone reports everything regardless of diff — no filtering
	// is applied. All findings are included as comments.
	FilterNone
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
// Uses FilterAdded mode (only added lines) for backward compatibility.
func MapToInline(findings []FindingInput, files []diff.File) []Inline {
	return MapToInlineFiltered(findings, files, FilterAdded)
}

// MapToInlineFiltered converts findings to positioned inline comments using
// the specified FilterMode to control which findings are included.
func MapToInlineFiltered(findings []FindingInput, files []diff.File, mode FilterMode) []Inline {
	var comments []Inline
	fileMap := buildFileMap(files)

	// Pre-build line sets for O(1) lookup when using context or added modes
	lineSetMap := make(map[string]diffLineSet)
	if mode == FilterDiffContext || mode == FilterAdded {
		for _, f := range files {
			lineSetMap[f.Path] = buildDiffLineSet(f)
		}
	}

	for _, f := range findings {
		_, exists := fileMap[f.File]

		switch mode {
		case FilterNone:
			// Include all findings regardless of diff position
			comments = append(comments, buildComment(f))

		case FilterFile:
			// Include if the file is in the diff, any line
			if exists {
				comments = append(comments, buildComment(f))
			}

		case FilterDiffContext:
			// Include if the line falls within any hunk's full range
			// (added, removed, or context lines) — O(1) lookup
			if exists {
				if ls, ok := lineSetMap[f.File]; ok && ls.contextLines[f.Line] {
					comments = append(comments, buildComment(f))
				}
			}

		default: // FilterAdded
			// Include only if the line is within the diff's new-side range — O(1) lookup
			if exists {
				if ls, ok := lineSetMap[f.File]; ok && ls.newRangeLines[f.Line] {
					comments = append(comments, buildComment(f))
				}
			}
		}
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

// diffLineSet holds precomputed line number sets for O(1) lookup.
type diffLineSet struct {
	newRangeLines map[int]bool // lines within new-side hunk ranges
	contextLines  map[int]bool // lines within context ranges or individual line refs
}

func buildDiffLineSet(file diff.File) diffLineSet {
	s := diffLineSet{
		newRangeLines: make(map[int]bool),
		contextLines:  make(map[int]bool),
	}
	for _, hunk := range file.Hunks {
		start := hunk.NewStart
		end := hunk.NewStart + hunk.NewCount
		for i := start; i <= end; i++ {
			s.newRangeLines[i] = true
			s.contextLines[i] = true
		}
		for _, l := range hunk.Lines {
			if l.NewNum > 0 {
				s.contextLines[l.NewNum] = true
			}
			if l.OldNum > 0 {
				s.contextLines[l.OldNum] = true
			}
		}
	}
	return s
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
