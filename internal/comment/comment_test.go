package comment

import (
	"strings"
	"testing"

	"github.com/GrayCodeAI/sight/internal/diff"
)

func TestMapToInline_Basic(t *testing.T) {
	files := []diff.File{
		{
			Path: "main.go",
			Hunks: []diff.Hunk{
				{NewStart: 10, NewCount: 5},
			},
		},
	}

	findings := []FindingInput{
		{File: "main.go", Line: 12, Severity: 3, Message: "Bug found", Fix: "if err != nil { return err }"},
	}

	comments := MapToInline(findings, files)
	if len(comments) != 1 {
		t.Fatalf("expected 1 comment, got %d", len(comments))
	}
	if comments[0].Path != "main.go" {
		t.Errorf("expected main.go, got %s", comments[0].Path)
	}
	if comments[0].StartLine != 12 {
		t.Errorf("expected line 12, got %d", comments[0].StartLine)
	}
	if !strings.Contains(comments[0].Body, "HIGH") {
		t.Error("expected HIGH severity in body")
	}
	if comments[0].Suggestion == "" {
		t.Error("expected suggestion for code-like fix")
	}
}

func TestMapToInline_OutsideDiff(t *testing.T) {
	files := []diff.File{
		{
			Path: "main.go",
			Hunks: []diff.Hunk{
				{NewStart: 10, NewCount: 5},
			},
		},
	}

	findings := []FindingInput{
		{File: "main.go", Line: 100, Severity: 2, Message: "Far away"},
	}

	comments := MapToInline(findings, files)
	if len(comments) != 0 {
		t.Errorf("expected 0 comments for out-of-range line, got %d", len(comments))
	}
}

func TestMapToInline_UnknownFile(t *testing.T) {
	files := []diff.File{
		{Path: "main.go", Hunks: []diff.Hunk{{NewStart: 1, NewCount: 10}}},
	}

	findings := []FindingInput{
		{File: "other.go", Line: 5, Severity: 1, Message: "wrong file"},
	}

	comments := MapToInline(findings, files)
	if len(comments) != 0 {
		t.Errorf("expected 0 comments for unknown file, got %d", len(comments))
	}
}

func TestMapToInline_NonCodeFix(t *testing.T) {
	files := []diff.File{
		{Path: "x.go", Hunks: []diff.Hunk{{NewStart: 1, NewCount: 20}}},
	}

	findings := []FindingInput{
		{File: "x.go", Line: 5, Severity: 2, Message: "Use parameterized query", Fix: "Use db.Query with $1 placeholder"},
	}

	comments := MapToInline(findings, files)
	if len(comments) != 1 {
		t.Fatalf("expected 1 comment, got %d", len(comments))
	}
	if comments[0].Suggestion != "" {
		t.Error("non-code fix should not generate suggestion")
	}
	if !strings.Contains(comments[0].Body, "Fix:") {
		t.Error("expected Fix: in body for non-code fix")
	}
}

func TestBuildComment_AllSeverities(t *testing.T) {
	for sev := 0; sev <= 4; sev++ {
		c := buildComment(FindingInput{
			File: "x.go", Line: 1, Severity: sev, Message: "test",
		})
		if c.Body == "" {
			t.Errorf("empty body for severity %d", sev)
		}
	}
}

func TestMapToInlineFiltered_FilterAdded(t *testing.T) {
	files := []diff.File{
		{
			Path: "main.go",
			Hunks: []diff.Hunk{
				{NewStart: 10, NewCount: 5},
			},
		},
	}

	findings := []FindingInput{
		{File: "main.go", Line: 12, Severity: 3, Message: "In range"},
		{File: "main.go", Line: 100, Severity: 2, Message: "Out of range"},
	}

	comments := MapToInlineFiltered(findings, files, FilterAdded)
	if len(comments) != 1 {
		t.Errorf("FilterAdded: expected 1 comment, got %d", len(comments))
	}
}

func TestMapToInlineFiltered_FilterFile(t *testing.T) {
	files := []diff.File{
		{
			Path: "main.go",
			Hunks: []diff.Hunk{
				{NewStart: 10, NewCount: 5},
			},
		},
	}

	findings := []FindingInput{
		{File: "main.go", Line: 100, Severity: 2, Message: "Far away but same file"},
		{File: "other.go", Line: 5, Severity: 2, Message: "Different file"},
	}

	comments := MapToInlineFiltered(findings, files, FilterFile)
	if len(comments) != 1 {
		t.Errorf("FilterFile: expected 1 comment (same file), got %d", len(comments))
	}
	if len(comments) > 0 && comments[0].Path != "main.go" {
		t.Errorf("expected main.go, got %s", comments[0].Path)
	}
}

func TestMapToInlineFiltered_FilterNone(t *testing.T) {
	files := []diff.File{
		{
			Path: "main.go",
			Hunks: []diff.Hunk{
				{NewStart: 10, NewCount: 5},
			},
		},
	}

	findings := []FindingInput{
		{File: "main.go", Line: 100, Severity: 2, Message: "Far away"},
		{File: "other.go", Line: 5, Severity: 2, Message: "Different file"},
	}

	comments := MapToInlineFiltered(findings, files, FilterNone)
	if len(comments) != 2 {
		t.Errorf("FilterNone: expected 2 comments (all findings), got %d", len(comments))
	}
}

func TestMapToInlineFiltered_FilterDiffContext(t *testing.T) {
	files := []diff.File{
		{
			Path: "main.go",
			Hunks: []diff.Hunk{
				{
					NewStart: 10, NewCount: 5,
					Lines: []diff.Line{
						{Type: diff.LineContext, Content: "ctx1", NewNum: 10, OldNum: 10},
						{Type: diff.LineAdded, Content: "new", NewNum: 11},
						{Type: diff.LineContext, Content: "ctx2", NewNum: 12, OldNum: 11},
					},
				},
			},
		},
	}

	findings := []FindingInput{
		{File: "main.go", Line: 10, Severity: 1, Message: "On context line"},
		{File: "main.go", Line: 11, Severity: 2, Message: "On added line"},
		{File: "main.go", Line: 100, Severity: 2, Message: "Outside diff context"},
	}

	comments := MapToInlineFiltered(findings, files, FilterDiffContext)
	if len(comments) != 2 {
		t.Errorf("FilterDiffContext: expected 2 comments, got %d", len(comments))
	}
}

func TestMapToInline_BackwardCompatible(t *testing.T) {
	// Ensure MapToInline still works the same as MapToInlineFiltered with FilterAdded
	files := []diff.File{
		{
			Path: "main.go",
			Hunks: []diff.Hunk{
				{NewStart: 10, NewCount: 5},
			},
		},
	}

	findings := []FindingInput{
		{File: "main.go", Line: 12, Severity: 3, Message: "Bug found"},
		{File: "main.go", Line: 100, Severity: 2, Message: "Out of range"},
	}

	old := MapToInline(findings, files)
	new := MapToInlineFiltered(findings, files, FilterAdded)
	if len(old) != len(new) {
		t.Errorf("backward compatibility broken: MapToInline got %d, MapToInlineFiltered got %d", len(old), len(new))
	}
}
