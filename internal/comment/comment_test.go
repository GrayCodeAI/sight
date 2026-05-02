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
