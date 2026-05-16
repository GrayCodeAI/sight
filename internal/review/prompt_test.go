package review

import (
	"strings"
	"testing"

	"github.com/GrayCodeAI/sight/internal/diff"
)

func TestBuildPrompt_Basic(t *testing.T) {
	files := []diff.File{
		{
			Path: "handler.go",
			Hunks: []diff.Hunk{
				{
					OldStart: 10, OldCount: 3,
					NewStart: 10, NewCount: 5,
					Header: "func handleRequest",
					Lines: []diff.Line{
						{Type: diff.LineContext, Content: "existing code"},
						{Type: diff.LineAdded, Content: "new code"},
						{Type: diff.LineRemoved, Content: "old code"},
					},
				},
			},
		},
	}

	concern := Concern{Name: "security", Prompt: "Check for security issues"}
	prompt := BuildPrompt(concern, files, 10)

	if !strings.Contains(prompt, "handler.go") {
		t.Error("expected file path in prompt")
	}
	if !strings.Contains(prompt, "+new code") {
		t.Error("expected added line with + prefix")
	}
	if !strings.Contains(prompt, "-old code") {
		t.Error("expected removed line with - prefix")
	}
	if !strings.Contains(prompt, " existing code") {
		t.Error("expected context line with space prefix")
	}
	if !strings.Contains(prompt, "security") {
		t.Error("expected concern name in prompt")
	}
}

func TestBuildPrompt_NewFile(t *testing.T) {
	files := []diff.File{
		{
			Path:  "new.go",
			Added: true,
			Hunks: []diff.Hunk{
				{NewStart: 1, NewCount: 3, Lines: []diff.Line{
					{Type: diff.LineAdded, Content: "package main"},
					{Type: diff.LineAdded, Content: ""},
					{Type: diff.LineAdded, Content: "func main() {}"},
				}},
			},
		},
	}

	concern := Concern{Name: "bugs"}
	prompt := BuildPrompt(concern, files, 5)

	if !strings.Contains(prompt, "(new file)") {
		t.Error("expected (new file) annotation")
	}
}

func TestBuildPrompt_RenamedFile(t *testing.T) {
	files := []diff.File{
		{
			Path:    "new_name.go",
			OldPath: "old_name.go",
			Renamed: true,
			Hunks:   []diff.Hunk{{NewStart: 1, NewCount: 1, Lines: []diff.Line{{Type: diff.LineContext, Content: "package main"}}}},
		},
	}

	concern := Concern{Name: "style"}
	prompt := BuildPrompt(concern, files, 5)

	if !strings.Contains(prompt, "renamed from old_name.go") {
		t.Error("expected rename annotation")
	}
}

func TestBuildPrompt_DeletedFileSkipped(t *testing.T) {
	files := []diff.File{
		{
			Path:    "deleted.go",
			Deleted: true,
			Hunks:   []diff.Hunk{{Lines: []diff.Line{{Type: diff.LineRemoved, Content: "old"}}}},
		},
		{
			Path:  "kept.go",
			Hunks: []diff.Hunk{{NewStart: 1, NewCount: 1, Lines: []diff.Line{{Type: diff.LineAdded, Content: "new"}}}},
		},
	}

	concern := Concern{Name: "bugs"}
	prompt := BuildPrompt(concern, files, 5)

	if strings.Contains(prompt, "deleted.go") {
		t.Error("deleted files should not appear in prompt")
	}
	if !strings.Contains(prompt, "kept.go") {
		t.Error("non-deleted files should appear")
	}
}

func TestSystemPrompt_ContainsConcern(t *testing.T) {
	concern := Concern{Name: "performance", Prompt: "Check for O(n^2)"}
	sys := SystemPrompt(concern)

	if !strings.Contains(sys, "performance") {
		t.Error("expected concern name in system prompt")
	}
	if !strings.Contains(sys, "JSON array") {
		t.Error("expected JSON instruction in system prompt")
	}
	if !strings.Contains(sys, "Check for O(n^2)") {
		t.Error("expected concern prompt embedded")
	}
}

func TestBuildConcerns_All(t *testing.T) {
	all := BuildConcerns(nil)
	if len(all) != 5 {
		t.Errorf("expected 5 concerns, got %d", len(all))
	}
}

func TestBuildConcerns_Filtered(t *testing.T) {
	filtered := BuildConcerns([]string{"security", "bugs"})
	if len(filtered) != 2 {
		t.Errorf("expected 2 concerns, got %d", len(filtered))
	}
	names := map[string]bool{}
	for _, c := range filtered {
		names[c.Name] = true
	}
	if !names["security"] || !names["bugs"] {
		t.Error("expected security and bugs in filtered result")
	}
}

func TestBuildConcerns_NoMatch(t *testing.T) {
	filtered := BuildConcerns([]string{"nonexistent"})
	if len(filtered) != 0 {
		t.Errorf("expected 0 concerns for non-existent name, got %d", len(filtered))
	}
}

func TestBuildPromptEnhanced_Basic(t *testing.T) {
	files := []diff.File{
		{
			Path: "handler.go",
			Hunks: []diff.Hunk{
				{
					OldStart: 10, OldCount: 3,
					NewStart: 10, NewCount: 5,
					Header: "func handleRequest",
					Lines: []diff.Line{
						{Type: diff.LineContext, Content: "existing code", OldNum: 10, NewNum: 10},
						{Type: diff.LineAdded, Content: "new code", NewNum: 11},
						{Type: diff.LineRemoved, Content: "old code", OldNum: 11},
					},
				},
			},
		},
	}

	concern := Concern{Name: "security", Prompt: "Check for security issues"}
	prompt := BuildPromptEnhanced(concern, files, 10)

	if !strings.Contains(prompt, "handler.go") {
		t.Error("expected file path in prompt")
	}
	if !strings.Contains(prompt, "__new hunk__") {
		t.Error("expected __new hunk__ section")
	}
	if !strings.Contains(prompt, "__old hunk__") {
		t.Error("expected __old hunk__ section")
	}
	if !strings.Contains(prompt, "+new code") {
		t.Error("expected added line in new hunk")
	}
	if !strings.Contains(prompt, "-old code") {
		t.Error("expected removed line in old hunk")
	}
	if !strings.Contains(prompt, "security") {
		t.Error("expected concern name in prompt")
	}
}

func TestBuildPromptEnhanced_DeletedFileSkipped(t *testing.T) {
	files := []diff.File{
		{
			Path:    "deleted.go",
			Deleted: true,
			Hunks:   []diff.Hunk{{Lines: []diff.Line{{Type: diff.LineRemoved, Content: "old"}}}},
		},
		{
			Path: "kept.go",
			Hunks: []diff.Hunk{{
				NewStart: 1, NewCount: 1,
				Lines: []diff.Line{{Type: diff.LineAdded, Content: "new", NewNum: 1}},
			}},
		},
	}

	concern := Concern{Name: "bugs"}
	prompt := BuildPromptEnhanced(concern, files, 5)

	if strings.Contains(prompt, "deleted.go") {
		t.Error("deleted files should not appear in enhanced prompt")
	}
	if !strings.Contains(prompt, "kept.go") {
		t.Error("non-deleted files should appear")
	}
}

func TestBuildPromptEnhanced_NewFile(t *testing.T) {
	files := []diff.File{
		{
			Path:  "new.go",
			Added: true,
			Hunks: []diff.Hunk{
				{NewStart: 1, NewCount: 2, Lines: []diff.Line{
					{Type: diff.LineAdded, Content: "package main", NewNum: 1},
					{Type: diff.LineAdded, Content: "func main() {}", NewNum: 2},
				}},
			},
		},
	}

	concern := Concern{Name: "bugs"}
	prompt := BuildPromptEnhanced(concern, files, 5)

	if !strings.Contains(prompt, "(new file)") {
		t.Error("expected (new file) annotation")
	}
}

func TestBuildPromptEnhanced_RenamedFile(t *testing.T) {
	files := []diff.File{
		{
			Path:    "new_name.go",
			OldPath: "old_name.go",
			Renamed: true,
			Hunks: []diff.Hunk{{
				NewStart: 1, NewCount: 1,
				Lines: []diff.Line{{Type: diff.LineContext, Content: "package main", OldNum: 1, NewNum: 1}},
			}},
		},
	}

	concern := Concern{Name: "style"}
	prompt := BuildPromptEnhanced(concern, files, 5)

	if !strings.Contains(prompt, "renamed from old_name.go") {
		t.Error("expected rename annotation in enhanced prompt")
	}
}

func TestAllConcerns_HasExpectedNames(t *testing.T) {
	all := AllConcerns()
	expected := map[string]bool{
		"security":    true,
		"bugs":        true,
		"performance": true,
		"correctness": true,
		"style":       true,
	}
	for _, c := range all {
		if !expected[c.Name] {
			t.Errorf("unexpected concern name: %q", c.Name)
		}
		if c.Prompt == "" {
			t.Errorf("concern %q has empty prompt", c.Name)
		}
	}
}
