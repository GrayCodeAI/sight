package sight_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/GrayCodeAI/sight"
)

var errTest = errors.New("test error")

func TestImprove_ValidResponse(t *testing.T) {
	improvements := []sight.Improvement{
		{
			File:        "handler.go",
			Line:        13,
			Category:    "performance",
			Description: "Use parameterized query instead of concatenation",
			Before:      `query := "SELECT * FROM users WHERE id = '" + userID + "'"`,
			After:       `query := "SELECT * FROM users WHERE id = $1"`,
			Reasoning:   "Parameterized queries are safer and can be cached by the DB",
		},
	}
	respJSON, _ := json.Marshal(improvements)
	provider := &mockProvider{response: string(respJSON)}

	result, err := sight.Improve(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Improve failed: %v", err)
	}
	if len(result.Improvements) != 1 {
		t.Fatalf("expected 1 improvement, got %d", len(result.Improvements))
	}
	if result.Improvements[0].File != "handler.go" {
		t.Errorf("expected handler.go, got %s", result.Improvements[0].File)
	}
	if result.Improvements[0].Category != "performance" {
		t.Errorf("expected category 'performance', got %q", result.Improvements[0].Category)
	}
	if result.TokensUsed != 500 {
		t.Errorf("expected 500 tokens, got %d", result.TokensUsed)
	}
}

func TestImprove_MarkdownWrappedJSON(t *testing.T) {
	resp := "Here are improvements:\n\n```json\n" + `[
		{
			"file": "handler.go",
			"line": 15,
			"category": "error-handling",
			"description": "Improve error message",
			"before": "log.Printf(\"Error: %v\")",
			"after": "log.Printf(\"failed to fetch user: %v\")",
			"reasoning": "More specific error messages"
		}
	]` + "\n```\n"
	provider := &mockProvider{response: resp}

	result, err := sight.Improve(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Improve failed: %v", err)
	}
	if len(result.Improvements) != 1 {
		t.Fatalf("expected 1 improvement, got %d", len(result.Improvements))
	}
}

func TestImprove_EmptyArray(t *testing.T) {
	provider := &mockProvider{response: "[]"}

	result, err := sight.Improve(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Improve failed: %v", err)
	}
	if len(result.Improvements) != 0 {
		t.Errorf("expected 0 improvements, got %d", len(result.Improvements))
	}
}

func TestImprove_InvalidJSON(t *testing.T) {
	provider := &mockProvider{response: "The code looks great, no improvements needed."}

	result, err := sight.Improve(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Improve failed: %v", err)
	}
	if len(result.Improvements) != 0 {
		t.Errorf("expected 0 improvements for non-JSON, got %d", len(result.Improvements))
	}
}

func TestImprove_FiltersIncomplete(t *testing.T) {
	// Improvements missing required fields should be filtered out
	resp := `[
		{"file": "handler.go", "description": "good desc", "after": "new code", "line": 1, "category": "naming", "before": "old", "reasoning": "better"},
		{"file": "", "description": "no file", "after": "code"},
		{"file": "x.go", "description": "", "after": "code"},
		{"file": "y.go", "description": "no after", "after": ""}
	]`
	provider := &mockProvider{response: resp}

	result, err := sight.Improve(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Improve failed: %v", err)
	}
	if len(result.Improvements) != 1 {
		t.Errorf("expected 1 valid improvement, got %d", len(result.Improvements))
	}
}

func TestImprove_NoProvider(t *testing.T) {
	_, err := sight.Improve(context.Background(), testDiff)
	if err != sight.ErrNoProvider {
		t.Errorf("expected ErrNoProvider, got %v", err)
	}
}

func TestImprove_EmptyDiff(t *testing.T) {
	provider := &mockProvider{response: "[]"}
	_, err := sight.Improve(context.Background(), "", sight.WithProvider(provider))
	if err != sight.ErrEmptyDiff {
		t.Errorf("expected ErrEmptyDiff, got %v", err)
	}
}

func TestImprove_ProviderError(t *testing.T) {
	provider := &mockProvider{err: errTest}
	_, err := sight.Improve(context.Background(), testDiff, sight.WithProvider(provider))
	if err == nil {
		t.Error("expected error from provider")
	}
}

func TestImprove_UnparseableDiff(t *testing.T) {
	provider := &mockProvider{response: "[]"}
	result, err := sight.Improve(context.Background(), "not a real diff", sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Improvements) != 0 {
		t.Errorf("expected 0 improvements for unparseable diff, got %d", len(result.Improvements))
	}
}

func TestImprove_CodeBlockWithoutJsonTag(t *testing.T) {
	resp := "```\n" + `[
		{
			"file": "handler.go",
			"line": 13,
			"category": "simplification",
			"description": "Simplify query",
			"before": "old",
			"after": "new",
			"reasoning": "simpler"
		}
	]` + "\n```"
	provider := &mockProvider{response: resp}

	result, err := sight.Improve(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Improve failed: %v", err)
	}
	if len(result.Improvements) != 1 {
		t.Errorf("expected 1 improvement, got %d", len(result.Improvements))
	}
}
