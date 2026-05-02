package sight_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/GrayCodeAI/sight"
)

func TestDescribe_ValidResponse(t *testing.T) {
	desc := sight.Description{
		Title:      "Add SQL query handler",
		Summary:    "Adds a new handler that queries users by ID",
		Changes:    []string{"Added handleRequest function", "Added SQL query"},
		ChangeType: "feature",
		Risk:       "high — SQL injection risk",
		TestPlan:   "Test with parameterized IDs",
	}
	respJSON, _ := json.Marshal(desc)
	provider := &mockProvider{response: string(respJSON)}

	result, err := sight.Describe(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Describe failed: %v", err)
	}
	if result.Title != "Add SQL query handler" {
		t.Errorf("expected title 'Add SQL query handler', got %q", result.Title)
	}
	if result.Summary != "Adds a new handler that queries users by ID" {
		t.Errorf("unexpected summary: %q", result.Summary)
	}
	if result.ChangeType != "feature" {
		t.Errorf("expected change_type 'feature', got %q", result.ChangeType)
	}
	if len(result.Changes) != 2 {
		t.Errorf("expected 2 changes, got %d", len(result.Changes))
	}
}

func TestDescribe_MarkdownWrappedJSON(t *testing.T) {
	resp := "Here is the description:\n\n```json\n" + `{
		"title": "Fix auth bug",
		"summary": "Fixes authentication bypass",
		"changes": ["Patched auth check"],
		"change_type": "bugfix",
		"risk": "low",
		"test_plan": "Run auth tests"
	}` + "\n```\n"
	provider := &mockProvider{response: resp}

	result, err := sight.Describe(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Describe failed: %v", err)
	}
	if result.Title != "Fix auth bug" {
		t.Errorf("expected 'Fix auth bug', got %q", result.Title)
	}
}

func TestDescribe_FallbackOnInvalidJSON(t *testing.T) {
	provider := &mockProvider{response: "This is not JSON at all, just prose."}

	result, err := sight.Describe(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Describe failed: %v", err)
	}
	// Fallback should generate a title from the first file
	if result.Title == "" {
		t.Error("expected non-empty fallback title")
	}
	if result.ChangeType != "chore" {
		t.Errorf("expected fallback change_type 'chore', got %q", result.ChangeType)
	}
}

func TestDescribe_NoProvider(t *testing.T) {
	_, err := sight.Describe(context.Background(), testDiff)
	if err != sight.ErrNoProvider {
		t.Errorf("expected ErrNoProvider, got %v", err)
	}
}

func TestDescribe_EmptyDiff(t *testing.T) {
	provider := &mockProvider{response: "{}"}
	_, err := sight.Describe(context.Background(), "", sight.WithProvider(provider))
	if err != sight.ErrEmptyDiff {
		t.Errorf("expected ErrEmptyDiff, got %v", err)
	}
}

func TestDescribe_UnparseableDiff(t *testing.T) {
	// A diff that parses to zero files
	provider := &mockProvider{response: "{}"}
	result, err := sight.Describe(context.Background(), "not a real diff", sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Title != "No changes" {
		t.Errorf("expected 'No changes' for empty parsed diff, got %q", result.Title)
	}
}

func TestDescribe_ProviderError(t *testing.T) {
	provider := &mockProvider{err: errTest}
	_, err := sight.Describe(context.Background(), testDiff, sight.WithProvider(provider))
	if err == nil {
		t.Error("expected error from provider")
	}
}

func TestDescribe_JSONInCodeBlock(t *testing.T) {
	resp := "```\n" + `{
		"title": "Refactor utils",
		"summary": "Cleaned up utility functions",
		"changes": ["Simplified helpers"],
		"change_type": "refactor",
		"risk": "low",
		"test_plan": "Run unit tests"
	}` + "\n```"
	provider := &mockProvider{response: resp}

	result, err := sight.Describe(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Describe failed: %v", err)
	}
	if result.Title != "Refactor utils" {
		t.Errorf("expected 'Refactor utils', got %q", result.Title)
	}
}

func TestDescribe_EmptyTitle_FallsBackToGenerated(t *testing.T) {
	// JSON parses but title is empty, so fallback kicks in
	resp := `{"title": "", "summary": "something"}`
	provider := &mockProvider{response: resp}

	result, err := sight.Describe(context.Background(), testDiff, sight.WithProvider(provider))
	if err != nil {
		t.Fatalf("Describe failed: %v", err)
	}
	if result.Title == "" {
		t.Error("expected non-empty fallback title")
	}
}
