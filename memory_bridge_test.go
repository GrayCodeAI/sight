package sight

import (
	"context"
	"fmt"
	"testing"
)

// mockMemorySource is a test double for MemorySource.
type mockMemorySource struct {
	recallFn func(ctx context.Context, query string, limit int) ([]MemoryResult, error)
	storeFn  func(ctx context.Context, key, content string, tags []string) error

	storedKeys   []string
	storedValues []string
	storedTags   [][]string
}

func (m *mockMemorySource) Recall(ctx context.Context, query string, limit int) ([]MemoryResult, error) {
	if m.recallFn != nil {
		return m.recallFn(ctx, query, limit)
	}
	return nil, nil
}

func (m *mockMemorySource) Store(ctx context.Context, key, content string, tags []string) error {
	if m.storeFn != nil {
		return m.storeFn(ctx, key, content, tags)
	}
	m.storedKeys = append(m.storedKeys, key)
	m.storedValues = append(m.storedValues, content)
	m.storedTags = append(m.storedTags, tags)
	return nil
}

// --- Tests ---

func TestNewMemoryBridge_InitializesCorrectly(t *testing.T) {
	src := &mockMemorySource{}
	b := NewMemoryBridge(src)

	if b == nil {
		t.Fatal("NewMemoryBridge returned nil")
	}
	if b.source != src {
		t.Error("source not set")
	}
	if b.maxContext != 2000 {
		t.Errorf("maxContext = %d, want 2000", b.maxContext)
	}
	if !b.enabled {
		t.Error("expected bridge to be enabled by default")
	}
}

func TestEnrichContext_WithResults_ReturnsConcatenatedContext(t *testing.T) {
	src := &mockMemorySource{
		recallFn: func(_ context.Context, _ string, _ int) ([]MemoryResult, error) {
			return []MemoryResult{
				{ID: "1", Content: "finding about auth", Score: 0.9},
				{ID: "2", Content: "finding about input", Score: 0.7},
			}, nil
		},
	}
	b := NewMemoryBridge(src)
	got, err := b.EnrichContext(context.Background(), []string{"sql injection", "auth bypass"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "" {
		t.Fatal("expected non-empty context")
	}
	// Both findings should appear since they have unique IDs.
	if got != "finding about auth\nfinding about input" {
		t.Errorf("unexpected context: %q", got)
	}
}

func TestEnrichContext_EmptyResults_ReturnsEmptyString(t *testing.T) {
	src := &mockMemorySource{
		recallFn: func(_ context.Context, _ string, _ int) ([]MemoryResult, error) {
			return nil, nil
		},
	}
	b := NewMemoryBridge(src)
	got, err := b.EnrichContext(context.Background(), []string{"some finding"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestEnrichContext_DisabledBridge_ReturnsEmpty(t *testing.T) {
	src := &mockMemorySource{
		recallFn: func(_ context.Context, _ string, _ int) ([]MemoryResult, error) {
			t.Fatal("Recall should not be called on a disabled bridge")
			return nil, nil
		},
	}
	b := NewMemoryBridge(src, WithMemoryEnabled(false))
	got, err := b.EnrichContext(context.Background(), []string{"x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestEnrichContext_RespectsMaxContextTokenLimit(t *testing.T) {
	// Each token is approximately 4 characters. Set a very small budget so
	// only the first (highest-scored) result fits.
	src := &mockMemorySource{
		recallFn: func(_ context.Context, _ string, _ int) ([]MemoryResult, error) {
			return []MemoryResult{
				{ID: "a", Content: "aaa", Score: 1.0},  // 3 chars, fits in 1 token budget (4 chars)
				{ID: "b", Content: "bbbb", Score: 0.5}, // 4 chars
			}, nil
		},
	}
	// maxContext=2 means maxChars=8. First entry (3) + newline (1) + second (4) = 8.
	// That fits, so set maxContext=1 => maxChars=4, which only fits the first.
	b := NewMemoryBridge(src, WithMaxContextTokens(1))
	got, err := b.EnrichContext(context.Background(), []string{"q"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "aaa" {
		t.Errorf("expected truncated result %q, got %q", "aaa", got)
	}
}

func TestStoreFindings_StoresAllFindings(t *testing.T) {
	src := &mockMemorySource{}
	b := NewMemoryBridge(src)
	findings := []Finding{
		{Concern: "security", Severity: SeverityHigh, File: "main.go", Line: 10, Message: "bad"},
		{Concern: "performance", Severity: SeverityLow, File: "util.go", Line: 20, Message: "slow"},
	}
	err := b.StoreFindings(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(src.storedKeys) != 2 {
		t.Fatalf("stored %d findings, want 2", len(src.storedKeys))
	}
	if src.storedKeys[0] != "main.go:10:security" {
		t.Errorf("key[0] = %q, want %q", src.storedKeys[0], "main.go:10:security")
	}
	if src.storedValues[0] != "bad" {
		t.Errorf("value[0] = %q, want %q", src.storedValues[0], "bad")
	}
	// Verify tags include review-finding, concern, and severity.
	tags := src.storedTags[0]
	found := false
	for _, tag := range tags {
		if tag == "review-finding" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'review-finding' tag, got %v", tags)
	}
}

func TestRecallSimilar_ReturnsSortedResults(t *testing.T) {
	src := &mockMemorySource{
		recallFn: func(_ context.Context, _ string, _ int) ([]MemoryResult, error) {
			return []MemoryResult{
				{ID: "low", Content: "low", Score: 0.3},
				{ID: "high", Content: "high", Score: 0.9},
				{ID: "mid", Content: "mid", Score: 0.6},
			}, nil
		},
	}
	b := NewMemoryBridge(src)
	results, err := b.RecallSimilar(context.Background(), "auth", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Score < results[1].Score || results[1].Score < results[2].Score {
		t.Errorf("results not sorted descending: %v", results)
	}
}

func TestRecallSimilar_WithLimit_RespectsCount(t *testing.T) {
	var capturedLimit int
	src := &mockMemorySource{
		recallFn: func(_ context.Context, _ string, limit int) ([]MemoryResult, error) {
			capturedLimit = limit
			return []MemoryResult{
				{ID: "a", Score: 1.0},
				{ID: "b", Score: 0.5},
				{ID: "c", Score: 0.3},
			}, nil
		},
	}
	b := NewMemoryBridge(src)
	_, err := b.RecallSimilar(context.Background(), "bug", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedLimit != 2 {
		t.Errorf("Recall called with limit=%d, want 2", capturedLimit)
	}
}

func TestNilSource_NoPanic(t *testing.T) {
	// A nil bridge (no source at all) must not panic.
	var b *MemoryBridge
	ctx := context.Background()

	_, err := b.EnrichContext(ctx, []string{"x"})
	if err != nil {
		t.Errorf("EnrichContext on nil bridge: %v", err)
	}

	err = b.StoreFindings(ctx, []Finding{{Concern: "c", Message: "m"}})
	if err != nil {
		t.Errorf("StoreFindings on nil bridge: %v", err)
	}

	res, err := b.RecallSimilar(ctx, "q", 5)
	if err != nil {
		t.Errorf("RecallSimilar on nil bridge: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("RecallSimilar on nil bridge returned %d results", len(res))
	}

	// Also verify that a bridge with a nil source does not panic when
	// operations are skipped (disabled).
	b2 := NewMemoryBridge(nil, WithMemoryEnabled(false))
	_, err = b2.EnrichContext(ctx, []string{"x"})
	if err != nil {
		t.Errorf("EnrichContext on disabled bridge with nil source: %v", err)
	}

	// Verify EnrichContext with empty findings on a valid bridge does not call source.
	src := &mockMemorySource{
		recallFn: func(_ context.Context, _ string, _ int) ([]MemoryResult, error) {
			return nil, fmt.Errorf("should not be called")
		},
	}
	b3 := NewMemoryBridge(src)
	_, err = b3.EnrichContext(ctx, nil)
	if err != nil {
		t.Errorf("EnrichContext with nil findings: %v", err)
	}
	_, err = b3.EnrichContext(ctx, []string{})
	if err != nil {
		t.Errorf("EnrichContext with empty findings: %v", err)
	}
}
