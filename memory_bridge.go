package sight

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// MemoryResult represents a single result retrieved from a memory store.
type MemoryResult struct {
	ID      string   `json:"id"`
	Content string   `json:"content"`
	Score   float64  `json:"score"`
	Tags    []string `json:"tags,omitempty"`
}

// MemorySource defines the interface for a memory backend (e.g. yaad).
// Using an interface keeps sight free of any direct yaad dependency.
type MemorySource interface {
	// Recall returns up to limit results relevant to query, sorted by
	// descending relevance score.
	Recall(ctx context.Context, query string, limit int) ([]MemoryResult, error)

	// Store persists content under key with the given tags for future recall.
	Store(ctx context.Context, key, content string, tags []string) error
}

// MemoryBridge enriches code reviews with historical context from a
// MemorySource and persists new findings back for future recall.
type MemoryBridge struct {
	source    MemorySource
	maxContext int // maximum approximate tokens to include in enriched context
	enabled   bool
}

// MemoryBridgeOption configures a MemoryBridge.
type MemoryBridgeOption func(*MemoryBridge)

// NewMemoryBridge creates a MemoryBridge backed by source.
// By default the bridge is enabled with a 2 000-token context budget.
func NewMemoryBridge(source MemorySource, opts ...MemoryBridgeOption) *MemoryBridge {
	b := &MemoryBridge{
		source:    source,
		maxContext: 2000,
		enabled:   true,
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// WithMaxContextTokens sets the approximate maximum number of tokens included
// in the enriched context returned by EnrichContext.
func WithMaxContextTokens(n int) MemoryBridgeOption {
	return func(b *MemoryBridge) { b.maxContext = n }
}

// WithMemoryEnabled enables or disables the bridge. When disabled all
// operations become no-ops.
func WithMemoryEnabled(enabled bool) MemoryBridgeOption {
	return func(b *MemoryBridge) { b.enabled = enabled }
}

// EnrichContext queries the memory source for context relevant to the given
// findings and returns a single concatenated, token-truncated string.
// A nil or disabled bridge returns an empty string.
func (b *MemoryBridge) EnrichContext(ctx context.Context, findings []string) (string, error) {
	if b == nil || !b.enabled || len(findings) == 0 {
		return "", nil
	}

	seen := make(map[string]struct{})
	var all []MemoryResult

	for _, finding := range findings {
		results, err := b.source.Recall(ctx, finding, 5)
		if err != nil {
			return "", fmt.Errorf("memory recall for %q: %w", finding, err)
		}
		for _, r := range results {
			if _, dup := seen[r.ID]; dup {
				continue
			}
			seen[r.ID] = struct{}{}
			all = append(all, r)
		}
	}

	sort.Slice(all, func(i, j int) bool { return all[i].Score > all[j].Score })

	return truncateToTokenBudget(all, b.maxContext), nil
}

// StoreFindings persists review findings back to the memory source for
// future recall. A nil or disabled bridge is a no-op.
func (b *MemoryBridge) StoreFindings(ctx context.Context, findings []Finding) error {
	if b == nil || !b.enabled {
		return nil
	}

	for _, f := range findings {
		tags := []string{"review-finding", f.Concern}
		if s := f.Severity.String(); s != "" {
			tags = append(tags, s)
		}
		if f.File != "" {
			tags = append(tags, f.File)
		}
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Concern)
		if err := b.source.Store(ctx, key, f.Message, tags); err != nil {
			return fmt.Errorf("store finding %s: %w", key, err)
		}
	}
	return nil
}

// RecallSimilar retrieves past findings similar to concern.
// A nil or disabled bridge returns an empty slice.
func (b *MemoryBridge) RecallSimilar(ctx context.Context, concern string, limit int) ([]MemoryResult, error) {
	if b == nil || !b.enabled {
		return nil, nil
	}

	results, err := b.source.Recall(ctx, concern, limit)
	if err != nil {
		return nil, fmt.Errorf("recall similar: %w", err)
	}

	results = deduplicateByID(results)
	sort.Slice(results, func(i, j int) bool { return results[i].Score > results[j].Score })
	return results, nil
}

// truncateToTokenBudget concatenates result contents, stopping when the
// approximate token budget (1 token ≈ 4 characters) is exhausted.
func truncateToTokenBudget(results []MemoryResult, maxTokens int) string {
	if len(results) == 0 || maxTokens <= 0 {
		return ""
	}

	maxChars := maxTokens * 4
	var b strings.Builder
	for _, r := range results {
		entry := r.Content
		if entry == "" {
			continue
		}
		if b.Len()+len(entry)+1 > maxChars {
			break
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(entry)
	}
	return b.String()
}

// deduplicateByID removes duplicate MemoryResult entries by ID, keeping the
// first occurrence (assumed to have the highest score).
func deduplicateByID(results []MemoryResult) []MemoryResult {
	seen := make(map[string]struct{}, len(results))
	out := make([]MemoryResult, 0, len(results))
	for _, r := range results {
		if _, dup := seen[r.ID]; dup {
			continue
		}
		seen[r.ID] = struct{}{}
		out = append(out, r)
	}
	return out
}
