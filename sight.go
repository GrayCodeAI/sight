// Package sight performs AI-powered code review on diffs. It parses unified diffs,
// enriches them with surrounding code context and git history, then runs parallel
// multi-concern reviews through an LLM provider.
//
// Sight has no CLI and no LLM SDK dependency — it defines a Provider interface
// that consumers (hawk) implement using their own LLM client (eyrie).
//
// Usage:
//
//	result, err := sight.Review(ctx, diffText, sight.WithProvider(myProvider), sight.Thorough)
//	for _, f := range result.Findings {
//	    fmt.Printf("[%s] %s:%d — %s\n", f.Severity, f.File, f.Line, f.Message)
//	}
//
// For repeated reviews, use the reusable Reviewer:
//
//	r := sight.NewReviewer(sight.WithProvider(p), sight.Thorough)
//	result1, _ := r.Review(ctx, diff1)
//	result2, _ := r.Review(ctx, diff2)
package sight

import (
	"context"
	"errors"
	"time"
)

// Finding represents a single issue detected during review.
type Finding struct {
	Concern   string   `json:"concern"`
	Severity  Severity `json:"severity"`
	File      string   `json:"file"`
	Line      int      `json:"line"`
	EndLine   int      `json:"end_line,omitempty"`
	Message   string   `json:"message"`
	Fix       string   `json:"fix,omitempty"`
	Reasoning string   `json:"reasoning,omitempty"`
}

// InlineComment is a finding mapped to an exact position in a diff, ready for
// posting as a review comment.
type InlineComment struct {
	Path       string `json:"path"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line,omitempty"`
	Body       string `json:"body"`
	Suggestion string `json:"suggestion,omitempty"`
}

// Stats provides review metrics.
type Stats struct {
	FilesReviewed      int                      `json:"files_reviewed"`
	HunksAnalyzed      int                      `json:"hunks_analyzed"`
	FindingsTotal      int                      `json:"findings_total"`
	BySeverity         map[Severity]int         `json:"by_severity"`
	ByConcern          map[string]int           `json:"by_concern"`
	TokensUsed         int                      `json:"tokens_used"`
	DurationPerConcern map[string]time.Duration `json:"duration_per_concern"`
}

// Result is the complete output of a review operation.
type Result struct {
	Findings []Finding       `json:"findings"`
	Comments []InlineComment `json:"comments"`
	Stats    Stats           `json:"stats"`
	Report   string          `json:"report"`
	FailOn   Severity        `json:"fail_on"`
}

// Failed returns true if any finding meets or exceeds the configured fail threshold.
func (r *Result) Failed() bool {
	for _, f := range r.Findings {
		if f.Severity.AtLeast(r.FailOn) {
			return true
		}
	}
	return false
}

// MaxSeverity returns the highest severity found.
func (r *Result) MaxSeverity() Severity {
	max := SeverityInfo
	for _, f := range r.Findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// FileChange represents a single file's changes for review.
type FileChange struct {
	Path    string
	OldPath string
	Diff    string
	Content string
}

// PRSource identifies a pull request to review.
type PRSource struct {
	Owner  string
	Repo   string
	Number int
}

// Review performs a one-shot review on a unified diff string.
func Review(ctx context.Context, diff string, opts ...Option) (*Result, error) {
	r := NewReviewer(opts...)
	return r.Review(ctx, diff)
}

// ErrNoProvider is returned when Review is called without a Provider configured.
var ErrNoProvider = errors.New("sight: no provider configured; use WithProvider()")

// ErrEmptyDiff is returned when the input diff is empty.
var ErrEmptyDiff = errors.New("sight: empty diff; nothing to review")

// ErrContextCancelled is returned when the context is cancelled during review.
var ErrContextCancelled = errors.New("sight: context cancelled")
