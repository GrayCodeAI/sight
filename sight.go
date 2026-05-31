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
	CWE       string   `json:"cwe,omitempty"`
	// Confidence is a numeric score from 0.0 to 1.0 indicating how certain
	// the system is that this finding is a true positive. Values closer to
	// 1.0 mean higher confidence.
	Confidence float64 `json:"confidence"`
	// SASTSource marks findings that originated from static analysis (SAST)
	// and were fed into the LLM prompt for validation.
	SASTSource bool `json:"sast_source,omitempty"`
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
	// AverageConfidence is the mean confidence score across all findings (0.0-1.0).
	AverageConfidence float64 `json:"average_confidence"`
	// HighConfidenceCount is the number of findings with confidence >= 0.7.
	HighConfidenceCount int `json:"high_confidence_count"`
	// LowConfidenceCount is the number of findings with confidence < 0.5.
	LowConfidenceCount int `json:"low_confidence_count"`
}

// Result is the complete output of a review operation.
type Result struct {
	Findings []Finding       `json:"findings"`
	Comments []InlineComment `json:"comments"`
	Stats    Stats           `json:"stats"`
	Report   string          `json:"report"`
	FailOn   Severity        `json:"fail_on"`
	// SASTFusion tracks which SAST findings the LLM confirmed vs dismissed.
	// Only populated when SAST-LLM fusion is active (preAnalysis enabled).
	SASTFusion *SASTFusionResult `json:"sast_fusion,omitempty"`
	// ConfidenceBreakdown groups findings by confidence band for quick triage.
	ConfidenceBreakdown *ConfidenceBreakdown `json:"confidence_breakdown,omitempty"`
}

// ConfidenceBreakdown groups findings into bands for quick triage.
type ConfidenceBreakdown struct {
	// High are findings with confidence >= 0.7.
	High []Finding `json:"high"`
	// Medium are findings with 0.5 <= confidence < 0.7.
	Medium []Finding `json:"medium"`
	// Low are findings with confidence < 0.5.
	Low []Finding `json:"low"`
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
