package sight

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// IncrementalState tracks the last-reviewed commit SHA for incremental reviews.
// It is safe for concurrent use.
type IncrementalState struct {
	mu             sync.Mutex
	lastReviewedSHA string
}

// NewIncrementalState creates a new state tracker, optionally seeded with a
// previously reviewed SHA for resumption.
func NewIncrementalState(lastSHA string) *IncrementalState {
	return &IncrementalState{lastReviewedSHA: lastSHA}
}

// LastReviewedSHA returns the SHA of the last reviewed commit.
func (s *IncrementalState) LastReviewedSHA() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReviewedSHA
}

// SetLastReviewedSHA updates the last-reviewed SHA after a successful review.
func (s *IncrementalState) SetLastReviewedSHA(sha string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReviewedSHA = sha
}

// ReviewIncremental reviews only the changes between base and head commits.
// It uses `git diff base...head` to obtain the diff, reviews it, and records
// the head SHA in the provided state for future incremental runs.
//
// If state is non-nil and has a LastReviewedSHA, that SHA is used as the base
// instead of the provided base argument (enabling resumption).
//
// Pass nil for state if you don't need resumption tracking.
func ReviewIncremental(ctx context.Context, base, head string, state *IncrementalState, opts ...Option) (*Result, error) {
	if state != nil {
		if last := state.LastReviewedSHA(); last != "" {
			base = last
		}
	}

	diffText, err := gitDiffRange(base, head)
	if err != nil {
		return nil, fmt.Errorf("sight: incremental diff failed: %w", err)
	}

	if strings.TrimSpace(diffText) == "" {
		result := &Result{Report: "No new changes since last review."}
		if state != nil {
			state.SetLastReviewedSHA(head)
		}
		return result, nil
	}

	r := NewReviewer(opts...)
	result, err := r.Review(ctx, diffText)
	if err != nil {
		return nil, err
	}

	if state != nil {
		state.SetLastReviewedSHA(head)
	}

	return result, nil
}

// gitDiffRange runs `git diff base...head` and returns the output.
func gitDiffRange(base, head string) (string, error) {
	// Try three-dot syntax first (merge-base diff)
	out, err := exec.Command("git", "diff", base+"..."+head).Output()
	if err == nil {
		return string(out), nil
	}

	// Fall back to two-dot syntax
	out, err = exec.Command("git", "diff", base, head).Output()
	if err != nil {
		return "", fmt.Errorf("git diff %s %s failed: %w", base, head, err)
	}
	return string(out), nil
}
