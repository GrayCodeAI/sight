package sight

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IncrementalState tracks the last-reviewed commit SHA for incremental reviews.
// It is safe for concurrent use.
type IncrementalState struct {
	mu              sync.Mutex
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
//
// If contextLines > 0, the review includes surrounding file context around
// each changed hunk for better understanding of the change.
func ReviewIncremental(ctx context.Context, base, head string, state *IncrementalState, opts ...Option) (*Result, error) {
	if state != nil {
		if last := state.LastReviewedSHA(); last != "" {
			base = last
		}
	}

	diffText, err := gitDiffRange(ctx, base, head)
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

	// Enrich diff with surrounding file context
	enrichedDiff := enrichDiffWithContext(ctx, diffText, 10)

	r := NewReviewer(opts...)
	result, err := r.Review(ctx, enrichedDiff)
	if err != nil {
		return nil, err
	}

	if state != nil {
		state.SetLastReviewedSHA(head)
	}

	return result, nil
}

// ReviewIncrementalWithContext reviews changes with surrounding file context.
// contextLines specifies how many lines of context to include around each hunk.
func ReviewIncrementalWithContext(ctx context.Context, base, head string, state *IncrementalState, contextLines int, opts ...Option) (*Result, error) {
	if state != nil {
		if last := state.LastReviewedSHA(); last != "" {
			base = last
		}
	}

	diffText, err := gitDiffRange(ctx, base, head)
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

	if contextLines > 0 {
		diffText = enrichDiffWithContext(ctx, diffText, contextLines)
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

// hunkHeaderRe matches @@ -a,b +c,d @@ hunk headers.
var hunkHeaderRe = regexp.MustCompile(`@@ -(\d+),?\d* \+(\d+),?\d* @@`)

// enrichDiffWithContext adds surrounding file content around each changed hunk.
// This gives the reviewer more context about what the change means in the
// broader file structure.
func enrichDiffWithContext(ctx context.Context, diffText string, contextLines int) string {
	var enriched strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(diffText))

	var currentFile string
	var inHunk bool

	for scanner.Scan() {
		line := scanner.Text()

		// Track current file from +++ b/path lines
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			enriched.WriteString(line + "\n")
			inHunk = false
			continue
		}

		// Detect hunk headers and add surrounding context
		if matches := hunkHeaderRe.FindStringSubmatch(line); matches != nil && currentFile != "" {
			inHunk = true
			startLine, _ := strconv.Atoi(matches[1])

			// Add surrounding context before the hunk
			contextBefore := loadFileLines(ctx, currentFile, startLine-contextLines, startLine-1)
			if len(contextBefore) > 0 {
				enriched.WriteString(fmt.Sprintf("\n--- Context before (lines %d-%d) ---\n", startLine-contextLines, startLine-1))
				for i, cl := range contextBefore {
					enriched.WriteString(fmt.Sprintf("  %d | %s\n", startLine-contextLines+i, cl))
				}
			}

			enriched.WriteString(line + "\n")
			continue
		}

		enriched.WriteString(line + "\n")
	}

	return enriched.String()
}

// loadFileLines reads specific line ranges from a file.
func loadFileLines(ctx context.Context, filePath string, startLine, endLine int) []string {
	if startLine < 1 {
		startLine = 1
	}

	f, err := os.Open(filePath)
	if err != nil {
		// Try to find the file relative to git root
		root, rerr := gitRoot(ctx)
		if rerr != nil {
			return nil
		}
		f, err = os.Open(filepath.Join(root, filePath))
		if err != nil {
			return nil
		}
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		if lineNum >= startLine && lineNum <= endLine {
			lines = append(lines, scanner.Text())
		}
		if lineNum > endLine {
			break
		}
	}

	return lines
}

// gitRoot returns the root directory of the git repository.
func gitRoot(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// gitDiffRange runs `git diff base...head` with a context timeout.
func gitDiffRange(ctx context.Context, base, head string) (string, error) {
	// Default 30s timeout if context has no deadline
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	// Try three-dot syntax first (merge-base diff)
	out, err := exec.CommandContext(ctx, "git", "diff", base+"..."+head).Output()
	if err == nil {
		return string(out), nil
	}

	// Fall back to two-dot syntax
	out, err = exec.CommandContext(ctx, "git", "diff", base, head).Output()
	if err != nil {
		return "", fmt.Errorf("git diff %s %s failed: %w", base, head, err)
	}
	return string(out), nil
}
