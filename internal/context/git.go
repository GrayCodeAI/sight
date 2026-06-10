// Package context provides git and code context enrichment for diffs.
package context

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// FileContext holds contextual information about a changed file.
type FileContext struct {
	Path          string
	RecentCommits []string
	BlameSnippet  string
}

// Enrich gathers git context for the given file paths.
// Returns context for each file, best-effort (non-fatal on failures).
// Uses a goroutine pool (max 10 concurrent git log calls) for parallelism.
func Enrich(files []string) []FileContext {
	results := make([]FileContext, len(files))
	if len(files) == 0 {
		return results
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for i, f := range files {
		results[i] = FileContext{Path: f}
		wg.Add(1)
		go func(idx int, path string) {
			defer wg.Done()
			sem <- struct{}{}        // acquire semaphore
			defer func() { <-sem }() // release semaphore
			if commits, err := recentCommits(path, 5); err == nil {
				results[idx].RecentCommits = commits
			}
		}(i, f)
	}

	wg.Wait()
	return results
}

// FormatContext renders file contexts as text suitable for LLM prompt injection.
func FormatContext(contexts []FileContext) string {
	if len(contexts) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n## Git Context\n\n")

	for _, fc := range contexts {
		if len(fc.RecentCommits) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s — Recent changes:\n", fc.Path)
		for _, c := range fc.RecentCommits {
			fmt.Fprintf(&b, "  - %s\n", c)
		}
		if fc.BlameSnippet != "" {
			fmt.Fprintf(&b, "  Blame: %s\n", fc.BlameSnippet)
		}
		b.WriteString("\n")
	}

	return b.String()
}

// DiffBase returns the diff of the current branch against a base branch.
func DiffBase(base string) (string, error) {
	if err := validateGitRef(base); err != nil {
		return "", err
	}
	// #nosec G204 — base validated by validateGitRef
	out, err := exec.Command("git", "diff", base+"...HEAD").Output()
	if err != nil {
		// #nosec G204 — base validated by validateGitRef
		out2, err2 := exec.Command("git", "diff", base).Output()
		if err2 != nil {
			return "", fmt.Errorf("git diff failed: %w", err)
		}
		return string(out2), nil
	}
	return string(out), nil
}

// ChangedFiles returns the list of files changed relative to a base.
func ChangedFiles(base string) ([]string, error) {
	if err := validateGitRef(base); err != nil {
		return nil, err
	}
	// #nosec G204 — base validated by validateGitRef
	out, err := exec.Command("git", "diff", "--name-only", base+"...HEAD").Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only failed: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	return lines, nil
}

// Blame runs git blame on a specific line range and returns a summary.
func Blame(file string, startLine, endLine int) (string, error) {
	if err := validateFilePath(file); err != nil {
		return "", fmt.Errorf("git blame: invalid path: %w", err)
	}

	args := []string{
		"blame", "--line-porcelain",
		"-L", strconv.Itoa(startLine) + "," + strconv.Itoa(endLine),
		"--", file,
	}

	// #nosec G204 — file validated by validateFilePath above, startLine/endLine are ints
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", fmt.Errorf("git blame failed: %w", err)
	}

	return parseBlameAuthors(string(out)), nil
}

// validateGitRef ensures a git ref (branch, tag, SHA) contains no dangerous characters.
func validateGitRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("empty git ref")
	}
	if ref[0] == '-' {
		return fmt.Errorf("git ref %q starts with dash", ref)
	}
	if strings.ContainsAny(ref, ";&|$`(){}[]<>!#*?\n\r\x00\\ ") {
		return fmt.Errorf("git ref %q contains forbidden characters", ref)
	}
	return nil
}

// validateFilePath ensures a file path does not traverse outside the working directory.
func validateFilePath(file string) error {
	if file == "" {
		return fmt.Errorf("empty path")
	}
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot determine working directory: %w", err)
	}
	absPath := file
	if !filepath.IsAbs(file) {
		absPath = filepath.Join(wd, file)
	}
	rel, err := filepath.Rel(wd, absPath)
	if err != nil {
		return fmt.Errorf("cannot resolve relative path: %w", err)
	}
	if strings.HasPrefix(rel, "..") {
		return fmt.Errorf("path %q traverses outside working directory", file)
	}
	return nil
}

func recentCommits(file string, n int) ([]string, error) {
	if err := validateFilePath(file); err != nil {
		return nil, fmt.Errorf("recentCommits: invalid path: %w", err)
	}
	// #nosec G204 — file validated by validateFilePath above
	out, err := exec.Command("git", "log", "--oneline", "-n", strconv.Itoa(n), "--", file).Output()
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}

func parseBlameAuthors(output string) string {
	authors := make(map[string]int)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "author ") {
			author := strings.TrimPrefix(line, "author ")
			authors[author]++
		}
	}
	if len(authors) == 0 {
		return ""
	}
	parts := make([]string, 0, len(authors))
	for author, count := range authors {
		parts = append(parts, fmt.Sprintf("%s(%d)", author, count))
	}
	return strings.Join(parts, ", ")
}
