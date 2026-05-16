// Package context provides git and code context enrichment for diffs.
package context

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// FileContext holds contextual information about a changed file.
type FileContext struct {
	Path          string
	RecentCommits []string
	BlameSnippet  string
}

// Enrich gathers git context for the given file paths.
// Returns context for each file, best-effort (non-fatal on failures).
func Enrich(files []string) []FileContext {
	var results []FileContext
	for _, f := range files {
		fc := FileContext{Path: f}
		if commits, err := recentCommits(f, 5); err == nil {
			fc.RecentCommits = commits
		}
		results = append(results, fc)
	}
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
		b.WriteString(fmt.Sprintf("### %s — Recent changes:\n", fc.Path))
		for _, c := range fc.RecentCommits {
			b.WriteString(fmt.Sprintf("  - %s\n", c))
		}
		if fc.BlameSnippet != "" {
			b.WriteString(fmt.Sprintf("  Blame: %s\n", fc.BlameSnippet))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// DiffBase returns the diff of the current branch against a base branch.
func DiffBase(base string) (string, error) {
	out, err := exec.Command("git", "diff", base+"...HEAD").Output()
	if err != nil {
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

	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", fmt.Errorf("git blame failed: %w", err)
	}

	return parseBlameAuthors(string(out)), nil
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
