package sight

import (
	"os"
	"path/filepath"
	"strings"
)

// LoadProjectRules scans a directory for project-specific coding rules and
// standards. It looks for:
//   - .cursor/rules/*.md
//   - CLAUDE.md
//   - CONTRIBUTING.md
//   - .sight/rules/*.md
//
// Found rules are concatenated with section headers and returned as a single
// string suitable for injection into an LLM system prompt. Returns an empty
// string if no rule files are found.
func LoadProjectRules(dir string) string {
	type ruleSource struct {
		label string
		paths []string
	}

	sources := []ruleSource{
		{
			label: "Cursor Rules",
			paths: globFiles(filepath.Join(dir, ".cursor", "rules", "*.md")),
		},
		{
			label: "Claude Rules",
			paths: fileIfExists(filepath.Join(dir, "CLAUDE.md")),
		},
		{
			label: "Contributing Guidelines",
			paths: fileIfExists(filepath.Join(dir, "CONTRIBUTING.md")),
		},
		{
			label: "Sight Rules",
			paths: globFiles(filepath.Join(dir, ".sight", "rules", "*.md")),
		},
	}

	var b strings.Builder
	for _, src := range sources {
		for _, path := range src.paths {
			data, err := os.ReadFile(path) // #nosec G304 -- path is built from filepath.Join(dir, ...) against known rule-file names/globs (.cursor/rules, CLAUDE.md, CONTRIBUTING.md, .sight/rules) under the project directory being reviewed
			if err != nil {
				continue
			}
			content := strings.TrimSpace(string(data))
			if content == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteString("\n\n")
			}
			b.WriteString("### ")
			b.WriteString(src.label)
			b.WriteString(" (")
			// Show relative path for clarity
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				rel = filepath.Base(path)
			}
			b.WriteString(rel)
			b.WriteString(")\n\n")
			b.WriteString(content)
		}
	}

	return b.String()
}

// globFiles returns matching file paths for a glob pattern, or nil on error.
func globFiles(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	return matches
}

// fileIfExists returns a single-element slice if the file exists, or nil.
func fileIfExists(path string) []string {
	if _, err := os.Stat(path); err == nil {
		return []string{path}
	}
	return nil
}
