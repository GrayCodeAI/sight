package sight

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/GrayCodeAI/sight/internal/review"
)

// CustomCheck represents a user-defined review check loaded from a markdown file
// in the .sight/checks/ directory. Each file becomes a check whose content is
// injected into the LLM prompt as an additional concern.
type CustomCheck struct {
	// Name is derived from the filename (e.g., "no-console-log" from no-console-log.md).
	Name string

	// Prompt is the markdown body that describes the check rules and gets
	// injected into the LLM system prompt.
	Prompt string

	// Severity is the default severity for findings from this check.
	// Parsed from YAML frontmatter; defaults to "medium".
	Severity string

	// Languages restricts the check to files matching these extensions
	// (e.g., ["go", "py"]). Empty means all languages.
	Languages []string

	// Enabled controls whether the check is active. Defaults to true.
	Enabled bool
}

// LoadChecks reads all markdown files from the given directory (typically
// ".sight/checks/") and parses them into CustomCheck values. Each .md file
// becomes one check. YAML frontmatter between --- delimiters is parsed for
// metadata (severity, languages, enabled); the remaining body becomes the
// check prompt.
//
// Returns an empty slice (not an error) if the directory does not exist.
func LoadChecks(dir string) ([]CustomCheck, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var checks []CustomCheck
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".md")
		check := parseCheckFile(name, string(data))
		checks = append(checks, check)
	}

	return checks, nil
}

// LoadChecksFromRepo is a convenience that looks for .sight/checks/ relative
// to the given repository root directory.
func LoadChecksFromRepo(repoDir string) ([]CustomCheck, error) {
	return LoadChecks(filepath.Join(repoDir, ".sight", "checks"))
}

// CustomChecksToConcerns converts loaded custom checks into internal Concern
// values suitable for the review pipeline. Only enabled checks are included.
// If languages is non-empty, the concern prompt notes which languages apply.
func CustomChecksToConcerns(checks []CustomCheck) []review.Concern {
	var concerns []review.Concern
	for _, c := range checks {
		if !c.Enabled {
			continue
		}
		prompt := c.Prompt
		if len(c.Languages) > 0 {
			prompt += "\n\nThis check applies only to files with these extensions: " +
				strings.Join(c.Languages, ", ")
		}
		if c.Severity != "" {
			prompt += "\n\nDefault severity for issues found by this check: " + c.Severity
		}
		concerns = append(concerns, review.Concern{
			Name:   "custom:" + c.Name,
			Prompt: prompt,
		})
	}
	return concerns
}

// WithCustomChecks loads checks from the given directory and appends them as
// additional concerns to the review. This is the primary integration point:
//
//	sight.Review(ctx, diff, sight.WithCustomChecks(".sight/checks"))
func WithCustomChecks(dir string) Option {
	return optFunc(func(c *config) {
		checks, err := LoadChecks(dir)
		if err != nil || len(checks) == 0 {
			return
		}
		concerns := CustomChecksToConcerns(checks)
		for _, concern := range concerns {
			c.concerns = append(c.concerns, concern.Name)
		}
		c.customConcerns = append(c.customConcerns, concerns...)
	})
}

// WithCustomChecksFromRepo loads checks from .sight/checks/ within the repo root.
func WithCustomChecksFromRepo(repoDir string) Option {
	return WithCustomChecks(filepath.Join(repoDir, ".sight", "checks"))
}

// parseCheckFile parses a markdown file into a CustomCheck. It extracts YAML
// frontmatter between --- delimiters for metadata and uses the remaining
// content as the prompt.
func parseCheckFile(name, content string) CustomCheck {
	check := CustomCheck{
		Name:     name,
		Enabled:  true,
		Severity: "medium",
	}

	content = strings.TrimSpace(content)

	// Parse YAML frontmatter if present
	if strings.HasPrefix(content, "---") {
		parts := strings.SplitN(content[3:], "---", 2)
		if len(parts) == 2 {
			parseFrontmatter(&check, strings.TrimSpace(parts[0]))
			content = strings.TrimSpace(parts[1])
		}
	}

	check.Prompt = content
	return check
}

// parseFrontmatter extracts metadata from a simplified YAML frontmatter block.
// Supports: severity, languages (comma-separated), enabled (true/false).
func parseFrontmatter(check *CustomCheck, fm string) {
	for _, line := range strings.Split(fm, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "severity":
			value = strings.ToLower(value)
			switch value {
			case "info", "low", "medium", "high", "critical":
				check.Severity = value
			}
		case "languages":
			langs := strings.Split(value, ",")
			for _, l := range langs {
				l = strings.TrimSpace(l)
				l = strings.Trim(l, "[]\"'")
				if l != "" {
					check.Languages = append(check.Languages, l)
				}
			}
		case "enabled":
			check.Enabled = !strings.EqualFold(value, "false")
		}
	}
}
