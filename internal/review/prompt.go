package review

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GrayCodeAI/sight/internal/diff"
)

// SystemPrompt returns the system prompt for a given concern.
func SystemPrompt(concern Concern) string {
	return fmt.Sprintf(`You are a senior software engineer performing a focused code review.
Your concern: %s

%s

IMPORTANT: Respond ONLY with a JSON array of findings. Each finding must have:
{
  "file": "path/to/file.go",
  "line": 42,
  "end_line": 45,
  "severity": "critical|high|medium|low|info",
  "message": "Clear description of the issue",
  "fix": "Suggested code fix or approach",
  "reasoning": "Why this is a problem",
  "cwe": "CWE-89 (if applicable, otherwise empty string)"
}

If you find no issues, respond with an empty array: []

Rules:
- Only report issues in CHANGED lines (lines starting with +)
- Be specific: reference exact variable names, function calls, line numbers
- Severity guide: critical=exploitable/crash, high=likely bug, medium=code smell, low=style, info=suggestion
- Fix must be actionable, not vague ("add error check" not "handle errors better")
- Do not report issues in removed lines (lines starting with -)
- Do not hallucinate line numbers — use the ones visible in the diff`, concern.Name, concern.Prompt)
}

// BuildPrompt constructs the user prompt from a concern and parsed diff files.
func BuildPrompt(concern Concern, files []diff.File, contextLines int) string {
	var b strings.Builder

	b.WriteString("Review the following code changes:\n\n")

	for _, file := range files {
		if file.Deleted {
			continue
		}
		b.WriteString(fmt.Sprintf("## File: %s\n", file.Path))
		if file.Renamed {
			b.WriteString(fmt.Sprintf("(renamed from %s)\n", file.OldPath))
		}
		if file.Added {
			b.WriteString("(new file)\n")
		}
		b.WriteString("\n```diff\n")

		for _, hunk := range file.Hunks {
			b.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@ %s\n",
				hunk.OldStart, hunk.OldCount,
				hunk.NewStart, hunk.NewCount,
				hunk.Header))

			for _, line := range hunk.Lines {
				switch line.Type {
				case diff.LineAdded:
					b.WriteString(fmt.Sprintf("+%s\n", line.Content))
				case diff.LineRemoved:
					b.WriteString(fmt.Sprintf("-%s\n", line.Content))
				case diff.LineContext:
					b.WriteString(fmt.Sprintf(" %s\n", line.Content))
				}
			}
		}

		b.WriteString("```\n\n")
	}

	b.WriteString(fmt.Sprintf("Focus on: %s\n", concern.Name))
	b.WriteString("Respond with a JSON array of findings.\n")

	return b.String()
}

// detectLanguages counts file extensions in the diff and returns a formatted
// language context summary. The primary language is the one with the most files.
func detectLanguages(files []diff.File) string {
	extCount := make(map[string]int)
	for _, f := range files {
		if f.Deleted {
			continue
		}
		ext := filepath.Ext(f.Path)
		if ext == "" {
			ext = filepath.Base(f.Path)
		}
		extCount[ext]++
	}
	if len(extCount) == 0 {
		return ""
	}

	// Determine primary language by highest count.
	type extEntry struct {
		ext   string
		count int
	}
	entries := make([]extEntry, 0, len(extCount))
	for ext, count := range extCount {
		entries = append(entries, extEntry{ext, count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].ext < entries[j].ext
	})

	// Map extensions to language names for primary language display.
	langNames := map[string]string{
		".go":    "Go",
		".py":    "Python",
		".js":    "JavaScript",
		".ts":    "TypeScript",
		".tsx":   "TypeScript (React)",
		".jsx":   "JavaScript (React)",
		".java":  "Java",
		".rs":    "Rust",
		".rb":    "Ruby",
		".cpp":   "C++",
		".c":     "C",
		".h":     "C/C++ Header",
		".cs":    "C#",
		".php":   "PHP",
		".swift": "Swift",
		".kt":    "Kotlin",
		".scala": "Scala",
		".yaml":  "YAML",
		".yml":   "YAML",
		".json":  "JSON",
		".toml":  "TOML",
		".md":    "Markdown",
		".sql":   "SQL",
		".sh":    "Shell",
		".bash":  "Bash",
	}

	primary := entries[0].ext
	primaryLang := langNames[primary]
	if primaryLang == "" {
		primaryLang = strings.TrimPrefix(primary, ".")
	}

	var b strings.Builder
	b.WriteString("## Context\n")
	b.WriteString(fmt.Sprintf("Primary language: %s\n", primaryLang))
	b.WriteString("Files: ")
	for i, e := range entries {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(fmt.Sprintf("%d %s", e.count, e.ext))
	}
	b.WriteString("\n")
	return b.String()
}

// BuildPromptEnhanced constructs a PR-Agent style prompt that separates new and
// old hunks with clear section markers. This helps the LLM distinguish added
// code from removed code more accurately.
func BuildPromptEnhanced(concern Concern, files []diff.File, contextLines int) string {
	var b strings.Builder

	b.WriteString("Review the following code changes:\n\n")

	// Inject language context before the diff content.
	if langCtx := detectLanguages(files); langCtx != "" {
		b.WriteString(langCtx)
		b.WriteString("\n")
	}

	for _, file := range files {
		if file.Deleted {
			continue
		}
		b.WriteString(fmt.Sprintf("## File: %s\n", file.Path))
		if file.Renamed {
			b.WriteString(fmt.Sprintf("(renamed from %s)\n", file.OldPath))
		}
		if file.Added {
			b.WriteString("(new file)\n")
		}
		b.WriteString("\n")

		for _, hunk := range file.Hunks {
			b.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@ %s\n\n",
				hunk.OldStart, hunk.OldCount,
				hunk.NewStart, hunk.NewCount,
				hunk.Header))

			// __new hunk__ section: added lines and context lines with new-file line numbers
			b.WriteString("__new hunk__\n")
			for _, line := range hunk.Lines {
				switch line.Type {
				case diff.LineAdded:
					b.WriteString(fmt.Sprintf("%d +%s\n", line.NewNum, line.Content))
				case diff.LineContext:
					b.WriteString(fmt.Sprintf("%d  %s\n", line.NewNum, line.Content))
				}
			}
			b.WriteString("\n")

			// __old hunk__ section: removed lines and context lines with old-file line numbers
			b.WriteString("__old hunk__\n")
			for _, line := range hunk.Lines {
				switch line.Type {
				case diff.LineRemoved:
					b.WriteString(fmt.Sprintf("%d -%s\n", line.OldNum, line.Content))
				case diff.LineContext:
					b.WriteString(fmt.Sprintf("%d  %s\n", line.OldNum, line.Content))
				}
			}
			b.WriteString("\n")
		}
	}

	b.WriteString(fmt.Sprintf("Focus on: %s\n", concern.Name))
	b.WriteString("Respond with a JSON array of findings.\n")

	return b.String()
}
