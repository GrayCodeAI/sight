package review

import (
	"fmt"
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
  "reasoning": "Why this is a problem"
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
