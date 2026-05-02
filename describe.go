package sight

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/GrayCodeAI/sight/internal/diff"
	"github.com/GrayCodeAI/sight/internal/review"
)

// Description is the generated PR summary.
type Description struct {
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	Changes    []string `json:"changes"`
	ChangeType string   `json:"change_type"`
	Risk       string   `json:"risk"`
	TestPlan   string   `json:"test_plan"`
}

// Describe generates a PR description from a diff using the configured LLM.
func Describe(ctx context.Context, rawDiff string, opts ...Option) (*Description, error) {
	cfg := buildConfig(opts)
	if cfg.provider == nil {
		return nil, ErrNoProvider
	}
	if rawDiff == "" {
		return nil, ErrEmptyDiff
	}

	files := diff.Parse(rawDiff)
	if len(files) == 0 {
		return &Description{Title: "No changes", Summary: "Empty diff"}, nil
	}

	prompt := buildDescribePrompt(files, cfg.maxTokens)

	resp, err := cfg.provider.Chat(ctx, []Message{
		{Role: "user", Content: prompt},
	}, ChatOpts{
		Model:       cfg.model,
		MaxTokens:   2048,
		Temperature: 0.3,
		System:      describeSystemPrompt,
	})
	if err != nil {
		return nil, err
	}

	return parseDescription(resp.Content, files), nil
}

const describeSystemPrompt = `You generate concise, accurate PR descriptions from code diffs.

Respond ONLY with a JSON object:
{
  "title": "Short imperative title (under 72 chars)",
  "summary": "1-3 sentence summary of what this PR does and why",
  "changes": ["Bullet point 1", "Bullet point 2", ...],
  "change_type": "feature|bugfix|refactor|docs|test|chore|perf|security",
  "risk": "low|medium|high — brief explanation",
  "test_plan": "How to verify this change works"
}

Rules:
- Title: imperative mood ("Add X" not "Added X"), under 72 chars
- Summary: what + why, not how
- Changes: 3-7 bullet points covering key changes
- Risk: consider blast radius, backwards compatibility, data migrations
- Test plan: concrete steps, not generic "run tests"`

func buildDescribePrompt(files []diff.File, maxTokens int) string {
	var b strings.Builder
	b.WriteString("Generate a PR description for these changes:\n\n")
	b.WriteString("## Stats\n")
	b.WriteString(diff.Summary(files))
	b.WriteString("\n\n## Changed Files\n\n")

	for _, f := range files {
		prefix := ""
		if f.Added {
			prefix = " (new)"
		} else if f.Deleted {
			prefix = " (deleted)"
		} else if f.Renamed {
			prefix = " (renamed from " + f.OldPath + ")"
		}
		b.WriteString("- " + f.Path + prefix + "\n")
	}

	// Build the diff section, truncating if it would exceed the token budget.
	// For Describe, keep the file list + stats but truncate the diff to fit.
	tokenBudget := maxTokens * 3 // leave room for the response
	headerTokens := review.EstimateTokens(b.String())
	diffBudget := tokenBudget - headerTokens - 100 // 100 token buffer

	var diffBuilder strings.Builder
	diffBuilder.WriteString("\n## Diff\n\n```diff\n")
	truncated := false

	for _, f := range files {
		if f.Deleted {
			continue
		}
		var fileSection strings.Builder
		fileSection.WriteString("--- " + f.Path + "\n")
		for _, h := range f.Hunks {
			for _, l := range h.Lines {
				switch l.Type {
				case diff.LineAdded:
					fileSection.WriteString("+" + l.Content + "\n")
				case diff.LineRemoved:
					fileSection.WriteString("-" + l.Content + "\n")
				case diff.LineContext:
					fileSection.WriteString(" " + l.Content + "\n")
				}
			}
		}

		sectionTokens := review.EstimateTokens(fileSection.String())
		currentTokens := review.EstimateTokens(diffBuilder.String())
		if diffBudget > 0 && currentTokens+sectionTokens > diffBudget {
			truncated = true
			break
		}
		diffBuilder.WriteString(fileSection.String())
	}

	diffBuilder.WriteString("```\n")
	if truncated {
		diffBuilder.WriteString("\n(diff truncated to fit token budget — file list and stats above are complete)\n")
	}

	b.WriteString(diffBuilder.String())
	return b.String()
}

func parseDescription(response string, files []diff.File) *Description {
	desc := &Description{}

	jsonStr := extractJSONObject(response)
	if jsonStr != "" {
		if err := json.Unmarshal([]byte(jsonStr), desc); err == nil && desc.Title != "" {
			return desc
		}
	}

	// Fallback: generate from diff stats
	desc.Title = "Update " + files[0].Path
	desc.Summary = diff.Summary(files)
	desc.ChangeType = "chore"
	desc.Risk = "low"
	return desc
}

func extractJSONObject(s string) string {
	s = strings.TrimSpace(s)

	if strings.Contains(s, "```json") {
		parts := strings.SplitN(s, "```json", 2)
		if len(parts) == 2 {
			end := strings.Index(parts[1], "```")
			if end != -1 {
				s = strings.TrimSpace(parts[1][:end])
			} else {
				s = strings.TrimSpace(parts[1])
			}
		}
	} else if strings.Contains(s, "```") {
		parts := strings.SplitN(s, "```", 2)
		if len(parts) == 2 {
			rest := parts[1]
			if idx := strings.Index(rest, "\n"); idx != -1 {
				rest = rest[idx+1:]
			}
			end := strings.Index(rest, "```")
			if end != -1 {
				s = strings.TrimSpace(rest[:end])
			}
		}
	}

	start := strings.Index(s, "{")
	if start == -1 {
		return ""
	}
	end := strings.LastIndex(s, "}")
	if end == -1 || end <= start {
		return ""
	}
	return s[start : end+1]
}
