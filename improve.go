package sight

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/GrayCodeAI/sight/internal/diff"
	"github.com/GrayCodeAI/sight/internal/review"
)

// Improvement represents a suggested code improvement.
type Improvement struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	EndLine     int    `json:"end_line,omitempty"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Before      string `json:"before"`
	After       string `json:"after"`
	Reasoning   string `json:"reasoning"`
}

// ImproveResult is the output of an Improve operation.
type ImproveResult struct {
	Improvements []Improvement `json:"improvements"`
	TokensUsed   int           `json:"tokens_used"`
}

// Improve analyzes a diff and suggests code improvements — better naming,
// cleaner patterns, performance wins, idiomatic rewrites. Unlike Review(),
// Improve() focuses on making good code better, not finding bugs.
func Improve(ctx context.Context, rawDiff string, opts ...Option) (*ImproveResult, error) {
	cfg := buildConfig(opts)
	if cfg.provider == nil {
		return nil, ErrNoProvider
	}
	if rawDiff == "" {
		return nil, ErrEmptyDiff
	}

	files := diff.Parse(rawDiff)
	if len(files) == 0 {
		return &ImproveResult{}, nil
	}

	// For Improve, only send the first N files that fit within the token budget.
	tokenBudget := cfg.maxTokens * 3 // leave room for response
	files = truncateFilesForBudget(files, tokenBudget)

	prompt := buildImprovePrompt(files)

	resp, err := cfg.provider.Chat(ctx, []Message{
		{Role: "user", Content: prompt},
	}, ChatOpts{
		Model:       cfg.model,
		MaxTokens:   cfg.maxTokens,
		Temperature: 0.2,
		System:      improveSystemPrompt,
	})
	if err != nil {
		return nil, err
	}

	improvements := parseImprovements(resp.Content)
	return &ImproveResult{
		Improvements: improvements,
		TokensUsed:   resp.TokensUsed,
	}, nil
}

const improveSystemPrompt = `You are a senior engineer suggesting improvements to code that already works.
Your goal is NOT to find bugs — it's to make good code better.

Focus on:
- Better naming (more descriptive, consistent with codebase conventions)
- Simpler implementations (fewer lines, clearer logic)
- Performance improvements (avoid allocations, better algorithms)
- Idiomatic patterns (language-specific best practices)
- DRY violations (extract common patterns)
- Better error messages (more actionable, include context)

Respond ONLY with a JSON array:
[
  {
    "file": "path/to/file.go",
    "line": 42,
    "end_line": 45,
    "category": "naming|simplification|performance|idiom|dry|error-handling",
    "description": "What to improve and why",
    "before": "The current code (1-5 lines)",
    "after": "The improved code (1-5 lines)",
    "reasoning": "Why this is better"
  }
]

Rules:
- Only suggest improvements for ADDED lines (+ lines in diff)
- Each suggestion must include concrete before/after code
- Max 7 suggestions — prioritize highest-impact improvements
- Don't suggest changes that alter behavior — only style/performance/clarity
- If code is already clean, return an empty array: []`

func buildImprovePrompt(files []diff.File) string {
	var b strings.Builder
	b.WriteString("Suggest improvements for these code changes:\n\n```diff\n")

	for _, f := range files {
		if f.Deleted {
			continue
		}
		b.WriteString("--- " + f.Path + "\n+++ " + f.Path + "\n")
		for _, h := range f.Hunks {
			b.WriteString(h.Header + "\n")
			for _, l := range h.Lines {
				switch l.Type {
				case diff.LineAdded:
					b.WriteString("+" + l.Content + "\n")
				case diff.LineRemoved:
					b.WriteString("-" + l.Content + "\n")
				case diff.LineContext:
					b.WriteString(" " + l.Content + "\n")
				}
			}
		}
	}
	b.WriteString("```\n")
	return b.String()
}

func parseImprovements(response string) []Improvement {
	jsonStr := extractJSONArray(response)
	if jsonStr == "" {
		return nil
	}

	var improvements []Improvement
	if err := json.Unmarshal([]byte(jsonStr), &improvements); err != nil {
		return nil
	}

	// Filter out empty improvements
	var valid []Improvement
	for _, imp := range improvements {
		if imp.File != "" && imp.Description != "" && imp.After != "" {
			valid = append(valid, imp)
		}
	}
	return valid
}

// truncateFilesForBudget returns a subset of files whose combined estimated
// token count fits within the given budget. It keeps files in order, including
// only those that fit.
func truncateFilesForBudget(files []diff.File, tokenBudget int) []diff.File {
	if tokenBudget <= 0 {
		return files
	}

	overhead := review.EstimateTokens(improveSystemPrompt) + 200
	available := tokenBudget - overhead
	if available <= 0 {
		available = tokenBudget / 2
	}

	var result []diff.File
	currentTokens := 0
	for _, f := range files {
		if f.Deleted {
			continue
		}
		fileTokens := estimateFileTokensPublic(f)
		if currentTokens+fileTokens > available && len(result) > 0 {
			break
		}
		result = append(result, f)
		currentTokens += fileTokens
	}
	if len(result) == 0 && len(files) > 0 {
		// Always include at least the first file.
		result = append(result, files[0])
	}
	return result
}

// estimateFileTokensPublic approximates the token count for a single file's diff.
func estimateFileTokensPublic(f diff.File) int {
	tokens := review.EstimateTokens(f.Path) + 20
	for _, h := range f.Hunks {
		tokens += 10
		for _, l := range h.Lines {
			tokens += review.EstimateTokens(l.Content) + 1
		}
	}
	return tokens
}

func extractJSONArray(s string) string {
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

	start := strings.Index(s, "[")
	if start == -1 {
		return ""
	}
	end := strings.LastIndex(s, "]")
	if end == -1 || end <= start {
		return ""
	}
	return s[start : end+1]
}
