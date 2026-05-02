package review

import (
	"github.com/GrayCodeAI/sight/internal/diff"
)

// EstimateTokens provides a rough token count for a string.
// Uses the ~4 characters per token heuristic.
func EstimateTokens(s string) int {
	return (len(s) + 3) / 4
}

// ChunkFiles splits files into groups that fit within the token budget.
// Each group's combined prompt should not exceed maxPromptTokens.
func ChunkFiles(files []diff.File, concern Concern, contextLines int, maxPromptTokens int) [][]diff.File {
	if maxPromptTokens <= 0 {
		return [][]diff.File{files}
	}

	systemTokens := EstimateTokens(SystemPrompt(concern))
	overhead := systemTokens + 200 // buffer for prompt framing

	available := maxPromptTokens - overhead
	if available <= 0 {
		available = maxPromptTokens / 2
	}

	var chunks [][]diff.File
	var current []diff.File
	currentTokens := 0

	for _, f := range files {
		fileTokens := estimateFileTokens(f)
		if currentTokens+fileTokens > available && len(current) > 0 {
			chunks = append(chunks, current)
			current = nil
			currentTokens = 0
		}
		current = append(current, f)
		currentTokens += fileTokens
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}

	return chunks
}

func estimateFileTokens(f diff.File) int {
	tokens := EstimateTokens(f.Path) + 20 // file header
	for _, h := range f.Hunks {
		tokens += 10 // hunk header
		for _, l := range h.Lines {
			tokens += EstimateTokens(l.Content) + 1
		}
	}
	return tokens
}
