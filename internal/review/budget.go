package review

import (
	"unicode"

	"github.com/GrayCodeAI/sight/internal/diff"
)

// EstimateTokens provides a BPE-approximation token count for a string.
// It splits on whitespace and punctuation, then applies a multiplier:
// ~1.3 tokens per word for English prose, ~2.0 tokens per word for code.
// This is significantly more accurate than the naive len(s)/4 heuristic.
func EstimateTokens(s string) int {
	if len(s) == 0 {
		return 0
	}

	words, codeIndicators := tokenizeWords(s)
	if words == 0 {
		// Fallback for strings that are all punctuation/symbols.
		return (len(s) + 3) / 4
	}

	// Determine multiplier based on code density.
	// If >30% of "words" contain code indicators, treat as code.
	codeRatio := float64(codeIndicators) / float64(words)
	var multiplier float64
	if codeRatio > 0.3 {
		multiplier = 2.0 // code: more subword splits (camelCase, snake_case, operators)
	} else {
		multiplier = 1.3 // English prose
	}

	tokens := int(float64(words)*multiplier + 0.5)
	if tokens < 1 {
		tokens = 1
	}
	return tokens
}

// tokenizeWords splits s into word-like segments and counts how many
// look like code (contain underscores, mixed case, braces, operators, etc.).
func tokenizeWords(s string) (totalWords int, codeWords int) {
	inWord := false
	wordStart := 0
	runes := []rune(s)

	for i, r := range runes {
		isWordChar := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$'

		if isWordChar {
			if !inWord {
				wordStart = i
				inWord = true
			}
		} else {
			if inWord {
				totalWords++
				if looksLikeCodeWord(runes[wordStart:i]) {
					codeWords++
				}
				inWord = false
			}
			// Count standalone punctuation clusters as tokens too
			// (braces, operators, etc. each become tokens in BPE).
			if !unicode.IsSpace(r) {
				totalWords++
				codeWords++ // punctuation outside words is almost always code
			}
		}
	}
	if inWord {
		totalWords++
		if looksLikeCodeWord(runes[wordStart:]) {
			codeWords++
		}
	}

	return totalWords, codeWords
}

// looksLikeCodeWord returns true if a word looks like source code:
// camelCase, snake_case, ALL_CAPS with underscores, or contains digits
// mixed with letters.
func looksLikeCodeWord(word []rune) bool {
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasUnderscore := false

	for _, r := range word {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case r == '_':
			hasUnderscore = true
		}
	}

	// camelCase or PascalCase: mixed case in a single word
	if hasUpper && hasLower && len(word) > 1 {
		// Check if it's truly mixed (not just capitalized first letter)
		for _, r := range word[1:] {
			if unicode.IsUpper(r) {
				return true
			}
		}
	}
	// snake_case
	if hasUnderscore {
		return true
	}
	// alphanumeric identifiers like "x86" or "v2"
	if hasDigit && (hasUpper || hasLower) {
		return true
	}

	return false
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
