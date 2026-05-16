package review

import (
	"strings"
	"testing"

	"github.com/GrayCodeAI/sight/internal/diff"
)

func TestEstimateTokens_Empty(t *testing.T) {
	tokens := EstimateTokens("")
	if tokens != 0 {
		t.Errorf("expected 0 tokens for empty string, got %d", tokens)
	}
}

func TestEstimateTokens_Prose(t *testing.T) {
	text := "This is a simple sentence with ordinary English words."
	tokens := EstimateTokens(text)
	// Should use prose multiplier (~1.3 per word)
	// 9 words * 1.3 ~ 12
	if tokens < 5 || tokens > 30 {
		t.Errorf("expected reasonable token count for prose, got %d", tokens)
	}
}

func TestEstimateTokens_Code(t *testing.T) {
	text := `func handleRequest(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	result, err := db.GetUser(userID)
	if err != nil {
		return fmt.Errorf("failed: %w", err)
	}
}`
	tokens := EstimateTokens(text)
	// Code should have higher token-to-word ratio
	if tokens < 20 {
		t.Errorf("expected higher token count for code, got %d", tokens)
	}
}

func TestEstimateTokens_PunctuationOnly(t *testing.T) {
	text := "{{{}}}[]()()"
	tokens := EstimateTokens(text)
	if tokens < 1 {
		t.Errorf("expected at least 1 token, got %d", tokens)
	}
}

func TestEstimateTokens_SingleWord(t *testing.T) {
	tokens := EstimateTokens("hello")
	if tokens < 1 {
		t.Errorf("expected at least 1 token, got %d", tokens)
	}
}

func TestEstimateTokens_CamelCase(t *testing.T) {
	text := "handleUserRequest processPaymentData validateAuthToken"
	tokens := EstimateTokens(text)
	// CamelCase words should be treated as code
	if tokens < 3 {
		t.Errorf("expected at least 3 tokens for camelCase words, got %d", tokens)
	}
}

func TestEstimateTokens_SnakeCase(t *testing.T) {
	text := "handle_user_request process_payment_data validate_auth_token"
	tokens := EstimateTokens(text)
	// snake_case words should be treated as code
	if tokens < 3 {
		t.Errorf("expected at least 3 tokens for snake_case words, got %d", tokens)
	}
}

func TestEstimateTokens_MixedContent(t *testing.T) {
	text := "The function handleRequest should be refactored to use validate_input properly."
	tokens := EstimateTokens(text)
	if tokens < 5 {
		t.Errorf("expected reasonable token count for mixed content, got %d", tokens)
	}
}

func TestEstimateTokens_LongString(t *testing.T) {
	text := strings.Repeat("word ", 1000)
	tokens := EstimateTokens(text)
	if tokens < 500 {
		t.Errorf("expected >500 tokens for 1000-word string, got %d", tokens)
	}
}

func TestChunkFiles_EmptyFiles(t *testing.T) {
	chunks := ChunkFiles(nil, Concern{Name: "security"}, 10, 1000)
	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for nil files, got %d", len(chunks))
	}
}

func TestChunkFiles_SingleFile(t *testing.T) {
	files := []diff.File{
		{
			Path: "main.go",
			Hunks: []diff.Hunk{
				{
					Lines: []diff.Line{
						{Type: diff.LineAdded, Content: "func main() {}"},
					},
				},
			},
		},
	}
	chunks := ChunkFiles(files, Concern{Name: "security", Prompt: "Check"}, 10, 100000)
	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk, got %d", len(chunks))
	}
	if len(chunks[0]) != 1 {
		t.Errorf("expected 1 file in chunk, got %d", len(chunks[0]))
	}
}

func TestChunkFiles_MultipleFilesSmallBudget(t *testing.T) {
	// Create files with enough content to exceed a small budget
	var files []diff.File
	for i := 0; i < 5; i++ {
		lines := make([]diff.Line, 50)
		for j := range lines {
			lines[j] = diff.Line{
				Type:    diff.LineAdded,
				Content: strings.Repeat("some code content here ", 10),
			}
		}
		files = append(files, diff.File{
			Path: "file" + string(rune('a'+i)) + ".go",
			Hunks: []diff.Hunk{
				{Lines: lines},
			},
		})
	}

	chunks := ChunkFiles(files, Concern{Name: "security", Prompt: "Check for security issues"}, 10, 500)
	if len(chunks) < 2 {
		t.Errorf("expected multiple chunks for small budget, got %d", len(chunks))
	}

	// All files should be accounted for
	total := 0
	for _, chunk := range chunks {
		total += len(chunk)
	}
	if total != 5 {
		t.Errorf("expected 5 total files across all chunks, got %d", total)
	}
}

func TestChunkFiles_ZeroBudget(t *testing.T) {
	files := []diff.File{
		{Path: "a.go", Hunks: []diff.Hunk{{Lines: []diff.Line{{Type: diff.LineAdded, Content: "x"}}}}},
	}
	chunks := ChunkFiles(files, Concern{Name: "bugs"}, 10, 0)
	// Zero budget means no chunking (all in one group)
	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk for zero budget, got %d", len(chunks))
	}
}

func TestChunkFiles_NegativeBudget(t *testing.T) {
	files := []diff.File{
		{Path: "a.go", Hunks: []diff.Hunk{{Lines: []diff.Line{{Type: diff.LineAdded, Content: "x"}}}}},
	}
	chunks := ChunkFiles(files, Concern{Name: "bugs"}, 10, -100)
	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk for negative budget, got %d", len(chunks))
	}
}

func TestChunkFiles_LargeBudget(t *testing.T) {
	var files []diff.File
	for i := 0; i < 10; i++ {
		files = append(files, diff.File{
			Path: "file.go",
			Hunks: []diff.Hunk{
				{Lines: []diff.Line{{Type: diff.LineAdded, Content: "code"}}},
			},
		})
	}
	chunks := ChunkFiles(files, Concern{Name: "bugs", Prompt: "Check"}, 10, 1000000)
	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk for large budget, got %d", len(chunks))
	}
}

func TestTokenizeWords_EmptyString(t *testing.T) {
	total, code := tokenizeWords("")
	if total != 0 || code != 0 {
		t.Errorf("expected 0/0, got %d/%d", total, code)
	}
}

func TestTokenizeWords_ProseText(t *testing.T) {
	total, code := tokenizeWords("the quick brown fox")
	if total < 4 {
		t.Errorf("expected at least 4 words, got %d", total)
	}
	// Pure prose should have low code word count
	if code > total {
		t.Errorf("code words (%d) should not exceed total (%d) for prose", code, total)
	}
}

func TestTokenizeWords_CodeText(t *testing.T) {
	total, code := tokenizeWords("handleRequest(ctx, userID)")
	if total < 2 {
		t.Errorf("expected at least 2 words, got %d", total)
	}
	// Code should have high code word ratio
	if code < 1 {
		t.Errorf("expected at least 1 code word, got %d", code)
	}
}

func TestLooksLikeCodeWord(t *testing.T) {
	tests := []struct {
		word     string
		expected bool
	}{
		{"handleRequest", true}, // camelCase
		{"user_name", true},     // snake_case
		{"v2", true},            // alphanumeric
		{"x86", true},           // alphanumeric
		{"hello", false},        // plain word
		{"THE", false},          // all caps, no underscores
		{"MAX_VALUE", true},     // SCREAMING_SNAKE_CASE
		{"PascalCase", true},    // PascalCase with mixed case
	}

	for _, tc := range tests {
		result := looksLikeCodeWord([]rune(tc.word))
		if result != tc.expected {
			t.Errorf("looksLikeCodeWord(%q): expected %v, got %v", tc.word, tc.expected, result)
		}
	}
}

func TestEstimateFileTokens(t *testing.T) {
	f := diff.File{
		Path: "handler.go",
		Hunks: []diff.Hunk{
			{
				Lines: []diff.Line{
					{Type: diff.LineAdded, Content: "func main() {}"},
					{Type: diff.LineContext, Content: "// comment"},
				},
			},
		},
	}
	tokens := estimateFileTokens(f)
	if tokens < 10 {
		t.Errorf("expected at least 10 tokens, got %d", tokens)
	}
}
