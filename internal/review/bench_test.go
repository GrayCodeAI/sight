package review

import (
	"testing"

	"github.com/GrayCodeAI/sight/internal/diff"
)

func BenchmarkParseResponse_Small(b *testing.B) {
	response := `[
		{"file": "main.go", "line": 10, "severity": "high", "message": "Bug", "fix": "fix it", "reasoning": "because"},
		{"file": "main.go", "line": 20, "severity": "low", "message": "Style", "fix": "rename", "reasoning": "convention"}
	]`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseResponse(response, "bugs")
	}
}

func BenchmarkParseResponse_Large(b *testing.B) {
	response := `[`
	for i := 0; i < 50; i++ {
		if i > 0 {
			response += ","
		}
		response += `{"file": "file.go", "line": ` + itoa(i*10) + `, "severity": "medium", "message": "Issue number ` + itoa(i) + `", "fix": "do something", "reasoning": "some reason"}`
	}
	response += `]`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseResponse(response, "performance")
	}
}

func BenchmarkBuildPrompt(b *testing.B) {
	files := []diff.File{
		{
			Path: "handler.go",
			Hunks: []diff.Hunk{
				{OldStart: 10, OldCount: 20, NewStart: 10, NewCount: 25, Header: "func handleRequest"},
			},
		},
	}
	for i := 0; i < 30; i++ {
		files[0].Hunks[0].Lines = append(files[0].Hunks[0].Lines, diff.Line{
			Type: diff.LineAdded, Content: "\tnewCode := doSomething()",
		})
	}

	concern := AllConcerns()[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildPrompt(concern, files, 10)
	}
}

func BenchmarkEstimateTokens(b *testing.B) {
	text := "This is a reasonably long string that we want to estimate tokens for, simulating typical code content with various characters and lengths."
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EstimateTokens(text)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
